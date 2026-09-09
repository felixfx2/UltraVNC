// This file is part of UltraVNC
// https://github.com/ultravnc/UltraVNC
// https://uvnc.com/
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// SPDX-FileCopyrightText: Copyright (C) 2002-2026 UltraVNC Team Members. All Rights Reserved.
//

// Apple Remote Desktop (ARD) authentication - RFB security type 30.
//
// macOS Screen Sharing issues a Diffie-Hellman handshake (server sends
// big-endian U16 generator, U16 key length, prime[keyLen], peer public[keyLen]).
// The client computes clientPub = gen^priv mod prime and
// shared = peerPub^priv mod prime (rfb/arddh.cpp), then replies with
// AES-128-ECB(MD5(shared)) over { username[64] password[64] } followed by the
// client public key. The unused credential bytes are random to keep the
// ciphertext unpredictable (wire format matches LibVNC libvncclient
// HandleARDAuth / Apple RemoteDesktop).

#include "ClientConnection.h"
#include "Exception.h"
#include "AuthDialog.h"
#include <vector>

extern "C" {
#include "..\rfb\arddh.h"
}

namespace {

const int kARDBufferSize = 128;
const int kMaxARDKeyLen = 512;

// MD5 via Crypto API (PROV_RSA_AES provides CALG_MD5).
bool ard_md5(const BYTE* data, DWORD len, BYTE digest[16])
{
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	DWORD dwSize = 16;
	bool ok = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) != FALSE;
	if (ok)
		ok = CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash) != FALSE;
	if (ok)
		ok = CryptHashData(hHash, data, len, 0) != FALSE;
	if (ok)
		ok = CryptGetHashParam(hHash, HP_HASHVAL, digest, &dwSize, 0) != FALSE;
	if (hHash)
		CryptDestroyHash(hHash);
	if (hProv)
		CryptReleaseContext(hProv, 0);
	return ok;
}

// Fill a buffer with Crypto API random bytes.
bool ard_random(BYTE* buf, DWORD len)
{
	HCRYPTPROV hProv = 0;
	bool ok = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) != FALSE;
	if (ok)
		ok = CryptGenRandom(hProv, len, buf) != FALSE;
	if (hProv)
		CryptReleaseContext(hProv, 0);
	return ok;
}

// AES-128-ECB, no padding. Buffer is treated as whole 16-byte blocks, so
// CryptEncrypt runs with bFinal = FALSE (Crypto API would otherwise append
// a padding block at the end of an aligned message).
struct ARDAESCipher
{
	static const DWORD BlockSize = 16;

	struct SymKeyBlob
	{
		BLOBHEADER  hdr;
		DWORD       cbKeySize;
		BYTE        key[16];
	};

	HCRYPTPROV	hProv;
	HCRYPTKEY	hKey;

	ARDAESCipher() : hProv(0), hKey(0) { }

	~ARDAESCipher()
	{
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
			CryptReleaseContext(hProv, 0);
	}

	bool Init(const BYTE key[16])
	{
		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
			return false;
		SymKeyBlob keyBlob = { 0 };
		keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
		keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
		keyBlob.hdr.aiKeyAlg = CALG_AES_128;
		keyBlob.cbKeySize = sizeof(keyBlob.key);
		memcpy(keyBlob.key, key, keyBlob.cbKeySize);
		if (!CryptImportKey(hProv, (BYTE*)&keyBlob, offsetof(SymKeyBlob, key) + keyBlob.cbKeySize, NULL, 0, &hKey))
			return false;
		DWORD mode = CRYPT_MODE_ECB;
		if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0))
			return false;
		return true;
	}

	bool Encrypt(BYTE* buf, DWORD size)
	{
		return CryptEncrypt(hKey, NULL, FALSE, 0, buf, &size, size) != FALSE;
	}
};

} // namespace

void ClientConnection::AuthAppleARD()
{
	BYTE gen[2] = { 0 };
	BYTE keyLenBytes[2] = { 0 };
	ReadExact((char*)gen, 2);
	ReadExact((char*)keyLenBytes, 2);
	const int keyLen = 256 * keyLenBytes[0] + keyLenBytes[1];
	if (keyLen < 1 || keyLen > kMaxARDKeyLen)
		throw WarningException(L"Invalid Apple ARD key length");

	std::vector<BYTE> prime(keyLen);
	std::vector<BYTE> peerPub(keyLen);
	std::vector<BYTE> clientPub(keyLen);
	std::vector<BYTE> shared(keyLen);
	ReadExact((char*)prime.data(), keyLen);
	ReadExact((char*)peerPub.data(), keyLen);

	if (!ard_dh_compute(prime.data(), keyLen, gen, 2, peerPub.data(), keyLen,
		clientPub.data(), shared.data()))
		throw WarningException(L"Apple ARD Diffie-Hellman failed");

	BYTE aesKey[16];
	if (!ard_md5(shared.data(), keyLen, aesKey))
		throw WarningException(L"Apple ARD MD5 failed");

	char user[256] = { 0 };
	char passwd[256] = { 0 };
	if ((m_cmdlnUser[0] != '\0') && (m_clearPasswd[0] != '\0'))
	{
		strncpy_s(user, _countof(user), m_cmdlnUser, _TRUNCATE);
		strncpy_s(passwd, _countof(passwd), m_clearPasswd, _TRUNCATE);
	}
	else
	{
		AuthDialog ad;
		ad.SetStatusWindow(m_hwndStatus, m_opts->m_ClassName);
		if (!ad.DoDialog(dtUserPassNotEncryption, m_host, m_port))
			throw WarningException(L"Apple ARD authentication cancelled");
		strncpy_s(user, _countof(user), ad.m_user, _TRUNCATE);
		strncpy_s(passwd, _countof(passwd), ad.m_passwd, _TRUNCATE);
		if (passwd[0] == '\0')
			throw WarningException(L"Password had zero length");
	}

	// { username[64] password[64] }, each null-terminated, remainder random.
	BYTE userpass[kARDBufferSize];
	if (!ard_random(userpass, sizeof(userpass)))
		throw WarningException(L"Apple ARD random failed");
	{
		const size_t userLen = strlen(user);
		memcpy(userpass, user, userLen < 64 ? userLen + 1 : 64);
		const size_t passwdLen = strlen(passwd);
		memcpy(userpass + 64, passwd, passwdLen < 64 ? passwdLen + 1 : 64);
	}

	ARDAESCipher aes;
	if (!aes.Init(aesKey))
		throw WarningException(L"Apple ARD AES init failed");
	if (!aes.Encrypt(userpass, sizeof(userpass)))
		throw WarningException(L"Apple ARD AES encrypt failed");

	WriteExact((char*)userpass, sizeof(userpass));
	WriteExact((char*)clientPub.data(), keyLen);

	// Lose the plain-text credentials from memory.
	memset(user, 0, sizeof(user));
	memset(passwd, 0, sizeof(passwd));
	memset(userpass, 0, sizeof(userpass));
}