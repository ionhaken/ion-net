#pragma once
#include <ion/net/NetSdk.h>
#include <ion/net/NetSecureTypes.h>

#include <ion/container/Array.h>

#include <cstring>
#include <ion/tracing/Log.h>
#include <libsodium/include/sodium/crypto_box.h>
#include <libsodium/include/sodium/crypto_kx.h>
#include <libsodium/include/sodium/crypto_pwhash_argon2id.h>
#include <libsodium/include/sodium/crypto_secretbox.h>
#include <libsodium/include/sodium/randombytes.h>
#include <libsodium/include/sodium/utils.h>

// Lib Sodium interface
namespace ion::NetSecure
{

static_assert(AuthenticationTagLength == crypto_box_MACBYTES);
static_assert(NonceLength == crypto_box_NONCEBYTES);
static_assert(PublicKeyLength == crypto_box_PUBLICKEYBYTES);
static_assert(SecretKeyLength == crypto_secretbox_KEYBYTES);

inline void Random(unsigned char* buffer, size_t len)
{
	// Use libsodium random instead of Random() for more unpredictable data.
	ION_ASSERT(ion::NetIsInitialized(), "NetSdk not initialized");
	randombytes_buf(buffer, len);
}

inline void HashPassword(unsigned char* out, size_t bufferSize, const ion::Array<uint64_t, 2>& nonce, const char* password,
						 size_t passwordLength)
{
	ION_ASSERT(ion::NetIsInitialized(), "ion::secure not initialized");
	static_assert(crypto_pwhash_argon2id_SALTBYTES == sizeof(uint64_t) * 2, "Invalid nonce");
	int ret = crypto_pwhash_argon2id(out, bufferSize, password, (unsigned long long)passwordLength, (const uint8_t*)nonce.Data(), 3u,
									 crypto_pwhash_argon2id_MEMLIMIT_MIN, int(crypto_pwhash_argon2id_ALG_ARGON2ID13));
	ION_ASSERT(ret == 0, "crypto_pwhash_argon2id failed");
}

template <typename T>
inline void MemZero(T& data)
{
	sodium_memzero(&data, sizeof(data));
}

inline bool SetupCryptoKeys(CryptoKeys& keys)
{
	int res = crypto_box_keypair(keys.mPublicKey.data, keys.mSecretKey.data);
	ION_ASSERT(res == 0, "Invalid keypair");
	return res == 0;
}
inline int ComputeSharedCryptoKeys(SharedKey& sharedKey, const CryptoKeys& keys, const NetSecure::PublicKey& remotePublicKey)
{
	return crypto_box_beforenm(sharedKey.data, remotePublicKey.data, keys.mSecretKey.data);
}

inline bool Encrypt(unsigned char* dst, const unsigned char* src, unsigned long long srcLen, const unsigned char* nonce,
					const SharedKey& sharedkey)
{
	ION_ASSERT(srcLen <= crypto_box_MESSAGEBYTES_MAX, "Invalid data length");
	return crypto_secretbox_detached(dst + AuthenticationTagLength, dst, src, srcLen, nonce, sharedkey.data) == 0;
}

inline bool Decrypt(unsigned char* dst, const unsigned char* src, unsigned long long srcLen, const unsigned char* nonce,
					const SharedKey& sharedkey)
{
	return crypto_secretbox_open_detached(dst, src + AuthenticationTagLength, src, srcLen - AuthenticationTagLength, nonce,
										  sharedkey.data) == 0;
}

inline bool Encrypt(unsigned char* dst, const unsigned char* src, unsigned long long srcLen, const unsigned char* nonce,
					const SecretKey& secretKey)
{
	ION_ASSERT(srcLen <= crypto_box_MESSAGEBYTES_MAX, "Invalid data length");
	return crypto_secretbox(dst, src, srcLen, nonce, secretKey.data) == 0;
}

inline bool Decrypt(unsigned char* dst, const unsigned char* src, unsigned long long srcLen, const unsigned char* nonce,
					const SecretKey& secretKey)
{
	ION_ASSERT(srcLen <= crypto_box_MESSAGEBYTES_MAX, "Invalid data length");
	return crypto_secretbox_easy(dst, src, srcLen, nonce, secretKey.data) == 0;
}

}  // namespace ion::NetSecure

#if ION_NET_FEATURE_SECURITY && ION_NET_FEATURE_SECURITY_AUDIT
	#define ION_NET_SECURITY_AUDIT_PRINTF(__format, ...) ION_LOG_INFO_FMT(__format, __VA_ARGS__)
#else
	#define ION_NET_SECURITY_AUDIT_PRINTF(__format, ...)
#endif
