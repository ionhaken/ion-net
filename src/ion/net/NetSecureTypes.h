#pragma once

#include <ion/Types.h>

namespace ion
{
namespace NetSecure
{
const constexpr size_t AuthenticationTagLength = 16;
const constexpr size_t PublicKeyLength = 32;
const constexpr size_t SecretKeyLength = 32;
const constexpr size_t SharedKeyLength = 32;
const constexpr size_t NonceLength = 24;

struct PublicKey
{
	unsigned char data[PublicKeyLength] = {};
};

struct SecretKey
{
	unsigned char data[SecretKeyLength] = {};
};

struct CryptoKeys
{
	PublicKey mPublicKey;
	SecretKey mSecretKey;
};

// Based on public key, a shared secret key can be calculated.
// Applications that send several messages to the same recipient or receive several messages from the same sender can improve performance by
// calculating the shared key only once and reusing it in  subsequent operations.
struct SharedKey
{
	unsigned char data[SharedKeyLength] = {};
};
}  // namespace NetSecure
}  // namespace ion
