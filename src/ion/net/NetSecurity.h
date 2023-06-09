#pragma once

#include <ion/net/NetSdk.h>

#include <ion/concurrency/Synchronized.h>

#include <ion/string/String.h>

namespace ion
{

template <typename T>
using NetVector = Vector<T, NetAllocator<T>>;

struct NetSecurity
{
#if ION_NET_FEATURE_SECURITY
	ion::NetSecure::SecretKey mSecretKey;
#endif
	Synchronized<NetVector<ion::String>> mySecurityExceptions;
	std::atomic<bool> myHasAnySecurityExceptions =
	  false;  // For avoiding mySecurityExceptions mutex since typically there are no exceptions
};
}  // namespace ion
