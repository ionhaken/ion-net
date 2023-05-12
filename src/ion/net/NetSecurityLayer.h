#pragma once

#include <ion/net/NetSecurity.h>

#include <ion/string/String.h>

namespace ion::NetSecurityLayer
{

bool IPAddressMatch(const ion::String& string, const char* IP)
{
	if (IP == nullptr)
	{
		return false;
	}

	unsigned characterIndex = 0;

	while (characterIndex < string.Length())
	{
		if (string.Data()[characterIndex] == IP[characterIndex])
		{
			characterIndex++;  // Equal characters
		}
		else
		{
			if (IP[characterIndex] == 0)
			{
				return false;  // End of one of the strings
			}

			// Characters do not match
			if (string.Data()[characterIndex] == '*')
			{
				return true;  // Domain is banned.
			}
			return false;  // Characters do not match and it is not a *
		}
	}

	if (IP[characterIndex] == 0)
	{
		return true;  // End of the string and the strings match
	}

	// No match found.
	return false;
}

bool IsInSecurityExceptionList(const NetSecurity& security, const char* ip)
{
	bool isEmpty = false;
	security.mySecurityExceptions.AssumeThreadSafeAccess([&](auto& securityExceptionList) { isEmpty = securityExceptionList.Size() == 0; });
	if (isEmpty)
	{
		return false;
	}

	bool isFound = false;
	security.mySecurityExceptions.Access(
	  [&](auto& securityExceptionList)
	  {
		  for (unsigned int i = 0; i < securityExceptionList.Size(); i++)
		  {
			  if (IPAddressMatch(securityExceptionList[i], ip))
			  {
				  isFound = true;
				  return;
			  }
		  }
	  });
	return isFound;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void AddToSecurityExceptionList(NetSecurity& security, const char* ip)
{
	security.mySecurityExceptions.Access([&](auto& securityExceptionList) { securityExceptionList.Add(ion::String(ip)); });
}


void RemoveFromSecurityExceptionList(NetSecurity& security, const char* ip)
{
	bool isEmpty = false;
	security.mySecurityExceptions.AssumeThreadSafeAccess([&](auto& securityExceptionList) { isEmpty = securityExceptionList.Size() == 0; });
	if (isEmpty)
	{
		return;
	}

	security.mySecurityExceptions.Access(
	  [&](auto& securityExceptionList)
	  {
		  if (ip == 0)
		  {
			  securityExceptionList.Clear();
		  }
		  else
		  {
			  unsigned i = 0;
			  while (i < securityExceptionList.Size())
			  {
				  if (IPAddressMatch(securityExceptionList[i], ip))
				  {
					  securityExceptionList[i] = securityExceptionList[securityExceptionList.Size() - 1];
					  securityExceptionList.Erase(securityExceptionList.Size() - 1);
				  }
				  else
				  {
					  i++;
				  }
			  }
		  }
	  });
}

}  // namespace ion::NetSecurityLayer
