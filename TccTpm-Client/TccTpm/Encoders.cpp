
#include <iostream>
#include "Encoders.h"
#include <botan/botan.h>
#include <botan/base64.h>
#include <botan/rsa.h>
#include "Defines.h"
#include "utils.h"
#include "Enum.h"

std::string base64Encode(const TpmCpp::ByteVec data, bool removeLines)
{
	return Botan::base64_encode(data.data(), data.size());
}

TpmCpp::ByteVec base64Decode(const std::string& encodedData)
{
	return Botan::unlock(Botan::base64_decode(encodedData));
}