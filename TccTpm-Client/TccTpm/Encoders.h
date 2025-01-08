#pragma once
#include <string>
#include <Tpm2.h>
#include "Enum.h"

std::string base64Encode(const TpmCpp::ByteVec data, bool removeLines);
TpmCpp::ByteVec base64Decode(const std::string& encodedData);