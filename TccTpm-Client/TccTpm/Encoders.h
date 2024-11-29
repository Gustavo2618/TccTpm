#pragma once
#include <string>
#include <Tpm2.h>
#include "Enum.h"

std::string formatEkPublicPem(TpmCpp::TPMT_PUBLIC outPublic);
std::string base64Encode(const TpmCpp::ByteVec data, bool removeLines);
std::string getEkPublicPem(TpmCpp::TPMT_PUBLIC outPublic, KeyType keyType);
TpmCpp::ByteVec base64Decode(const std::string& encodedData);