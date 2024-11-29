
#include <iostream>
#include "Encoders.h"
#include <botan/botan.h>
#include <botan/base64.h>
#include <botan/rsa.h>
#include "Defines.h"
#include "utils.h"
#include "Enum.h"

std::string formatEkPublicPem(TpmCpp::TPMT_PUBLIC outPublic)
{
	std::string pemFormatKey;
	size_t  bytesToskip = 2;
	TpmCpp::ByteVec unique = outPublic.unique->toBytes();
	TpmCpp::ByteVec keyModule;
	for (int i = bytesToskip; i < unique.size(); i++)
	{
		keyModule.push_back(unique[i]);
	}
	auto rsaPublicKey = Botan::RSA_PublicKey(Botan::BigInt(keyModule.data(), keyModule.size()), DEFAULT_KEY_EXPONENT);
	pemFormatKey = Botan::X509::PEM_encode(rsaPublicKey);

	return trimPublicKey(pemFormatKey);
}

std::string base64Encode(const TpmCpp::ByteVec data, bool removeLines)
{
	return Botan::base64_encode(data.data(), data.size());
}


std::string getEkPublicPem(TpmCpp::TPMT_PUBLIC outPublic, KeyType keyType) {

	std::string pemFormatKey;
	size_t bytestoSkip = 2;
	TpmCpp::ByteVec unique = outPublic.unique->toBytes();
	if (keyType == KeyType::rsa)
	{
		TpmCpp::ByteVec keyModule;
		for (int i = bytestoSkip; i < unique.size(); i++)
		{
			keyModule.push_back(unique[i]);
		}
		auto rsaPublicKey = Botan::RSA_PublicKey(Botan::BigInt(keyModule.data(), keyModule.size()), DEFAULT_KEY_EXPONENT);
		pemFormatKey = Botan::X509::PEM_encode(rsaPublicKey);
	}
	return trimPublicKey(pemFormatKey);
}

TpmCpp::ByteVec base64Decode(const std::string& encodedData)
{
	return Botan::unlock(Botan::base64_decode(encodedData));
}