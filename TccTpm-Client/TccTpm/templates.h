#pragma once


#include <Tpm2.h>

class Templates {
public:
	static TpmCpp::TPMT_PUBLIC ekRsaTemplate();
	static TpmCpp::TPMT_PUBLIC akRsaTemplate();
};