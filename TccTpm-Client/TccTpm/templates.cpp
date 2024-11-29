
#include <string>
#include <memory>
#include <stdexcept>
#include "templates.h"

static const TpmCpp::TPMT_SYM_DEF_OBJECT Aes128Cfb {TpmCpp::TPM_ALG_ID::AES, 128, TpmCpp::TPM_ALG_ID::CFB};

TpmCpp::TPMT_PUBLIC Templates::ekRsaTemplate() {
	return TpmCpp::TPMT_PUBLIC(
		TpmCpp::TPM_ALG_ID::SHA256,
		TpmCpp::TPMA_OBJECT::decrypt
		| TpmCpp::TPMA_OBJECT::restricted
		| TpmCpp::TPMA_OBJECT::fixedParent
		| TpmCpp::TPMA_OBJECT::fixedTPM
		| TpmCpp::TPMA_OBJECT::sensitiveDataOrigin
		| TpmCpp::TPMA_OBJECT::userWithAuth,
		{},// no policy
		TpmCpp::TPMS_RSA_PARMS(Aes128Cfb, TpmCpp::TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
		TpmCpp::TPM2B_PUBLIC_KEY_RSA());
}

TpmCpp::TPMT_PUBLIC Templates::akRsaTemplate()
{
	return TpmCpp::TPMT_PUBLIC(
		TpmCpp::TPM_ALG_ID::SHA256,
		TpmCpp::TPMA_OBJECT::fixedTPM
		| TpmCpp::TPMA_OBJECT::fixedParent
		| TpmCpp::TPMA_OBJECT::sensitiveDataOrigin
		| TpmCpp::TPMA_OBJECT::userWithAuth
		| TpmCpp::TPMA_OBJECT::restricted
		| TpmCpp::TPMA_OBJECT::sign,
		{},
		TpmCpp::TPMS_RSA_PARMS({}, TpmCpp::TPMS_SCHEME_RSASSA(TpmCpp::TPM_ALG_ID::SHA256),2048, 0),
		TpmCpp::TPM2B_PUBLIC_KEY_RSA()
	);
}