#pragma once

#include <Tpm2.h>
#include <iostream>
#include "structs.h"

namespace TccTpm {
	void processProvisioning(TpmCpp::TPMT_PUBLIC& ek, TpmCpp::TPM_HANDLE& ekHandle, TpmCpp::TPMT_PUBLIC& ak,
		TpmCpp::TPM_HANDLE& akHandle, TpmCpp::CreateResponse& akResponse, std::string& ekPubContent, std::string& akPubContent);
	void processCertify(TpmCpp::TPM_HANDLE& akHandle, TpmCpp::CertifyResponse& certifyData, std::string& certifyInfo, TpmCpp::ByteVec& certifySignatureBytes);
	void processQuote(std::vector<UINT32>& pcrsToMakeQuote, TpmCpp::ByteVec& Nonce, std::string& quoteForServer, std::string& PCRS, std::string& encodedSignatureQuote);
	TpmCpp::ByteVec processActivateCredential(std::string& credentialFromServer, std::string& secretFromServer);
}