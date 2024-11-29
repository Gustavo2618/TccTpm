#pragma once

#include <Tpm2.h>
#include "Enum.h"
#include "structs.h"

void createEKey(TpmCpp::TPMT_PUBLIC& ek, TpmCpp::TPM_HANDLE& ekhandle);
TpmCpp::CreatePrimaryResponse makeEndorsementKey(KeyType keyType);
TpmCpp::TPM_HANDLE makeAttestationKey(TpmCpp::TPM_HANDLE& ekHandle, KeyType& keyType, TpmCpp::TPMT_PUBLIC& ak, TpmCpp::TPM_HANDLE &akhandle, TpmCpp::CreateResponse &akResponse);


