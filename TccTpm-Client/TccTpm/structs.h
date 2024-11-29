#pragma once

#include<Tpm2.h>
#include <iostream>
#include "Enum.h"

struct TpmData {

    TpmCpp::TPMT_PUBLIC ek;
    TpmCpp::TPM_HANDLE ekhandle;
    TpmCpp::TPMT_PUBLIC ak;
    TpmCpp::TPM_HANDLE akhandle;
    TpmCpp::CreateResponse akResponse;
    TpmCpp::CertifyResponse certify;
    std::string ekpubContent, akpubContent, certifyInfo, credentialFromServer, secretFromServer, quoteForServer, encodedPCRS , encodedSignatureQuote;
    TpmCpp::ByteVec certifySignatureBytes, rawDataSignature;
    TpmCpp::Tpm2 tpm;
    TpmCpp::TpmTbsDevice tbsDevice;
    TpmCpp::TpmTcpDevice tcpDevice;
    bool useSimulator = false;
    KeyType keyType = KeyType::rsa;
    std::vector<UINT32> pcrsToMakeQuote;
    TpmCpp::QuoteResponse quote;
    TpmCpp::PCR_ReadResponse readingDigestFromPcrs;
    /*std::shared_ptr <TpmCpp::TPMU_SIGNATURE> signatureQuote;*/
};