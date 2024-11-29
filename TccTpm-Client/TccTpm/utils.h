#pragma once



#include <Tpm2.h>
#include <string>

extern TpmCpp::Tpm2 tpm;
extern TpmCpp::TpmTbsDevice tbsDevice;
extern TpmCpp::TpmTcpDevice tcpDevice;
extern bool useSimulator;
std::string trimPublicKey(std::string pemFormatKey);
int InitTpm();
void ShutDownTpm();
TpmCpp::ByteVec toByteVec(const std::shared_ptr<TpmCpp::TPMU_SIGNATURE>& ptr, size_t skipBytes);