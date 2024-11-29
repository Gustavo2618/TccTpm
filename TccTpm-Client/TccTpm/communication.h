#pragma once
#include<iostream>
#include "Encoders.h"
#include "jsonHandler.h"

std::string communicationProofOfPossetion();
TpmCpp::ByteVec communicationSendRecoveredSecretForAttestation(std::string& credentialFromServer, std::string& secretFromServer);
void communicationSendQuoteForAttestation();