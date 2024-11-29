#pragma once
#include <string.h>




std::string JsonSendProofOfPossetion(std::string& ekPubContent, std::string& akPubContent, std::string& certify, std::string& certifySignature);
std::string JsonSendRecoveredSecret(std::string& recoveredSecret);
std::string JsonSendQuote(std::string& quoteForServer, std::string& pcrsForServer, std::string& quoteSignature);
namespace TccTpm {
	void JsonResponseProofOfPossetion(std::string& responseFromServer);
	std::string JsonResponseRecoveredSecret(std::string& responseSecretFromServer);
}