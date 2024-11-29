#include<iostream>
#include<json/json.h>
#include "jsonHandler.h"
#include "communication.h"
#include "structs.h"

extern TpmData tpmdata;
std::string JsonSendProofOfPossetion(std::string& ekPubContent, std::string& akPubContent, std::string& certify, std::string& certifySignature) {
	Json::FastWriter jsonWriter;
	Json::Value jsonRoot;
	Json::Value ProofOfPossetion;

	ProofOfPossetion["ekPublic"] = ekPubContent;
	ProofOfPossetion["akPublic"] = akPubContent;
	ProofOfPossetion["certify"] = certify;
	ProofOfPossetion["certifySignature"] = certifySignature;
	jsonRoot["ProofOfPossetion"] = ProofOfPossetion;

	return jsonWriter.write(jsonRoot);
}


//criando formato json com o secret recuperado.
std::string JsonSendRecoveredSecret(std::string& recoveredSecret) {
	Json::FastWriter jsonWriter;
	Json::Value jsonSecret;
	jsonSecret["Client Secret"] = recoveredSecret;
	return jsonWriter.write(jsonSecret);
}
//criando json do quote para ao enviar ao servidor
std::string JsonSendQuote(std::string& quotedForServer, std::string& pcrsForServer, std::string& quoteSignature) {
	Json::FastWriter jsonWriter;
	Json::Value jsonQuote;
	jsonQuote["Quote"] = quotedForServer;
	jsonQuote["PCRS"] = pcrsForServer;
	jsonQuote["QuoteSignature"] = quoteSignature;
	return jsonWriter.write(jsonQuote);

}
namespace TccTpm {
	//Recebendo resultado da ProofOfPossetion
	void JsonResponseProofOfPossetion(std::string& responseFromServer) {
		Json::Reader jsonReader;
		Json::Value responseInitialChallengeJson;
		jsonReader.parse(responseFromServer, responseInitialChallengeJson);
		tpmdata.credentialFromServer = responseInitialChallengeJson["credential"].asString();
		tpmdata.secretFromServer = responseInitialChallengeJson["encryptedSecret"].asString();
	}
	//recebendo resultado do secret enviado pelo servidor e se preparando para o challenge
	std::string JsonResponseRecoveredSecret(std::string& responseSecretFromServer) {
		Json::Reader jsonReader;
		Json::Value responseJsonSecret;
		jsonReader.parse(responseSecretFromServer, responseJsonSecret);
		std::string newNonce = responseJsonSecret["nonce"].asString();
		for (const auto& pcrValue : responseJsonSecret["PCRS"]) {
			tpmdata.pcrsToMakeQuote.push_back(pcrValue.asUInt());
		}
		return newNonce;
	}
	
}