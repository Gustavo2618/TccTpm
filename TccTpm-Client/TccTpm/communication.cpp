#include "communication.h"
#include "structs.h"
#include "request.h"
#include "json/json.h"
#include "tpm.h"

extern TpmData tpmdata;
std::string communicationProofOfPossetion() {
	std::string certifySignature = base64Encode(tpmdata.rawDataSignature, true);
	std::string proofOfPossetion = JsonSendProofOfPossetion(tpmdata.ekpubContent, tpmdata.akpubContent, tpmdata.certifyInfo, certifySignature);
	std::cout << "\n" + proofOfPossetion << std::endl;
	std::string initialChallengeResponse = makeRequest(ProcessPhase::PROVISIONING, proofOfPossetion, false);
	return initialChallengeResponse;
}

TpmCpp::ByteVec communicationSendRecoveredSecretForAttestation(std::string& credentialFromServer, std::string& secretFromServer) {
	TpmCpp::ByteVec recoveredSecret = TccTpm::processActivateCredential(credentialFromServer, secretFromServer);
	std::cout << std::endl << std::endl;
	std::string secretToSend = base64Encode(recoveredSecret,true);
	std::cout << ">>>Secret encoded to send for server: " + secretToSend << std::endl;
	std::string jsonSecret = JsonSendRecoveredSecret(secretToSend);
	std::cout << "\n" + jsonSecret << std::endl;
	std::string responseSecretFromServer = makeRequest(ProcessPhase::SECRET_CHECK_FOR_ATTESTATION, jsonSecret, false);

	//recebendo o Json com o novo nonce para atestação
	std::string newNonceJsonFromServerForAttestation = TccTpm::JsonResponseRecoveredSecret(responseSecretFromServer);
	TpmCpp::ByteVec newNonceFromServerForAttestationBytes = base64Decode(newNonceJsonFromServerForAttestation);
	TpmCpp::ByteVec newNonce;
	
	for (int k = 0; k < newNonceFromServerForAttestationBytes.size(); k++) {
		newNonce.push_back(newNonceFromServerForAttestationBytes[k]);
	}
	return newNonce;
}
void communicationSendQuoteForAttestation() {
	std::string jsonQuoteToSend = JsonSendQuote(tpmdata.quoteForServer, tpmdata.encodedPCRS, tpmdata.encodedSignatureQuote);
	std::cout << "\nQuote e pcrs encodados que vão para o servidor: " + jsonQuoteToSend << std::endl;
	std::string responseQuoteFromServer = makeRequest(ProcessPhase::RESULT_ATTESTATION, jsonQuoteToSend, false);
	std::cout << responseQuoteFromServer << std::endl;
}