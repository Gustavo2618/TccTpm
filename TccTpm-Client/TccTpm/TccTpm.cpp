

#include <iostream>
#include <Tpm2.h>
#include <cstdint>
#include<json/json.h>

#include "utils.h"
#include "templates.h"
#include "Enum.h"
#include "keys.h"
#include "Encoders.h"
#include "jsonHandler.h"
#include "request.h"
#include "tpm.h"
#include "structs.h"
#include "communication.h"

TpmData tpmdata;

int main()
{
	InitTpm();
	std::cout << "Tpm inicializado!\n";
	
	//Processo de provisionamento de chaves
	TccTpm::processProvisioning(tpmdata.ek, tpmdata.ekhandle, tpmdata.ak, tpmdata.akhandle, tpmdata.akResponse, tpmdata.ekpubContent, tpmdata.akpubContent);


	//Processo de Certifica��o de uma chave criada pelo tpm
	TccTpm::processCertify(tpmdata.akhandle, tpmdata.certify, tpmdata.certifyInfo, tpmdata.certifySignatureBytes);

	//Realizando primeira comunica��o com servidor para a certifica��o da chave de atesta��o
	std::string responseProofOfPossetion = communicationProofOfPossetion();
	if (responseProofOfPossetion.empty())
	{
		return std::cout << ">>>Sem resposta do servidor..." << std::endl, -1;
	}
	//Verificando Secret enviado pelo servidor e rebendo secret para atesta��o usando o quote
	TccTpm::JsonResponseProofOfPossetion(responseProofOfPossetion);
	TpmCpp::ByteVec freshNonce = communicationSendRecoveredSecretForAttestation(tpmdata.credentialFromServer, tpmdata.secretFromServer);
	std::cout << "\n>>>FreshNonce: ";
	for (int i = 0; i < freshNonce.size(); i++)
	{
		printf("%02x", freshNonce[i]);
	}
	std::cout << "\n>>>Servidor confirmou a identidade do cliente." << std::endl;
	

	std::cout << ">>>FreshNonce do servidor para atesta��o: ";
	for (int i = 0; i < freshNonce.size(); i++)
	{
		printf("%02x", freshNonce[i]);
	}
	

	//realizando quote
	TccTpm::processQuote(tpmdata.pcrsToMakeQuote, freshNonce, tpmdata.quoteForServer, tpmdata.encodedPCRS, tpmdata.encodedSignatureQuote);
	communicationSendQuoteForAttestation();

	ShutDownTpm();
}

