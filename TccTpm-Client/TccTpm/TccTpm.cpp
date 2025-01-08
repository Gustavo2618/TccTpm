

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
	std::cout << "\n>>>Iniciando o Processo de prova de posse das chaves!" <<std::endl;
	TccTpm::processProvisioning(tpmdata.ek, tpmdata.ekhandle, tpmdata.ak, tpmdata.akhandle, tpmdata.akResponse, tpmdata.ekpubContent, tpmdata.akpubContent);
	

	//Processo de Certificação de uma chave criada pelo tpm
	TccTpm::processCertify(tpmdata.akhandle, tpmdata.certify, tpmdata.certifyInfo, tpmdata.certifySignatureBytes);
	
	//Realizando primeira comunicação com servidor para a certificação da chave de atestação
	std::string responseProofOfPossetion = communicationProofOfPossetion();
	
	if (responseProofOfPossetion.empty())
	{
		return std::cout << ">>>Sem resposta do servidor..." << std::endl, -1;
	}
	std::cout << "\n>>>Processo de prova de posse terminado com sucesso!\n" << std::endl;

	//Verificando Secret enviado pelo servidor e rebendo secret para atestação com o quote
	std::cout << ">>>Inicio do processo de challenge do cliente!" << std::endl;
	TccTpm::JsonResponseProofOfPossetion(responseProofOfPossetion);
	TpmCpp::ByteVec freshNonce = communicationSendRecoveredSecretForAttestation(tpmdata.credentialFromServer, tpmdata.secretFromServer);
	std::cout << "\n>>>FreshNonce: ";
	for (int i = 0; i < freshNonce.size(); i++)
	{
		printf("%02x", freshNonce[i]);
	}
	
	std::cout <<"\n\n>>>Servidor confirmou a identidade do cliente.\n" << std::endl;
	std::cout << ">>>Fim do processo de challenge!\n" << std::endl;

	std::cout << ">>>Inicio do processo de atestacao usando o quote!\n" << std::endl;
	//realizando quote
	TccTpm::processQuote(tpmdata.pcrsToMakeQuote, freshNonce, tpmdata.quoteForServer, tpmdata.encodedPCRS, tpmdata.encodedSignatureQuote);
	
	
	
	if (!communicationSendQuoteForAttestation())
	{
		std::cout << ">>>Fim do processo de atestacao utilizando quote cliente autenticado!" << std::endl;
	}
	else {
		std::cout << ">>>Fim do processo de atestacao utilizando quote cliente nao conseguiu se autenticar!" << std::endl;
	}

	ShutDownTpm();
}

