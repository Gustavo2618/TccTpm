#include <iostream>
#include <string>
#include <memory>
#include <stdexcept>
#include <Tpm2.h>
#include "keys.h"
#include "templates.h"
#include "Enum.h"
#include "structs.h"

extern TpmData tpmdata;

void createEKey(TpmCpp::TPMT_PUBLIC& ek, TpmCpp::TPM_HANDLE& ekhandle)
{
	std::cout << "\n>>>Gerando a Chave EK...\n" << std::endl;
	auto createPrimaryResponse = makeEndorsementKey(tpmdata.keyType);
	ek = createPrimaryResponse.outPublic;
	ekhandle = createPrimaryResponse.handle;
	std::cout << ek.ToString() << std::endl;
	/*std::cout << ekhandle.ToString() << std::endl;*/

	std::cout << "\n>>>Chave EK Criada com sucesso!" << std::endl;
}
TpmCpp::CreatePrimaryResponse makeEndorsementKey(KeyType keyType)
{
	return tpmdata.tpm.CreatePrimary(TpmCpp::TPM_RH::ENDORSEMENT,{}, Templates::ekRsaTemplate(), {}, {});
}
TpmCpp::TPM_HANDLE makeAttestationKey(TpmCpp::TPM_HANDLE& ekHandle, KeyType& keyType, TpmCpp::TPMT_PUBLIC &ak, TpmCpp::TPM_HANDLE &akhandle, TpmCpp::CreateResponse &akResponse)
{
	std::cout << "\n>>>Gerando a Chave AK...." << std::endl;
	auto tempAkKey = tpmdata.tpm._AllowErrors().Create(ekHandle, {}, Templates::akRsaTemplate(), {}, {});
	if (tpmdata.tpm._GetLastResponseCode() != TpmCpp::TPM_RC::SUCCESS)
	{
		std::cout << ">>>Falha no comando ! " << TpmCpp::EnumToStr(tpmdata.tpm._GetLastResponseCode()) << std::endl;

	}
	/*std::cout << tempAkKey.ToString() << std::endl;*/
	//parte publica da AK
	ak = tempAkKey.outPublic;
	std::cout << "\n>>>Attestation Key: \n" << std::endl;
	std::cout << ak.ToString() << std::endl;
	/*std::cout << tempAkKey.ToString() << std::endl;*/
	akhandle = tempAkKey.getHandle();
	//handle da ak
	//std::cout << " >>>Ak Handle:" << std::endl;
	//std::cout << akhandle.ToString() << std::endl;
	akResponse = tempAkKey;
	std::cout << "\n>>>AK criada com sucesso!" << std::endl;
	
	return tpmdata.tpm.Load(ekHandle, tempAkKey.outPrivate, tempAkKey.outPublic);
}