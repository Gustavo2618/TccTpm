

#include <iostream>
#include<iomanip>
#include <string.h>
#include "tpm.h"
#include "Enum.h"
#include "keys.h"
#include "Encoders.h"
#include "utils.h"
#include "structs.h"


extern TpmData tpmdata;
namespace TccTpm {
	//processo de provisionamento de chaves EK e AK
	void processProvisioning(TpmCpp::TPMT_PUBLIC& ek, TpmCpp::TPM_HANDLE& ekHandle, TpmCpp::TPMT_PUBLIC& ak,
		TpmCpp::TPM_HANDLE& akHandle, TpmCpp::CreateResponse& akResponse, std::string& ekPubContent, std::string& akPubContent) {
		createEKey(ek, ekHandle);
		akHandle = makeAttestationKey(ekHandle, tpmdata.keyType, ak, akHandle, akResponse);
		std::cout << "\nEkbytes: ";
		for (int l = 0; l < ek.toBytes().size(); l++){
			std::cout << std::hex << std::setw(2) << std::setfill('0')
				<< static_cast<int>(ek.toBytes()[l]) << " ";
		}
		std::cout << "\n\nAkbytes: ";
		for (int l = 0; l < ak.toBytes().size(); l++) {
			std::cout << std::hex << std::setw(2) << std::setfill('0')
				<< static_cast<int>(ak.toBytes()[l]) << " ";
		}
		ekPubContent = base64Encode(ek.toBytes(), true);
		akPubContent = base64Encode(ak.toBytes(), true);
	}
	//processo para certificar uma chave do tpm.
	void processCertify(TpmCpp::TPM_HANDLE& akHandle, TpmCpp::CertifyResponse& certifyData, std::string& certifyInfo, TpmCpp::ByteVec& certifySignatureBytes) {
		std::cout << "\n\n>>>Certificando que a Chave AK vem do TPM usando Certify.\n" << std::endl;
		certifyData = tpmdata.tpm.Certify(akHandle, akHandle, {}, TpmCpp::TPMS_NULL_SIG_SCHEME());
		std::cout << certifyData.ToString();
		certifyInfo = base64Encode(certifyData.certifyInfo.toBytes(), true);
		std::cout << "\n\n>>>CerifyInfo: ";
		printBytesHex(certifyData.certifyInfo.toBytes());
		std::cout << "\n>>>CerifySignature: ";
		printBytesHex(certifyData.signature->toBytes());
		certifySignatureBytes = certifyData.signature->toBytes();
		tpmdata.rawDataSignature.insert(tpmdata.rawDataSignature.end(), tpmdata.certifySignatureBytes.begin() + 4, tpmdata.certifySignatureBytes.end());
		std::cout << "\n>>>Certify criado com sucesso!"<<std::endl;
	}

	TpmCpp::ByteVec processActivateCredential(std::string& credentialFromServer, std::string& secretFromServer) {
		TpmCpp::ByteVec credentialBytes = base64Decode(credentialFromServer);
		TpmCpp::ByteVec secretBytes = base64Decode(secretFromServer);
		std::cout << "\n>>>Processo de Activate Credential para atestacao.\n" << std::endl;
		std::cout << ">>>Bytes da credencial: ";
		printBytesHex(credentialBytes);
		std::cout << ">>>Segredo em bytes: ";
		printBytesHex(secretBytes);
		std::cout << ">>>Blob da credential:\n\n ";
		TpmCpp::TPM2B_ID_OBJECT credentialBlob = TpmCpp::TPM2B_ID_OBJECT::fromBytes(credentialBytes);
		std::cout << credentialBlob.ToString() << std::endl;
		TpmCpp::ByteVec newSecretBytes;
		for (int i = 2; i < secretBytes.size(); i++) {
			newSecretBytes.push_back(secretBytes[i]);
		}
		
		TpmCpp::ByteVec recoveredSecret = tpmdata.tpm._AllowErrors().ActivateCredential(tpmdata.akhandle, tpmdata.ekhandle, credentialBlob.credential, newSecretBytes);
		//verificando se o activate Credential deu certo.
		if (tpmdata.tpm._GetLastResponseCode() != TpmCpp::TPM_RC::SUCCESS) {
			std::cout << ">>>Falha ao realizar o activateCredential " << TpmCpp::EnumToStr(tpmdata.tpm._GetLastResponseCode()) << std::endl;
		}

		//Enviando recoveredSecret para o server.
		std::cout << "\n>>>Segredo enviado pelo servidor: ";
		printBytesHex(recoveredSecret);
		std::cout << ">>>Processo de activate crendential finalizado com successo! "<<std::endl;
		return recoveredSecret;
	}

	//processo de quote para enviar ao servidor
	void processQuote(std::vector<UINT32>& pcrsToMakeQuote, TpmCpp::ByteVec& Nonce, std::string& encodedQuoteForServer, std::string& encodedPcrs, std::string& encodedSignatureQuote) {
	
		std::vector<TpmCpp::TPMS_PCR_SELECTION>digestFromPcrs{ TpmCpp::TPMS_PCR_SELECTION(TpmCpp::TPM_ALG_ID::SHA256, pcrsToMakeQuote) };
		tpmdata.readingDigestFromPcrs = tpmdata.tpm.PCR_Read(digestFromPcrs);
		//pegando o digest de todos os PCR's
		TpmCpp::ByteVec tempVec;
		for (int i = 0; i < tpmdata.readingDigestFromPcrs.pcrValues.size(); i++) {
			tempVec.insert(tempVec.end(), tpmdata.readingDigestFromPcrs.pcrValues[i].buffer.begin(), tpmdata.readingDigestFromPcrs.pcrValues[i].buffer.end());
		}
		
		std::cout << ">>>Digest dos pcr's: \n\n" << tpmdata.readingDigestFromPcrs.ToString() << std::endl;
		tpmdata.quote = tpmdata.tpm._AllowErrors().Quote(tpmdata.akhandle, Nonce, TpmCpp::TPMS_NULL_SIG_SCHEME(), digestFromPcrs);
	
		if (tpmdata.tpm._GetLastResponseCode() != TpmCpp::TPM_RC::SUCCESS) {
			std::cout << "Falha ao tentar criar o quote! " << TpmCpp::EnumToStr(tpmdata.tpm._GetLastResponseCode()) << std::endl;
		}
		std::cout << tpmdata.quote.ToString() << std::endl;
		std::cout << "\n>>>Sucesso ao criar Quote!" << std::endl;
		std::shared_ptr<TpmCpp::TPMU_SIGNATURE> sharedPointerQuoteSignature = tpmdata.quote.signature;
		TpmCpp::ByteVec quoteSignaturebytes = tpmdata.quote.signature->toBytes();
	
		TpmCpp::ByteVec tempBytevec;
		tempBytevec.reserve((quoteSignaturebytes.size() - 4));
		tempBytevec.insert(tempBytevec.begin(), quoteSignaturebytes.begin() + 4, quoteSignaturebytes.end());
		//encodando todas as informações do quote
		encodedSignatureQuote = base64Encode(tempBytevec,true);
		encodedQuoteForServer = base64Encode(tpmdata.quote.quoted.toBytes(), true);
		encodedPcrs = base64Encode(tempVec, true);
	}
}