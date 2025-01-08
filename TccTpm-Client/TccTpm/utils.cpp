#include<iostream>
#include "utils.h"
#include "structs.h"

extern TpmData tpmdata;

int InitTpm()
{
	if (tpmdata.useSimulator)
	{
		if (!tpmdata.tcpDevice.Connect("127.0.0.1", 2321))
		{
			std::cerr << "Nao foi possivel fazer a conexao com o simulador tpm!\n";
			return -1;
		}
		tpmdata.tpm._SetDevice(tpmdata.tcpDevice);
		tpmdata.tcpDevice.PowerOff();
		tpmdata.tcpDevice.PowerOn();
		tpmdata.tpm.Startup(TpmCpp::TPM_SU::CLEAR);
		return 0;
	}
	if (!tpmdata.tbsDevice.Connect())
	{
		std::cerr << "Nao foi possivel fazer a conexao com o tpm via Hardware!\n";
		return -1;
	}
	tpmdata.tpm._SetDevice(tpmdata.tbsDevice);
	return 0;
}

void ShutDownTpm()
{
	if (!tpmdata.useSimulator) return;
	tpmdata.tpm.Shutdown(TpmCpp::TPM_SU::CLEAR);
	tpmdata.tcpDevice.PowerOff();
}
TpmCpp::ByteVec toByteVec(const std::shared_ptr<TpmCpp::TPMU_SIGNATURE>& ptr, size_t skipBytes) {
	// Tamanho total do objeto apontado
	size_t totalSize = sizeof(TpmCpp::TPMU_SIGNATURE);

	// Verificar se o número de bytes a pular é menor que o tamanho total
	if (skipBytes >= totalSize) {
		throw std::invalid_argument("O número de bytes a pular é maior ou igual ao tamanho do objeto.");
	}

	// Tamanho dos dados após pular os bytes
	size_t dataSize = totalSize - skipBytes;

	// Criar um ByteVec e ajustar o tamanho para dataSize
	TpmCpp::ByteVec byteVec(dataSize);

	// Copiar os dados para o ByteVec, começando após os bytes pulados
	std::memcpy(byteVec.data(), reinterpret_cast<const uint8_t*>(ptr.get()) + skipBytes, dataSize);

	return byteVec;
}
void printBytesHex(TpmCpp::ByteVec vec) {
	for (size_t i = 0; i < vec.size(); ++i) {
		printf("%02x ",vec[i]);
	}
	printf("\n\n");
}