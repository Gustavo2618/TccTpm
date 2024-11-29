#pragma once
#include<string >

enum ProcessPhase
{
	INITIAL_CHALLENGE,
	PROVISIONING,
	SECRET_CHECK_FOR_ATTESTATION,
	RESULT_ATTESTATION,/*
	ALTERNATIVE_INITIAL_CHALLENGE,
	ALTERNATIVE_SECRET_CHECK,*/
};
std::string getProcessPhaseStr(ProcessPhase phase);
std::string makeRequest(ProcessPhase phase, std::string data, bool verbose);