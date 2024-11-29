
#include<curlpp/cURLpp.hpp>
#include<curlpp/Easy.hpp>
#include <curlpp/Options.hpp>
#include <json/json.h>

#include "request.h";
#include "defines.h";

std::string getProcessPhaseStr(ProcessPhase phase)
{
	switch (phase)
	{
	case INITIAL_CHALLENGE:
		return "http://localhost:8080/requestfirst";
	case PROVISIONING:
		return "http://localhost:8080/InitialCommunication";
	case SECRET_CHECK_FOR_ATTESTATION:
		return "http://localhost:8080/secretCheckForAttestation";
	case RESULT_ATTESTATION:
		return "http://localhost:8080/resultAttestation";
	
	default:
		return "Url Error";
	}
}

std::string makeRequest(ProcessPhase phase, std::string data, bool verbose = false)
{
	try {
		curlpp::Cleanup curlCleaner;
		curlpp::Easy httpRequest;
		std::ostringstream httpResponse;
		httpRequest.setOpt(new curlpp::options::WriteStream(&httpResponse));
		httpRequest.setOpt(new curlpp::options::Url(getProcessPhaseStr(phase)));
	/*	httpRequest.setOpt<curlpp::options::Url>("http://localhost:8080/requestfirst");*/
		httpRequest.setOpt(new curlpp::options::PostFields(data));
		httpRequest.setOpt(new curlpp::options::PostFieldSize(data.size()));
		if (verbose)
		{

			LOG("\t>>> Performing Request....");
		}

		httpRequest.perform();
		if (verbose)
		{
			LOG("\t>>> Request response: ");
		
		}

		return httpResponse.str();
			
	}
	catch (curlpp::LogicError& e)
	{
		std::cout << e.what() << std::endl;
		return "Request Error";
	}
	catch (curlpp::RuntimeError& e)
	{
		std::cout << e.what() << std::endl;
		return "Request Error";
	}
}