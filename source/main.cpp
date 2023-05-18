#include <cpr/cpr.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <iostream>
#include <string>
#include <json/json.hpp>
class BinanceApiRequest
{
public:
	BinanceApiRequest(std::string apiKey, std::string secretKey, std::string baseURL)
	{
		this->apiKey = apiKey;
		this->secretKey = secretKey;
		this->baseURL = baseURL;
	}

	std::string GenerateSignature(std::string queryString)
	{
		unsigned char digest[SHA256_DIGEST_LENGTH];
		HMAC_CTX *hmac_ctx = HMAC_CTX_new();
		HMAC_Init_ex(hmac_ctx, secretKey.c_str(), secretKey.length(), EVP_sha256(), NULL);
		HMAC_Update(hmac_ctx, (unsigned char *)queryString.c_str(), queryString.length());
		unsigned int len = SHA256_DIGEST_LENGTH;
		HMAC_Final(hmac_ctx, digest, &len);
		HMAC_CTX_free(hmac_ctx);

		std::stringstream ss;
		ss << std::hex << std::setfill('0');
		for (unsigned char c : digest)
		{
			ss << std::setw(2) << static_cast<int>(c);
		}
		return ss.str();
	}

	cpr::Response Send(std::string endpoint, std::string queryString)
	{
		std::string finalURL = baseURL + endpoint + "?" + queryString + "&signature=" + GenerateSignature(queryString);
		cpr::Header header;
		header.emplace("X-MBX-APIKEY", apiKey);

		cpr::Response response = cpr::Post(cpr::Url{finalURL}, header);
		if (response.error)
		{
			std::cout << "Error sending request: " << response.error.message << std::endl;
			return response;
		}

		std::cout << "Response Code: " << response.status_code << std::endl;
		nlohmann::json jsonData = nlohmann::json::parse(response.text);
		std::string parsedData;
		for (auto it = jsonData.begin(); it != jsonData.end(); ++it)
		{
			parsedData += it.key() + ": " + it.value().dump() + "\n";
		}
		std::cout << "Parsed Data:\n"
				<< parsedData << std::endl;
		return response;
	}

	cpr::Response PlaceOrder(std::string symbol, int quantity, std::string side)
	{
		long long timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
							 std::chrono::system_clock::now().time_since_epoch())
							 .count();
		std::string queryString = "quantity=" + std::to_string(quantity) + "&side=" + side + "&symbol=" + symbol + "&timestamp=" + std::to_string(timestamp) + "&type=MARKET";
		return Send("/fapi/v1/order", queryString);
	}

	cpr::Response getAccountTrades(std::string symbol)
	{
		long long timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
							 std::chrono::system_clock::now().time_since_epoch())
							 .count();
		std::string queryString = "symbol=" + symbol +
							 "&startTime=" + std::to_string(timestamp - 7 * 24 * 60 * 60 * 1000) +
							 "&endTime=" + std::to_string(timestamp);

		return Send("/fapi/v1/userTrades", queryString);
	}

	cpr::Response GetAccountInfo()
	{
		return Send("/fapi/v1/account", "");
	}

private:
	std::string apiKey;
	std::string secretKey;
	std::string baseURL;
};

int main()
{
	
	
	BinanceApiRequest request(apiKey, secretKey, "https://fapi.binance.com");
	
	// Place an order
	// size_t quantity_to_buy{};
	// std::string sa;
	 cpr::Response response{};
	// while (true)
	// {
	// 	std::string sa;
	// 	std::getline(std::cin, sa);
	// 	quantity_to_buy = stoi(sa);
	// 	response = request.PlaceOrder("AUDIOUSDT", quantity_to_buy, "BUY");
	// }
	
	// cpr::Response response = request.PlaceOrder("AUDIOUSDT", 24, "BUY");
	
	// Get account information
	//response = request.GetAccountInfo();
	request.getAccountTrades("AUDIOUSDT");
	return 0;
}