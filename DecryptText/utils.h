#pragma once

#include <string>
#include <vector>

inline const std::string gk_sourceDir         = "TextSources\\";
inline const std::string gk_fileNameToEncrypt = gk_sourceDir + "encode_text";
inline const std::string gk_fileNameToDecrypt = gk_sourceDir + "chipher_text";
inline const std::string gk_plainOutput       = gk_sourceDir + "plain_text";

void ReadFile(const std::string& filePath, std::vector<unsigned char>& buf);

void WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf);

void AppendToFile(const std::string& filePath, const std::vector<unsigned char>& buf);

void PasswordToKey(std::string& password, unsigned char* key, unsigned char* iv);

void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash);
