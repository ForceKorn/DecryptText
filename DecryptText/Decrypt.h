#pragma once

#include <vector>

void DecryptAes(const std::vector<unsigned char>& chipherText, std::vector<unsigned char>& plainText,
    const unsigned char* key, const unsigned char* iv);

void Decrypt(const unsigned char* key, const unsigned char* iv);
