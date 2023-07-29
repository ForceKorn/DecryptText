#pragma once

#include <vector>

void EncryptAes(const std::vector<unsigned char> plainText, std::vector<unsigned char>& chipherText,
    const unsigned char* key, const unsigned char* iv);

void Encrypt(const unsigned char* key, const unsigned char* iv);
