#include "Decrypt.h"
#include "utils.h"

#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

void DecryptAes(const std::vector<unsigned char>& chipherText, 
                std::vector<unsigned char>& plainText,
                const unsigned char* key,
                const unsigned char* iv)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    plainText.resize(chipherText.size() + AES_BLOCK_SIZE);

    int plainTextSize = 0;
    int decryptError = EVP_DecryptUpdate(ctx, &plainText[0], &plainTextSize, &chipherText[0], chipherText.size());
    if (decryptError <= 0)
    {
        throw std::runtime_error("Decrypt error");
    }

    int lastPartLen = 0;
    decryptError = EVP_DecryptFinal_ex(ctx, &plainText[0] + plainTextSize, &lastPartLen);
    if (decryptError <= 0)
    {
        throw std::runtime_error("DecryptFinal error");
    }

    plainTextSize += lastPartLen;
    plainText.erase(plainText.begin() + plainTextSize, plainText.end());

    EVP_CIPHER_CTX_free(ctx);
}

void Decrypt(const unsigned char* key, const unsigned char* iv)
{
    const std::string& encodedFileName = gk_fileNameToDecrypt;
    const std::string& decodedFileName = gk_plainOutput;

    std::vector<unsigned char> chipherText;
    ReadFile(encodedFileName, chipherText);

    chipherText.resize(chipherText.size() - SHA256_DIGEST_LENGTH);
    
    std::vector<unsigned char> plainText;
    DecryptAes(chipherText, plainText, key, iv);

    WriteFile(decodedFileName, plainText);
}
