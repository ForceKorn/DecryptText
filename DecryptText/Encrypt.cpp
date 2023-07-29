#include "Encrypt.h"
#include "utils.h"

#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/aes.h>


void EncryptAes(const std::vector<unsigned char> plainText, 
                std::vector<unsigned char>& chipherText,
                const unsigned char* key, 
                const unsigned char* iv)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        throw std::runtime_error("EncryptInit error");
    }

    std::vector<unsigned char> chipherTextBuf(plainText.size() + AES_BLOCK_SIZE);
    int chipherTextSize = 0;
    if (!EVP_EncryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &plainText[0], plainText.size())) 
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encrypt error");
    }

    int lastPartLen = 0;
    if (!EVP_EncryptFinal_ex(ctx, &chipherTextBuf[0] + chipherTextSize, &lastPartLen)) 
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptFinal error");
    }

    chipherTextSize += lastPartLen;
    chipherTextBuf.erase(chipherTextBuf.begin() + chipherTextSize, chipherTextBuf.end());

    chipherText.swap(chipherTextBuf);

    EVP_CIPHER_CTX_free(ctx);
}

void Encrypt(const unsigned char* key, const unsigned char* iv)
{
    const std::string& encodedFileName  = gk_fileNameToEncrypt;
    const std::string& dencodedFileName = gk_fileNameToDecrypt;

    std::vector<unsigned char> plainText;
    ReadFile(encodedFileName.data(), plainText);

    std::vector<unsigned char> hash;
    CalculateHash(plainText, hash);

    std::vector<unsigned char> chipherText;
    EncryptAes(plainText, chipherText, key, iv);

    WriteFile(dencodedFileName, chipherText);
    AppendToFile(dencodedFileName, hash);
}
