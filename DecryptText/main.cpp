#include "utils.h"
#include "Encrypt.h"
#include "Decrypt.h"

#include <iostream>
#include <stdexcept>
#include <string>

#include <openssl/evp.h>


unsigned char key[EVP_MAX_KEY_LENGTH];
unsigned char iv[EVP_MAX_IV_LENGTH];


int main()
{
    std::string pass = "pass";

    try
    {
        PasswordToKey(pass, key, iv);
        //Encrypt(key, iv);
        Decrypt(key, iv);
    }
    catch (const std::runtime_error& ex)
    {
        std::cerr << ex.what();
    }
}
