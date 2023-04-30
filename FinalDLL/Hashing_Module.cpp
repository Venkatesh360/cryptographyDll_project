#include "pch.h"
#include "ProjectHeader.h"
#include <iostream>
#include <cryptlib.h>
#include <sha3.h>
using namespace std;
using namespace CryptoPP;

void sha_256_Hashing(std::string message)
{
    SHA3_256 hash;

    try {
        byte digest[SHA3_256::DIGESTSIZE];

        hash.CalculateDigest(digest, (byte*)message.c_str(), message.length());

        std::cout << "SHA-3 256-bit digest: ";
        for (int i = 0; i < SHA3_256::DIGESTSIZE; i++)
        {
            std::cout << std::hex << (int)digest[i];
        }
        std::cout << std::endl;

    }
    catch (const Exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return;
    }

    return ;
}

void sha_512_Hashing(std::string message)
{
    try {
        SHA3_512 hash;
        byte digest[SHA3_512::DIGESTSIZE];

        hash.CalculateDigest(digest, (byte*)message.c_str(), message.length());

        std::cout << "SHA-3 512-bit digest: ";
        for (int i = 0; i < SHA3_512::DIGESTSIZE; i++)
        {
            std::cout << std::hex << (int)digest[i];
        }
        std::cout << std::endl;
    }
    catch (const Exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return;
    }

    return;
}