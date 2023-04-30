#include "pch.h"
#include "ProjectHeader.h"

#include <base64.h>
#include <cryptlib.h>
#include <iostream>
#include <string>
#include <iomanip>
#include <pwdbased.h>
#include <md5.h>
#include <sha3.h>
#include <osrng.h>
#include <oids.h>
#include <scrypt.h>
#include <rsa.h>
#include <ecp.h>
#include <secblock.h>
#include <filters.h>
#include <files.h>
#include <rsa.h>
#include <hex.h>

using namespace CryptoPP;
using namespace std;

void PBKDF1(std::string password, std::string salt)
{

    const int iterations = 1000;
    const int derivedKeyLength = 16;

    CryptoPP::SecByteBlock derived(derivedKeyLength);

    CryptoPP::PKCS5_PBKDF1<CryptoPP::MD5> pbkdf;
    pbkdf.DeriveKey(derived.data(), derived.size(), 0, (byte*)password.data(), password.size(), (byte*)salt.data(), salt.size(), iterations);

    std::string encodedKey;
    CryptoPP::StringSource(derived.data(), derived.size(), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encodedKey)));

    std::cout << "Encoded Key: " << encodedKey << std::endl;

    return ;
}

void PBKDF2(std::string password, std::string salt)
{
    const int iterations = 10000;
    const int derivedKeyLength = 32;

    CryptoPP::SecByteBlock derived(derivedKeyLength);

    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
    pbkdf.DeriveKey(derived.data(), derived.size(), 0, (byte*)password.data(), password.size(), (byte*)salt.data(), salt.size(), iterations);

    std::string encodedKey;
    CryptoPP::StringSource(derived.data(), derived.size(), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encodedKey)));

    std::cout << "Encoded Key: " << encodedKey << std::endl;

    return ;
}

void rsa_key_generation()
{

    // Random number generator
    AutoSeededRandomPool rng;

    // Generate private key
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 2048);

    // Generate public key
    RSA::PublicKey publicKey(privateKey);

    // Print private key
    std::cout << "Private key:" << std::endl;
    std::cout << "  Modulus: " << privateKey.GetModulus() << std::endl;
    std::cout << "  Exponent: " << privateKey.GetPublicExponent() << std::endl;
    std::cout << "  Private exponent: " << privateKey.GetPrivateExponent() << std::endl;
    std::cout << "  Prime1: " << privateKey.GetPrime1() << std::endl;
    std::cout << "  Prime2: " << privateKey.GetPrime2() << std::endl;
    std::cout << "  Exponent1: " << privateKey.GetModPrime1PrivateExponent() << std::endl;
    std::cout << "  Exponent2: " << privateKey.GetModPrime2PrivateExponent() << std::endl;
    std::cout << "  Coefficient: " << privateKey.GetMultiplicativeInverseOfPrime2ModPrime1() << std::endl;

    // Print public key
    std::cout << "Public key:" << std::endl;
    std::cout << "  Modulus: " << publicKey.GetModulus() << std::endl;
    std::cout << "  Exponent: " << publicKey.GetPublicExponent() << std::endl;

    return;
}

void scrypt(std::string password, std::string salt)
{

    const int iterations = 16384;
    const int blockSize = 8;
    const int parallelism = 1;
    const int derivedKeyLength = 32;

    CryptoPP::SecByteBlock derived(derivedKeyLength);

    CryptoPP::Scrypt pbkdf;
    pbkdf.DeriveKey(derived.data(), derived.size(), (byte*)password.data(), password.size(), (byte*)salt.data(), salt.size(), iterations, blockSize, parallelism);

    std::string encodedKey;
    CryptoPP::StringSource(derived.data(), derived.size(), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encodedKey)));

    std::cout << "Encoded Key: " << encodedKey << std::endl;

    return ;
}

