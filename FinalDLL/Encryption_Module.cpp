
#include "pch.h"
#include "ProjectHeader.h"
#include <iostream>
#include <string>
#include <iostream>
#include <Windows.h>
#include "osrng.h"
#include <iostream>
#include <string>
#include <cstdlib>
#include "cryptlib.h"
#include "hex.h"
#include "filters.h"
#include "files.h"
#include "aes.h"
#include "ccm.h"
#include "assert.h"
#include <modes.h>
#include <gcm.h>
#include <cmac.h>
#include <rsa.h>
#include <base64.h>
#include <stdexcept>
#include <hmac.h>
#include <sha.h>
#include <secblock.h>
#include <blowfish.h>
#include <twofish.h>
#include <chacha.h>

using namespace CryptoPP;
using namespace std;


void aes128_gmc_encryption(std::string plaintext)
{
    byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    byte iv[CryptoPP::AES::BLOCKSIZE];
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(key, sizeof(key));
    prng.GenerateBlock(iv, sizeof(iv));

    // Set up the GCM cipher object
    CryptoPP::GCM<CryptoPP::AES>::Encryption gcmEncryptor;
    gcmEncryptor.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    // Encrypt a message
    std::string ciphertext;
    CryptoPP::StringSource(plaintext, true, new CryptoPP::AuthenticatedEncryptionFilter(gcmEncryptor,
        new CryptoPP::StringSink(ciphertext)));

    // Print the encrypted message
    std::cout << "Ciphertext: " << ciphertext << std::endl;
    std::cout << "key: " << key << std::endl;
    std::cout << "IV: " << iv << std::endl;

    // Set up the GCM cipher object for decryption


    return;
}

void aes128_gcm_decryption(std::string ciphertext, std::string KEY, std::string IV) {

    byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    byte iv[CryptoPP::AES::BLOCKSIZE];

    // Convert the key string to a binary representation using a hash function
    CryptoPP::SHA256().CalculateDigest(key, reinterpret_cast<const CryptoPP::byte*>(KEY.data()), KEY.length());
    CryptoPP::SHA256().CalculateDigest(iv, reinterpret_cast<const CryptoPP::byte*>(IV.data()), IV.length());

    CryptoPP::GCM<CryptoPP::AES>::Decryption gcmDecryptor;
    gcmDecryptor.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    // Decrypt the message
    std::string decryptedtext;
    CryptoPP::StringSource(ciphertext, true, new CryptoPP::AuthenticatedDecryptionFilter(gcmDecryptor,
        new CryptoPP::StringSink(decryptedtext)));

    // Print the decrypted message
    std::cout << "Decrypted text: " << decryptedtext << std::endl;
}


void aes128_cbc_encryption(std::string plaintext)
{
    // The key and IV
    byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(key, sizeof(key));


    // Generate a random IV
    byte iv[CryptoPP::AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));


    // Encrypt the plaintext
    std::string ciphertext;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption(key, sizeof(key), iv);
    CryptoPP::StringSource(plaintext, true,
        new CryptoPP::StreamTransformationFilter(encryption,
            new CryptoPP::StringSink(ciphertext)
        )
    );

    // Output the ciphertext
    std::cout << "Ciphertext: " << ciphertext << std::endl;
    std::cout << "Key: " << key << std::endl;
    std::cout << "IV: " << iv << std::endl;


    return;
}

void aes_cbc_decryptor(std::string ciphertext, std::string KEY, std::string IV) {
    // Decrypt the ciphertext
    byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];

    CryptoPP::StringSource(KEY, true,
        new CryptoPP::ArraySink(key, CryptoPP::AES::DEFAULT_KEYLENGTH)
    );

    byte iv[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::StringSource(IV, true,
        new CryptoPP::ArraySink(iv, CryptoPP::AES::DEFAULT_KEYLENGTH)
    );
    std::string decryptedtext;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption(key, sizeof(key), iv);
    CryptoPP::StringSource(ciphertext, true,
        new CryptoPP::StreamTransformationFilter(decryption,
            new CryptoPP::StringSink(decryptedtext)
        )
    );

    // Output the decrypted text
    std::cout << "Decrypted text: " << decryptedtext << std::endl;

}


void aes128_ctr_encription(std::string plaintext)
{
    // The key and nonce to use for encryption
    byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    byte nonce[CryptoPP::AES::BLOCKSIZE];
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(key, sizeof(key));
    rng.GenerateBlock(nonce, sizeof(nonce));

    // Create the AES-128 CTR cipher object
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption cipher;
    cipher.SetKeyWithIV(key, sizeof(key), nonce);

    // Encrypt the plaintext
    std::string ciphertext;
    CryptoPP::StringSource(plaintext, true,
        new CryptoPP::StreamTransformationFilter(cipher,
            new CryptoPP::StringSink(ciphertext)
        )
    );

    // Output the encrypted text
    cout << "Ciphertext: " << ciphertext << std::endl;
    cout << "Key: " << key << endl;
    cout << "Nounce: " << nonce << endl;


    return;
}

void aes_128_decryptor(std::string ciphertext, std::string KEY, std::string NONCE) {

    // Decrypt the ciphertext

    byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];

    CryptoPP::StringSource(KEY, true,
        new CryptoPP::ArraySink(key, CryptoPP::AES::DEFAULT_KEYLENGTH)
    );

    byte nonce[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::StringSource(NONCE, true,
        new CryptoPP::ArraySink(nonce, CryptoPP::AES::DEFAULT_KEYLENGTH)
    );


    std::string decryptedtext;

    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, sizeof(key), nonce);
    CryptoPP::StringSource(ciphertext, true,
        new CryptoPP::StreamTransformationFilter(decryptor,
            new CryptoPP::StringSink(decryptedtext)
        )
    );

    // Output the decrypted text
    std::cout << "Decryptedtext: " << decryptedtext << std::endl;

}


void rsa_encryption(string Public_Key)
{
    // Set up the keys (these could also be read in from files)
    ifstream file(Public_Key);
    string keyStrPublic((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    RSA::PublicKey publicKey;
    publicKey.Load(StringSource(keyStrPublic, true).Ref());


    // Set up the plaintext message
    string plaintext = "Hello, world!";

    // Encrypt the message
    AutoSeededRandomPool rng;
    string ciphertext;
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    StringSource(plaintext, true, new PK_EncryptorFilter(rng, encryptor, new StringSink(ciphertext)));
    Base64Encoder encode;
    // Output the ciphertext
    cout << "Ciphertext: " << encode.Put(reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) << endl;

    return;
}

void rsa_decreption(string Private_Key)
{

    // Set up the keys (these could also be read in from files)
    ifstream file(Private_Key);
    string keyStrPrivate((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    RSA::PrivateKey privateKey;
    privateKey.Load(StringSource(keyStrPrivate, true).Ref()); // Load the private key from a file or string

    // Set up the ciphertext message
    string ciphertext = "ENCODED_CIPHERTEXT"; // Replace with the Base64-encoded ciphertext

    // Decrypt the message
    AutoSeededRandomPool rng;
    string plaintext;
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    StringSource(reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size(), true, new PK_DecryptorFilter(rng, decryptor, new StringSink(plaintext)));

    // Output the plaintext
    cout << "Plaintext: " << plaintext << endl;

    return;
}


void BlowFish_encyription(std::string plaintext, std::string key) {

    // Create a Blowfish encryption object and set the key
    CryptoPP::BlowfishEncryption encryption;
    encryption.SetKey((const byte*)key.data(), key.size());

    // Encrypt the plaintext using CBC mode
    std::string ciphertext;
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(encryption, (const byte*)key.data());
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size());
    stfEncryptor.MessageEnd();

    // Print the resulting ciphertext
    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size());
    encoder.MessageEnd();
    std::cout << "Encoded output: " << output << std::endl;


    return;
}

void BlowFish_decryption(std::string ciphertext, std::string key) {

    // Create a Blowfish decryption object and set the key
    CryptoPP::BlowfishDecryption decryption;
    decryption.SetKey((const byte*)key.data(), key.size());

    // Decrypt the ciphertext using CBC mode
    std::string decryptedtext;
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(decryption, (const byte*)key.data());
    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
    stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size());
    stfDecryptor.MessageEnd();

    // Print the resulting decrypted plaintext
    std::cout << "Decrypted plaintext: " << decryptedtext << std::endl;

    return;
}


void twofish_encryptor(std::string plaintext, std::string key)
{


    // Set up the encryption and decryption objects
    CryptoPP::Twofish::Encryption encryptor((const byte*)key.data(), key.size());

    // Set up the modes of operation
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryptor(encryptor, (const byte*)"1234567890123456");

    // Encrypt the plaintext
    std::string ciphertext;
    CryptoPP::StringSource(plaintext, true,
        new CryptoPP::StreamTransformationFilter(cbcEncryptor,
            new CryptoPP::StringSink(ciphertext)
        )
    );

    std::cout << "Ciphertext: " << ciphertext << std::endl;


    return;
}

void twofish_decryptor(std::string ciphertext, std::string KEY) {

    CryptoPP::Twofish::Decryption decryptor((const byte*)KEY.data(), KEY.size());
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryptor(decryptor, (const byte*)"1234567890123456");
    // Decrypt the ciphertext
    std::string decryptedtext;
    CryptoPP::StringSource(ciphertext, true,
        new CryptoPP::StreamTransformationFilter(cbcDecryptor,
            new CryptoPP::StringSink(decryptedtext)
        )
    );

    std::cout << "Decrypted text: " << decryptedtext << std::endl;
    return;
}

