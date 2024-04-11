# Cryptography Dll for C++

This is an easy-to-use DLL file made for educational purposes and to simplify working with cryptography algorithms. The Dll is divided into 5 modules, each containing algorithms for specific use.

## Module List

### DSA Module
- **RSA_Signature_signer**: Reads public and private keys from files, generates an RSA signature for the provided message using the private key, encodes the signature in Base64, outputs the signature to the console, and writes it to a file.
- **RSA_Signature_verification**: Reads a public key and a signature from files, verifies the signature using the public key, and outputs the verification result to the console.
- **ECDSA_signer**: Generates a new ECDSA key pair, prints the public key, signs a message using the private key, and prints the signature.
- **ECDSA_verifier**: Reads a public key and a signature from files, verifies the signature using the public key and the provided message, and outputs the verification result to the console.
- **dsa_2048**: Generates a DSA key pair with a 2048-bit key size, saves the private and public keys to files, signs a message using the private key, verifies the signature using the public key and the provided message.

### Key Management Module
- **PBKDF1**: The PBKDF1 key derivation function with the MD5 hash function takes a password and a salt as input, derives a 16-byte key using the PKCS#5 standard, encodes the key in hexadecimal, and prints it to the console.
- **PBKDF2**: The PBKDF2 key derivation function with the SHA-256 hash function takes a password and a salt as input, derives a 32-byte key using the PKCS#5 standard, encodes the key in hexadecimal, and prints it to the console.
- **RSA key generation**: Generates a 2048-bit RSA key pair using the Crypto++ library, and prints the components of the private and public keys to the console.
- **SCRYPT**: Implements the scrypt key derivation function, takes a password and a salt as input, derives a 32-byte key using the scrypt algorithm, encodes the key in hexadecimal, and prints it to the console.

### MAC Module
- **HMAC-SHA256**: A cryptographic hash function that uses a secret key to authenticate and verify a message's integrity, outputs the calculated HMAC-SHA256 digest.
- **AES128_cmac**: Calculates the CMAC using AES-128 encryption, and outputs the MAC as a hexadecimal string.

### Encryption and Decryption Module
- **AES128_GMC_encryptor**: Generates a random key and initialization vector (IV) using the AutoSeededRandomPool function from the Crypto++ library, sets up a GCM encryption object, encrypts the plaintext, and prints the ciphertext, key, and IV.
- **AES128_GMC_decryptor**: Decrypts the ciphertext using an authenticated decryption filter, and prints the decrypted text.
- **AES128_CBC_encryptor**: Generates a random key and IV, sets up a CBC encryption object, encrypts the plaintext, and prints the ciphertext, key, and IV.
- **AES128_CBC_decryptor**: Decrypts the ciphertext using a stream transformation filter, and prints the decrypted text.
- **AES128_CTR_encryptor**: Generates a random key and nonce, sets up a CTR encryption object, encrypts the plaintext, and prints the ciphertext, key, and nonce.
- **AES128_CTR_decryptor**: Decrypts the ciphertext using a stream transformation filter, and prints the decrypted text.
- **RSA_encryption**: Encrypts a plaintext message using RSA encryption with a provided public key, and outputs the resulting ciphertext in Base64 encoding.
- **RSA_decryption**: Decrypts a ciphertext message using RSA decryption with a provided private key, and outputs the resulting plaintext.
- **BLOWFISH_encryption**: Encrypts a plaintext message using Blowfish encryption, and outputs the resulting ciphertext in hexadecimal encoding.
- **BLOWFISH_decryption**: Decrypts a ciphertext message using Blowfish decryption, and outputs the resulting plaintext.
- **TWOFISH_encryptor**: Encrypts a plaintext message using Twofish encryption, and outputs the resulting ciphertext.
- **TWOFISH_decryptor**: Decrypts a ciphertext message using Twofish decryption, and outputs the resulting plaintext.

### Hashing Module
- **SHA_256_Hashing function**: Performs SHA-3 256-bit hashing on a string message, and prints the hashed value in hexadecimal format.
- **SHA_512_Hashing function**: Performs SHA-512 hashing on a string message, and prints the hashed value in hexadecimal format.


# Header File
```
#pragma once
#ifdef FINALDLL_EXPORTS
#define FINAL_API __declspec(dllexport)
#else
#define FINAL_API __declspec(dllimport)
#endif 
#include<string>
#include<iostream>
using namespace std;

//MACs Module

FINAL_API  void  hmac_sha256(std::string& message, std::string& key);
FINAL_API  void aes128_cmacbyte(std::string message_str, std::string key_str);

//Key Management Module
FINAL_API  void PBKDF1(std::string password, std::string salt);
FINAL_API  void PBKDF2(std::string password, std::string salt);
FINAL_API  void scrypt(std::string password, std::string salt);
FINAL_API  void rsa_key_generation();

//Digital Signature Module
FINAL_API  void rsa_signature_signer(std::string public_key, std::string private_key, std::string message);
FINAL_API  void rsa_signature_verification(std::string public_key, std::string message);
FINAL_API  void ECDSA_fn(std::string message);
FINAL_API  void ECDSA_verfier(std::string public_Key, std::string signature, std::string message);
FINAL_API  void dsa_2048(std::string message);

//Encription Decryption Module
FINAL_API  void aes128_gmc_encryption(std::string plaintext);
FINAL_API  void aes128_gcm_decryption(std::string ciphertext, std::string KEY, std::string IV);
FINAL_API  void aes128_cbc_encryption(std::string plaintext);
FINAL_API  void aes_cbc_decryptor(std::string ciphertext, std::string KEY, std::string IV);
FINAL_API  void aes128_ctr_encription(std::string plaintext);
FINAL_API  void rsa_encryption(std::string Public_Key);
FINAL_API  void rsa_decreption(std::string Private_Key);
FINAL_API  void BlowFish_encyription(std::string plaintext, std::string key);
FINAL_API  void BlowFish_decryption(std::string ciphertext, std::string key);
FINAL_API  void twofish_encryptor(std::string plaintext, std::string key);
FINAL_API  void twofish_decryptor(std::string ciphertext, std::string KEY);

//Hashing Module
FINAL_API  void sha_256_Hashing(std::string message);
FINAL_API  void sha_512_Hashing(std::string message);
```
