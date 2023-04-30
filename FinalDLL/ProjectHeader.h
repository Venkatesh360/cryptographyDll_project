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

