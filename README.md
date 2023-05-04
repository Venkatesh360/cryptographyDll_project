# Cryptography Dll for C++
This a easy to use Dll file made for education purposes and to simplify working with cryptography algorithms.
the Dll is divided into 5 module, each module contains algorithms for specific use.

## Module List
* [DSA Module](https://github.com/Venkatesh360/FinalDLL/new/master?readme=1#dsa-module)
* [Key Management Module](https://github.com/Venkatesh360/FinalDLL/new/master?readme=1#key-management-module)
* [MAC Module](https://github.com/Venkatesh360/FinalDLL/new/master?readme=1#mac-module)
* [Encryption and Decryption Module](https://github.com/Venkatesh360/FinalDLL/new/master?readme=1#encryption-and-decryption-module)
* [Hashing Module](https://github.com/Venkatesh360/FinalDLL/new/master?readme=1#hashing-module)


 ## DSA Module
#### RSA_Signature_signer

The function reads public and private keys from files, generates an RSA signature for the provided message using the private key,
encodes the signature in Base64, outputs the signature to console and writes it to a file.

#### RSA_Signature_verification

The function reads a public key and a signature from files, verifies the signature using the public key, and outputs the verification result to console.

#### ECDSA_signer

The function generates a new ECDSA key pair, prints the public key, signs a message using the private key, and prints the signature.

#### ECDSA_verifier

The function reads a public key and a signature from files, verifies the signature using the public key and the provided message, and outputs the verification result to console.

#### dsa_2048

The  function generates a DSA key pair with a 2048-bit key size, saves the private and public keys to files, signs a message using the private key, verifies the signature using the public key and
the provided message.

 ## Key Management Module
 #### PBKDF1 
 The PBKDF1 key derivation function with the MD5 hash function takes a password and a salt as input, and uses the PKCS#5 standard to derive a 16-byte key.
 The function then encodes the key in hexadecimal and prints it to the console.

#### PBKDF2
The PBKDF2 key derivation function with the SHA-256 hash function takes a password and a salt as input, and uses the PKCS#5 standard to derive a 32-byte key. 
The function then encodes the key in hexadecimal and prints it to the console.

#### RSA key generation
The function generates a 2048-bit RSA key pair using the Crypto++ library. The function uses an auto-seeded random number generator to generate a private key, and then derives the corresponding public key. The function prints the components of the private and public keys to the console.

#### SCRYPT
The function that implements the scrypt key derivation function. The function takes a password and a salt as input, and uses the scrypt algorithm to derive a 32-byte key. 
The function then encodes the key in hexadecimal and prints it to the console.



 ## MAC Module
 #### HMAC-SHA256
This is a cryptographic hash function that uses a secret key to authenticate and verify a message's integrity. The input message and key are passed as parameters, 
and the function outputs the calculated HMAC-SHA256 digest.

#### AES128_cmac
The takes in a message and a key as strings and calculates the CMAC using AES-128 encryption.
First, the function uses SHA256 to generate a 256-bit key from the input key string. Then, it generates a 128-bit message by using SHA256 on the input message string.
Next, it creates a CMAC object using the AES-128 algorithm and the generated key. The function updates the CMAC object with the message and finalizes the MAC. Finally, it prints the MAC as a hexadecimal string.

## Encryption and Decryption Module
 
#### AES128_GMC_encryptor
This function generates a random key and initialization vector (IV) using the AutoSeededRandomPool function from Crypto++ library. It then sets up a GCM encryption object with the key and IV, encrypts the plaintext using an authenticated encryption filter, and prints the ciphertext, key, and IV.

#### AES128_GMC_decryptor
This function takes a ciphertext, key, and IV as input. It first converts the key and IV from string format to binary format using a SHA256 hash function.
It then sets up a GCM decryption object with the key and IV, decrypts the ciphertext using an authenticated decryption filter, and prints the decrypted text.

#### AES128_CBC_encryptor
This function generates a random key using the AutoSeededRandomPool function from Crypto++ library and a random initialization vector (IV) using the same function. It then sets up a CBC encryption object with the key and IV, encrypts the plaintext using a stream transformation filter, and prints the ciphertext, key, and IV.

#### AES128_CBC_decryptor
This function takes a ciphertext, key, and IV as input. It first converts the key and IV from string format to binary format using an array sink. It then sets up a CBC decryption object with the key and IV, decrypts the ciphertext using a stream transformation filter, and prints the decrypted text.

#### AES128_CTR_encryptor
This function generates a random key and nonce using the AutoSeededRandomPool function from Crypto++ library. It then sets up a CTR encryption object with the key and nonce, encrypts the plaintext using a stream transformation filter, and prints the ciphertext, key, and nonce.

#### AES128_CTR_decryptor
This function takes a ciphertext, key, and nonce as input. It first converts the key and nonce from string format to binary format using an array sink. It then sets up a CTR decryption object with the key and nonce, decrypts the ciphertext using a stream transformation filter, and prints the decrypted text.

#### RSA_encryption
This function takes in a public key file as input, sets up a plaintext message, encrypts the message using RSA encryption with the provided public key, and outputs the resulting ciphertext in Base64 encoding.

#### RSA_decryption
This function takes in a private key file as input, sets up a ciphertext message (which should be in Base64 encoding), decrypts the message using RSA decryption with the provided private key, and outputs the resulting plaintext.

#### BLOWFISH_encryption
This function takes in a plaintext message and a key, sets up a Blowfish encryption object with the provided key, encrypts the plaintext message using the object in CBC mode, and outputs the resulting ciphertext in hexadecimal encoding.

#### BLOWFISH_decryption
This function takes in a ciphertext message (in hexadecimal encoding) and a key, sets up a Blowfish decryption object with the provided key, decrypts the ciphertext message using the object in CBC mode, and outputs the resulting plaintext.

#### TWOFISH_encryptor
This function takes in a plaintext message and a key, sets up a Twofish encryption object with the provided key, encrypts the plaintext message using the object in CBC mode with a fixed initialization vector, and outputs the resulting ciphertext.

#### TWOFISH_decryptor
This function takes in a ciphertext message and a key, sets up a Twofish decryption object with the provided key, decrypts the ciphertext message using the object in CBC mode with the same fixed initialization vector, and outputs the resulting plaintext.

## Hashing Module
#### SHA_256_Hashing function

This function takes a string message as input and performs SHA-3 256-bit hashing on it.
It uses the SHA3_256 class from a cryptographic library to perform the hashing.
The hashed value is stored in a byte array digest.
The function then prints the hashed value in hexadecimal format to the console.
Any exceptions that may occur during the hashing process are handled by catching them and printing an error message.

#### SHA_512_Hashing function:

This function takes a string message as input and performs SHA-512 hashing on it.
It uses the SHA512 class from a cryptographic library to perform the hashing.
The hashed value is stored in a byte array digest.
The function then prints the hashed value in hexadecimal format to the console.
Any exceptions that may occur during the hashing process are handled by catching them and printing an error message.
