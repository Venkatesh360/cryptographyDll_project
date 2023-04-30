#include "pch.h"
#include "ProjectHeader.h"
#include <iostream>
#include <asn.h>
#include <base64.h>
#include <cryptlib.h>
#include <dsa.h>
#include <eccrypto.h>
#include <filters.h>
#include <files.h>
#include <hex.h>
#include <oids.h>
#include <osrng.h>
#include <rsa.h>
#include <string>
#include <secblock.h>
#include <vector>
#include <sha.h>


using namespace CryptoPP;
using namespace std;


void rsa_signature_signer(string public_key, string private_key, string message)
{
    //read public key data from file and assigning to KeyStrPublic
    ifstream file1(public_key);
    string keyStrPublic((istreambuf_iterator<char>(file1)), istreambuf_iterator<char>());

    //read private key data from file and assigning to KeyStrPrivate
    ifstream file2(private_key);
    string keyStrPrivate((istreambuf_iterator<char>(file2)), istreambuf_iterator<char>());


    // Set up the keys 
    RSA::PrivateKey privateKey;
    privateKey.Load(StringSource(keyStrPrivate, true).Ref());

    RSA::PublicKey publicKey;
    publicKey.Load(StringSource(keyStrPublic, true).Ref());

    // Generate the signature
    AutoSeededRandomPool rng;
    RSASSA_PKCS1v15_SHA_Signer signer(privateKey);
    string signature;
    StringSource(message, true, new SignerFilter(rng, signer, new StringSink(signature)));

    //create a encoder using  CryptoPP::Base64Encoder encoder
    Base64Encoder encoder;

    // Output the signature
    cout << "Signature: " << encoder.Put(reinterpret_cast<const unsigned char*>(signature.data()), signature.size()) << endl;

    //output the signature to a rsa_signature_output.txt
    ofstream myfile("rsa_signature_output.txt");
    if (myfile.is_open()) {
        myfile << signature; // write the string to the file
        myfile.close(); // close the file
        cout << "String saved to file." << endl;
    }
    else {
        cout << "Unable to open file." << endl;
    }

    // Verify the signature

}

void rsa_signature_verification(string public_key, string message) {
    ifstream file1(public_key);
    string keyStrPublic((istreambuf_iterator<char>(file1)), istreambuf_iterator<char>());

    ifstream file2(message);
    string signature((istreambuf_iterator<char>(file2)), istreambuf_iterator<char>());

    RSA::PublicKey publicKey;
    publicKey.Load(StringSource(keyStrPublic, true).Ref());

    //creating the verifier object using public key
    RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);

    bool result = false;
    StringSource(reinterpret_cast<const unsigned char*>(signature.data()), signature.size(), true, new SignatureVerificationFilter(verifier, new ArraySink((byte*)&result, sizeof(result))));

    // Output the verification result
    cout << "Verification result: " << (result ? "valid" : "invalid") << endl;

}

void ECDSA_fn(string message)
{
    // Generate a new ECDSA key pair
    AutoSeededRandomPool rng;
    CryptoPP::ECDSA<ECP, SHA256>::PrivateKey privateKey;
    privateKey.Initialize(rng, ASN1::secp256r1());

    CryptoPP::ECDSA<ECP, SHA256>::PublicKey publicKey;
    privateKey.MakePublicKey(publicKey);

    // Print the public key
    string publicKeyStr;
    publicKey.Save(StringSink(publicKeyStr).Ref());
    cout << "Public Key: " << publicKeyStr << endl;

    // Sign a message using the private key
    string signature;

    CryptoPP::ECDSA<ECP, SHA256>::Signer signer(privateKey);
    StringSource(message, true, new CryptoPP::SignerFilter(rng, signer, new StringSink(signature)));


    // Print the signature
    cout << "Signature: " << signature << std::endl;

    // Verify the signature using the public key

    return;
}

void ECDSA_verfier(string public_Key, string signature, string message) {
    //generate a public key instance
    CryptoPP::ECDSA<ECP, SHA256>::PublicKey publicKey;

    //loading data into publickey instance 
    ifstream file(public_Key);
    string keyStrPublic((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    publicKey.Load(StringSource(keyStrPublic, true).Ref());

    CryptoPP::ECDSA<ECP, SHA256>::Verifier verifier(publicKey);

    bool result = false;
    StringSource(signature + message, true, new SignatureVerificationFilter(verifier, new ArraySink(reinterpret_cast<byte*>(&result), sizeof(result))));

    if (result)
        cout << "Signature is valid." << std::endl;
    else
        cout << "Signature is invalid." << std::endl;

}

void dsa_2048(string message) {

    // Generate a DSA key pair
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::DSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 2048);

    CryptoPP::DSA::PublicKey publicKey;
    privateKey.MakePublicKey(publicKey);

    // Save the private key to a file
    CryptoPP::FileSink privateKeyFile("private.key");
    privateKey.DEREncode(privateKeyFile);

    // Save the public key to a file
    CryptoPP::FileSink publicKeyFile("public.key");
    publicKey.DEREncode(publicKeyFile);


    //signing the message
    string signature;
    DSA::Signer signer(privateKey);

    StringSource ss1(message, true,
        new SignerFilter(rng, signer,
            new StringSink(signature))
    );

    //verification of message
    DSA::Verifier verifier(publicKey);
    StringSource ss2(message + signature, true,
        new SignatureVerificationFilter(
            verifier, NULL, NULL
            /* SIGNATURE_AT_END */
        ));
    return;
}
/*
void rsa_signature_signer(  string public_key, string private_key, string message)
void rsa_signature_verification(string public_key, string message)
void ECDSA_fn(string message)
void ECDSA_verfier(string public_Key, string signature, string message)
void dsa_2048(string message)
*/