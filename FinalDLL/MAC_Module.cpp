#include "pch.h"
#include "ProjectHeader.h"
#include <iostream>
#include <string>
#include <stdexcept>
#include <hmac.h>
#include <sha.h>
#include <hex.h>
#include <aes.h>
#include <files.h>
#include <cmac.h>

using namespace CryptoPP;
using namespace std;

void hmac_sha256(string& message, string& key) {
    try {
        HMAC<SHA256> hmac(reinterpret_cast<const unsigned char*>(key.c_str()), key.length());
        string digest;
        StringSource ss(message, true, new HashFilter(hmac, new StringSink(digest)));
        cout<< digest;
    }
    catch (const exception& ex) {
        throw runtime_error("HMAC calculation failed: " + string(ex.what()));
        return;
    }
    return;
}

void aes128_cmacbyte(string message_str, string key_str)
{

    byte key[AES::DEFAULT_KEYLENGTH];
    byte message[AES::DEFAULT_KEYLENGTH];

    CryptoPP::SHA256().CalculateDigest(key, reinterpret_cast<const CryptoPP::byte*>(key_str.data()), key_str.length());
    CryptoPP::SHA256().CalculateDigest(message, reinterpret_cast<const CryptoPP::byte*>(message_str.data()), message_str.length());

    size_t messageLen = strlen((char*)message);
    byte mac[AES::BLOCKSIZE];

    // Create the CMAC object
    CMAC<AES> cmac(key, sizeof(key));

    // Calculate the MAC
    cmac.Update(message, messageLen);
    cmac.Final(mac);

    // Print the MAC
    cout << "MAC: ";
    StringSource(mac, sizeof(mac), true, new HexEncoder(new FileSink(cout)));
    cout << endl;

    return;
}