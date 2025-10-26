#ifndef CONFIG_H
#define CONFIG_H

#include <windows.h>
#include <string>
#include <random>

// Compile-time random seed
#define RANDOM_SEED __TIME__[7] + __TIME__[6] + __TIME__[4] + __TIME__[3] + __TIME__[1] + __TIME__[0]

// Obfuscated constants
#define OBFU_MZ 0x5A4D
#define OBFU_PE 0x4550

// Random function name generator
class NameObfuscator {
public:
    static std::string Generate(int length = 12) {
        static const char charset[] = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::string result;
        result.reserve(length);
        
        srand((unsigned)__TIME__[7] ^ GetTickCount());
        
        for (int i = 0; i < length; ++i) {
            result += charset[rand() % (sizeof(charset) - 1)];
        }
        return result;
    }
};

// XOR key obfuscation
#define XOR_KEY (0xAB ^ RANDOM_SEED)

// Encryption key stored obfuscated
static const unsigned char MASTER_KEY[] = {
    0x4D^0xAA, 0x79^0xBB, 0x53^0xCC, 0x65^0xDD,
    0x63^0xEE, 0x72^0xFF, 0x65^0x11, 0x74^0x22,
    0x4B^0x33, 0x65^0x44, 0x79^0x55, 0x31^0x66,
    0x32^0x77, 0x33^0x88, 0x21^0x99, 0x40^0xAA,
    0x23^0xBB, 0x24^0xCC, 0x25^0xDD, 0x5E^0xEE,
    0x26^0xFF, 0x2A^0x11, 0x28^0x22, 0x29^0x33,
    0x00
};

static std::string GetDecryptedKey() {
    std::string key;
    for (int i = 0; MASTER_KEY[i] != 0; i++) {
        key += (char)(MASTER_KEY[i] ^ (0xAA + (i % 6)));
    }
    return key;
}

#endif
