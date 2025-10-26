#include <windows.h>
#include <cstdio>
#include <vector>
#include <string>
#include "config.h"
#include "encryption.h"

// ensure BYTE is defined (uncomment if needed)
// typedef unsigned char BYTE;

int main(int argc, char* argv[]) {
    std::printf("========================================\n");
    std::printf("  Advanced Payload Encryption Tool\n");
    std::printf("========================================\n\n");

    if (argc != 3) {
        std::printf("Usage: %s <input_file> <output_file>\n", argv[0]);
        std::printf("Example: %s out.exe encrypted_payload.bin\n", argv[0]);
        return 1;
    }

    // Read input file
    FILE* fin = std::fopen(argv[1], "rb");
    if (!fin) {
        std::printf("[-] Cannot open input file: %s\n", argv[1]);
        return 1;
    }

    std::fseek(fin, 0, SEEK_END);
    long ftellSize = ftell(fin);
    if (ftellSize < 0) {
        std::printf("[-] ftell failed\n");
        std::fclose(fin);
        return 1;
    }
    size_t fileSize = static_cast<size_t>(ftellSize);
    std::fseek(fin, 0, SEEK_SET);

    std::vector<BYTE> fileData;
    fileData.resize(fileSize);

    if (fileSize > 0) {
        size_t read = std::fread(fileData.data(), 1, fileSize, fin);
        if (read != fileSize) {
            std::printf("[-] Read error: expected %llu bytes, got %llu bytes\n",
                        static_cast<unsigned long long>(fileSize),
                        static_cast<unsigned long long>(read));
            std::fclose(fin);
            return 1;
        }
    }
    std::fclose(fin);

    std::printf("[*] Loaded file: %llu bytes\n", static_cast<unsigned long long>(fileSize));

    // Get decryption key
    std::string key = GetDecryptedKey();
    std::printf("[*] Using obfuscated key\n");

    // Encrypt with multi-layer encryption
    std::printf("[*] Encrypting with AES-256 + XOR...\n");

    // Make sure Encrypt signature matches (example: returns vector<BYTE>)
    std::vector<BYTE> encrypted = MultiLayerEncryption::Encrypt(fileData, key);

    if (encrypted.empty()) {
        std::printf("[-] Encryption failed\n");
        return 1;
    }

    // Write output
    FILE* fout = std::fopen(argv[2], "wb");
    if (!fout) {
        std::printf("[-] Cannot create output file: %s\n", argv[2]);
        return 1;
    }

    size_t wrote = std::fwrite(encrypted.data(), 1, encrypted.size(), fout);
    std::fclose(fout);

    if (wrote != encrypted.size()) {
        std::printf("[-] Write error: wrote %llu of %llu bytes\n",
                    static_cast<unsigned long long>(wrote),
                    static_cast<unsigned long long>(encrypted.size()));
        return 1;
    }

    std::printf("[+] Successfully encrypted %llu bytes\n", static_cast<unsigned long long>(fileSize));
    std::printf("[+] Output: %llu bytes (with padding)\n", static_cast<unsigned long long>(encrypted.size()));
    std::printf("[+] Saved to: %s\n", argv[2]);

    return 0;
}
