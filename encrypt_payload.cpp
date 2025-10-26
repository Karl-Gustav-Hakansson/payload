#include <windows.h>
#include <stdio.h>
#include <vector>
#include "config.h"
#include "encryption.h"

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("  Advanced Payload Encryption Tool\n");
    printf("========================================\n\n");
    
    if (argc != 3) {
        printf("Usage: %s <input_file> <output_file>\n", argv[0]);
        printf("Example: %s out.exe encrypted_payload.bin\n", argv[0]);
        return 1;
    }
    
    // Read input file
    FILE* fin = fopen(argv[1], "rb");
    if (!fin) {
        printf("[-] Cannot open input file: %s\n", argv[1]);
        return 1;
    }
    
    fseek(fin, 0, SEEK_END);
    size_t fileSize = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    
    std::vector<BYTE> fileData(fileSize);
    fread(fileData.data(), 1, fileSize, fin);
    fclose(fin);
    
    printf("[*] Loaded file: %zu bytes\n", fileSize);
    
    // Get decryption key
    std::string key = GetDecryptedKey();
    printf("[*] Using obfuscated key\n");
    
    // Encrypt with multi-layer encryption
    printf("[*] Encrypting with AES-256 + XOR...\n");
    std::vector<BYTE> encrypted = MultiLayerEncryption::Encrypt(fileData, key);
    
    if (encrypted.empty()) {
        printf("[-] Encryption failed\n");
        return 1;
    }
    
    // Write output
    FILE* fout = fopen(argv[2], "wb");
    if (!fout) {
        printf("[-] Cannot create output file: %s\n", argv[2]);
        return 1;
    }
    
    fwrite(encrypted.data(), 1, encrypted.size(), fout);
    fclose(fout);
    
    printf("[+] Successfully encrypted %zu bytes\n", fileSize);
    printf("[+] Output: %zu bytes (with padding)\n", encrypted.size());
    printf("[+] Saved to: %s\n", argv[2]);
    
    return 0;
}
