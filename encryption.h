#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <windows.h>
#include <wincrypt.h>
#include <vector>

#pragma comment(lib, "advapi32.lib")

class AES256 {
private:
    static bool DeriveKey(HCRYPTPROV hProv, const std::string& password, HCRYPTKEY* hKey) {
        HCRYPTHASH hHash = 0;
        
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
            return false;
            
        if (!CryptHashData(hHash, (BYTE*)password.c_str(), password.length(), 0)) {
            CryptDestroyHash(hHash);
            return false;
        }
        
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, CRYPT_EXPORTABLE, hKey)) {
            CryptDestroyHash(hHash);
            return false;
        }
        
        CryptDestroyHash(hHash);
        return true;
    }

public:
    static std::vector<BYTE> Encrypt(const std::vector<BYTE>& data, const std::string& key) {
        HCRYPTPROV hProv = 0;
        HCRYPTKEY hKey = 0;
        std::vector<BYTE> result;

        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            return result;

        if (!DeriveKey(hProv, key, &hKey)) {
            CryptReleaseContext(hProv, 0);
            return result;
        }

        // Add padding
        DWORD blockSize = 16;
        DWORD paddedSize = ((data.size() / blockSize) + 1) * blockSize;
        result.resize(paddedSize + sizeof(DWORD));
        
        // Store original size
        memcpy(result.data(), &data.size(), sizeof(DWORD));
        memcpy(result.data() + sizeof(DWORD), data.data(), data.size());
        
        DWORD encryptSize = paddedSize;
        if (!CryptEncrypt(hKey, 0, TRUE, 0, result.data() + sizeof(DWORD), &encryptSize, paddedSize)) {
            result.clear();
        } else {
            result.resize(encryptSize + sizeof(DWORD));
        }

        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return result;
    }

    static std::vector<BYTE> Decrypt(const std::vector<BYTE>& data, const std::string& key) {
        HCRYPTPROV hProv = 0;
        HCRYPTKEY hKey = 0;
        std::vector<BYTE> result;

        if (data.size() < sizeof(DWORD)) return result;

        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            return result;

        if (!DeriveKey(hProv, key, &hKey)) {
            CryptReleaseContext(hProv, 0);
            return result;
        }

        DWORD originalSize;
        memcpy(&originalSize, data.data(), sizeof(DWORD));
        
        std::vector<BYTE> encrypted(data.begin() + sizeof(DWORD), data.end());
        DWORD decryptSize = encrypted.size();
        
        if (CryptDecrypt(hKey, 0, TRUE, 0, encrypted.data(), &decryptSize)) {
            result.assign(encrypted.begin(), encrypted.begin() + originalSize);
        }

        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return result;
    }
};

// Multi-layer encryption
class MultiLayerEncryption {
public:
    static std::vector<BYTE> Encrypt(const std::vector<BYTE>& data, const std::string& key) {
        // Layer 1: XOR
        std::vector<BYTE> xored(data.size());
        for (size_t i = 0; i < data.size(); i++) {
            xored[i] = data[i] ^ key[i % key.length()];
        }
        
        // Layer 2: AES-256
        return AES256::Encrypt(xored, key);
    }
    
    static std::vector<BYTE> Decrypt(const std::vector<BYTE>& data, const std::string& key) {
        // Layer 1: AES-256
        std::vector<BYTE> decrypted = AES256::Decrypt(data, key);
        if (decrypted.empty()) return decrypted;
        
        // Layer 2: XOR
        for (size_t i = 0; i < decrypted.size(); i++) {
            decrypted[i] ^= key[i % key.length()];
        }
        
        return decrypted;
    }
};

#endif
