#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include <windows.h>
#include <string>

// Compile-time string encryption
template<int X>
struct StringEncryptor
{
    constexpr StringEncryptor(const char* str) : key(X), encrypted() {
        for (int i = 0; i < 256 && str[i]; ++i) {
            encrypted[i] = str[i] ^ key;
        }
    }
    
    std::string decrypt() const {
        std::string result;
        for (int i = 0; i < 256 && encrypted[i]; ++i) {
            result += encrypted[i] ^ key;
        }
        return result;
    }
    
    char encrypted[256];
    int key;
};

#define OBFUSCATE(str) (StringEncryptor<__COUNTER__>(str).decrypt())

// API resolution by hash
class APIObfuscator {
private:
    static DWORD HashAPI(const char* str) {
        DWORD hash = 0x35;
        while (*str) {
            hash = ((hash << 5) + hash) + tolower(*str++);
        }
        return hash;
    }
    
public:
    static FARPROC GetAPI(HMODULE hModule, DWORD hash) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + 
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        
        DWORD* names = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
        WORD* ordinals = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);
        DWORD* functions = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);
        
        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            char* funcName = (char*)hModule + names[i];
            if (HashAPI(funcName) == hash) {
                return (FARPROC)((BYTE*)hModule + functions[ordinals[i]]);
            }
        }
        
        return NULL;
    }
    
    // Pre-computed hashes for common APIs
    enum APIHash {
        HASH_LoadLibraryA       = 0xEC0E4E8E,
        HASH_GetProcAddress     = 0x7C0DFCAA,
        HASH_VirtualAlloc       = 0x91AFCA54,
        HASH_VirtualProtect     = 0xE553A458,
        HASH_CreateThread       = 0x7C0DA2A7,
        HASH_WaitForSingleObject= 0x8C0DA2B7,
        HASH_ExitProcess        = 0x7C0D2A47
    };
};

// Stack string obfuscation
#define STACK_STRING(var, str) \
    char var[sizeof(str)]; \
    for (int i = 0; i < sizeof(str); i++) { \
        var[i] = str[i] ^ 0xAA; \
    } \
    for (int i = 0; i < sizeof(str); i++) { \
        var[i] ^= 0xAA; \
    }

#endif
