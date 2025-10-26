#ifndef DOTNET_LOADER_H
#define DOTNET_LOADER_H

#include <windows.h>
#include <metahost.h>
#include <stdio.h>

#pragma comment(lib, "mscoree.lib")

#import "mscorlib.tlb" raw_interfaces_only high_property_prefixes("_get","_put","_putref") rename("ReportEvent", "InteropServices_ReportEvent")

using namespace mscorlib;

class DotNetLoader {
private:
    ICLRMetaHost* pMetaHost;
    ICLRRuntimeInfo* pRuntimeInfo;
    ICLRRuntimeHost* pRuntimeHost;
    
public:
    DotNetLoader() : pMetaHost(NULL), pRuntimeInfo(NULL), pRuntimeHost(NULL) {}
    
    ~DotNetLoader() {
        if (pRuntimeHost) pRuntimeHost->Release();
        if (pRuntimeInfo) pRuntimeInfo->Release();
        if (pMetaHost) pMetaHost->Release();
    }
    
    bool Initialize() {
        HRESULT hr;
        
        // Get CLR MetaHost
        hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
        if (FAILED(hr)) {
            printf("[-] CLRCreateInstance failed: 0x%X\n", hr);
            return false;
        }
        
        // Get .NET runtime (v4.0.30319)
        hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
        if (FAILED(hr)) {
            printf("[-] GetRuntime failed: 0x%X\n", hr);
            return false;
        }
        
        // Check if runtime is loadable
        BOOL loadable;
        hr = pRuntimeInfo->IsLoadable(&loadable);
        if (FAILED(hr) || !loadable) {
            printf("[-] Runtime not loadable\n");
            return false;
        }
        
        // Get runtime host
        hr = pRuntimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (LPVOID*)&pRuntimeHost);
        if (FAILED(hr)) {
            printf("[-] GetInterface failed: 0x%X\n", hr);
            return false;
        }
        
        // Start runtime
        hr = pRuntimeHost->Start();
        if (FAILED(hr)) {
            printf("[-] Start failed: 0x%X\n", hr);
            return false;
        }
        
        printf("[+] .NET CLR initialized successfully\n");
        return true;
    }
    
    bool ExecuteAssembly(const BYTE* assemblyData, DWORD assemblySize, const wchar_t* args = L"") {
        if (!pRuntimeHost) {
            printf("[-] Runtime not initialized\n");
            return false;
        }
        
        HRESULT hr;
        DWORD retVal;
        
        // Create safe array for assembly bytes
        SAFEARRAYBOUND bounds[1];
        bounds[0].cElements = assemblySize;
        bounds[0].lLbound = 0;
        
        SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, bounds);
        if (!pSafeArray) {
            printf("[-] SafeArrayCreate failed\n");
            return false;
        }
        
        // Copy assembly data
        void* pData;
        hr = SafeArrayAccessData(pSafeArray, &pData);
        if (FAILED(hr)) {
            SafeArrayDestroy(pSafeArray);
            return false;
        }
        
        memcpy(pData, assemblyData, assemblySize);
        SafeArrayUnaccessData(pSafeArray);
        
        // Load and execute assembly
        IUnknown* pUnk = NULL;
        hr = pRuntimeHost->ExecuteInDefaultAppDomain(
            L"",  // No path, loading from memory
            L"",  // Type name (will use entry point)
            L"",  // Method name
            args, // Arguments
            &retVal
        );
        
        // Alternative method: Use AppDomain to load assembly from memory
        ICorRuntimeHost* pCorRuntimeHost = NULL;
        hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&pCorRuntimeHost);
        if (SUCCEEDED(hr)) {
            IUnknown* pAppDomainUnk = NULL;
            hr = pCorRuntimeHost->GetDefaultDomain(&pAppDomainUnk);
            
            if (SUCCEEDED(hr)) {
                _AppDomain* pAppDomain = NULL;
                hr = pAppDomainUnk->QueryInterface(__uuidof(_AppDomain), (VOID**)&pAppDomain);
                
                if (SUCCEEDED(hr)) {
                    _Assembly* pAssembly = NULL;
                    hr = pAppDomain->Load_3(pSafeArray, &pAssembly);
                    
                    if (SUCCEEDED(hr)) {
                        printf("[+] Assembly loaded successfully\n");
                        
                        _MethodInfo* pMethodInfo = NULL;
                        hr = pAssembly->get_EntryPoint(&pMethodInfo);
                        
                        if (SUCCEEDED(hr) && pMethodInfo) {
                            VARIANT retval;
                            SAFEARRAY* pParams = SafeArrayCreateVector(VT_VARIANT, 0, 0);
                            
                            hr = pMethodInfo->Invoke_3(VARIANT(), pParams, &retval);
                            
                            if (SUCCEEDED(hr)) {
                                printf("[+] Assembly executed successfully\n");
                            }
                            
                            SafeArrayDestroy(pParams);
                            pMethodInfo->Release();
                        }
                        
                        pAssembly->Release();
                    }
                    
                    pAppDomain->Release();
                }
                
                pAppDomainUnk->Release();
            }
            
            pCorRuntimeHost->Release();
        }
        
        SafeArrayDestroy(pSafeArray);
        return SUCCEEDED(hr);
    }
};

#endif
