// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include <Windows.h>
#include <string>
#include "../core/common.hpp"
#include "pipe_client.hpp"
#include <sstream>
#include <fstream>
#include <cstring>

namespace Payload {

    static void DebugLog(const std::string& msg) { (void)msg; }

    PipeClient::PipeClient(const std::wstring& pipeName) : m_hPipe(INVALID_HANDLE_VALUE) {
        int retries = 15;
        int retryDelayMs = 100;

        while (retries > 0 && m_hPipe == INVALID_HANDLE_VALUE) {
            m_hPipe = CreateFileW(
                pipeName.c_str(),
                GENERIC_WRITE | GENERIC_READ,
                0,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr
            );

            if (m_hPipe == INVALID_HANDLE_VALUE) {
                retries--;
                if (retries > 0) {
                    Sleep(retryDelayMs);
                    retryDelayMs += 50;
                }
            }
        }
    }

    PipeClient::~PipeClient() {
        if (IsValid()) {
            try {
                Log("__DLL_PIPE_COMPLETION_SIGNAL__");
                Flush();
                Sleep(500);
                CloseHandle(m_hPipe);
                m_hPipe = INVALID_HANDLE_VALUE;
            }
            catch (...) {}
        }
    }

    void PipeClient::Log(const std::string& msg) {
        if (!IsValid()) return;

        DWORD written = 0;
        WriteFile(
            m_hPipe,
            msg.c_str(),
            static_cast<DWORD>(msg.length() + 1),
            &written,
            nullptr
        );
        FlushFileBuffers(m_hPipe);
    }

    void PipeClient::LogDebug(const std::string& msg) { (void)msg; }

    void PipeClient::LogData(const std::string& key, const std::string& value) {
        (void)key;
        (void)value;
    }

    void PipeClient::Flush() {
        if (IsValid())
            FlushFileBuffers(m_hPipe);
    }

    PipeClient::Config PipeClient::ReadConfig() {
        Config config{};
        config.verbose = false;
        config.fingerprint = false;
        config.outputPath = "";
        config.browserType = "";
        config.browserVersion = "";

        if (!IsValid()) return config;

        // Signal injector we are ready to receive config
        Log("READY");

        char  buffer[4096] = { 0 };
        DWORD read = 0;

        // Read verbose flag
        ZeroMemory(buffer, sizeof(buffer));
        if (ReadFile(m_hPipe, buffer, sizeof(buffer) - 1, &read, nullptr) && read > 0)
            buffer[read] = '\0';

        // Read fingerprint flag
        ZeroMemory(buffer, sizeof(buffer));
        if (ReadFile(m_hPipe, buffer, sizeof(buffer) - 1, &read, nullptr) && read > 0)
            buffer[read] = '\0';

        // Read output path
        ZeroMemory(buffer, sizeof(buffer));
        if (ReadFile(m_hPipe, buffer, sizeof(buffer) - 1, &read, nullptr) && read > 0) {
            buffer[read] = '\0';
            config.outputPath = buffer;
        }

        // Read browser type
        ZeroMemory(buffer, sizeof(buffer));
        if (ReadFile(m_hPipe, buffer, sizeof(buffer) - 1, &read, nullptr) && read > 0) {
            buffer[read] = '\0';
            config.browserType = buffer;
        }

        // Read browser version
        ZeroMemory(buffer, sizeof(buffer));
        if (ReadFile(m_hPipe, buffer, sizeof(buffer) - 1, &read, nullptr) && read > 0) {
            buffer[read] = '\0';
            config.browserVersion = buffer;
        }

        // Acknowledge config received
        Log("CONFIG_RECEIVED");

        return config;
    }

} // namespace Payload