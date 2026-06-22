// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <Windows.h>
#include <iostream>
#include <string>
#include <iomanip>
#include <vector>
#include "version.hpp"

namespace Core {

    class Console {
    public:
        explicit Console(bool verbose) : m_verbose(verbose) {
            m_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            GetConsoleScreenBufferInfo(m_hConsole, &csbi);
            m_origAttrs = csbi.wAttributes;
            SetConsoleOutputCP(CP_UTF8);
        }

        ~Console() {
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
        }

        // Standard log messages (for syscall init, errors, etc - outside browser box)
        void Info(const std::string& msg) const {
          
        }
        void Success(const std::string& msg) const {
            
        }
        void Error(const std::string& msg) const {
            
        }
        void Warn(const std::string& msg) const {
            
        }

        // Debug messages - inside the browser box, connected to tree
        void Debug(const std::string& msg) const {
            if (m_verbose) {
                SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                std::cout << std::endl;
                SetConsoleTextAttribute(m_hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                std::cout << std::endl;
                SetConsoleTextAttribute(m_hConsole, m_origAttrs);
            }
        }

        // Browser section header with box drawing
        void BrowserHeader(const std::string& name, const std::string& version = "") const {
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << std::endl;

            size_t contentLen = name.length();
            if (!version.empty()) {
                SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                std::cout << std::endl;
                SetConsoleTextAttribute(m_hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::cout << std::endl;
                SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                std::cout << std::endl;
                contentLen += 3 + version.length();
            }

            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            const size_t totalWidth = 50;
            const size_t prefixLen = 7;  // "  ┌──── "
            size_t dashCount = (totalWidth > prefixLen + contentLen + 1) ? (totalWidth - prefixLen - contentLen - 1) : 4;
            std::cout << std::endl;
            for (size_t i = 0; i < dashCount; ++i) std::cout << "─";
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
        }

        // No ABE warning (within browser box)
        void NoAbeWarning(const std::string& msg) const {
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
        }

        // ABE Key display
        void KeyDecrypted(const std::string& keyHex) const {
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
        }

        // Copilot ABE Key display (Edge only)
        void AsterKeyDecrypted(const std::string& keyHex) const {
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
        }

        // Profile section header
        void ProfileHeader(const std::string& name) const {
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
        }

        // Verbose data row (only shown in verbose mode)
        void DataRow(const std::string& key, const std::string& value) const {
            if (m_verbose) {
                SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                std::cout << std::endl;
                SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                std::cout << std::endl;
                SetConsoleTextAttribute(m_hConsole, m_origAttrs);
            }
        }

        // Extraction result (always shown)
        void ExtractionResult(const std::string& type, int count, int total = -1) const {
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << std::endl;
            if (total > 0 && total != count) {
                SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                std::cout << std::endl;
            }
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
        }

        // Summary line
        void Summary(int cookies, int passwords, int cards, int ibans, int tokens, int profiles, const std::string& outputPath) const {
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);

            std::vector<std::string> parts;
            if (cookies > 0) parts.push_back(std::to_string(cookies) + " cookies");
            if (passwords > 0) parts.push_back(std::to_string(passwords) + " passwords");
            if (cards > 0) parts.push_back(std::to_string(cards) + " cards");
            if (ibans > 0) parts.push_back(std::to_string(ibans) + " IBANs");
            if (tokens > 0) parts.push_back(std::to_string(tokens) + " tokens");

            for (size_t i = 0; i < parts.size(); i++) {
                std::cout << parts[i];
                if (i < parts.size() - 1) std::cout << ", ";
            }

            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
        }

        void Banner() const {
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
          
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
        }

        bool IsVerbose() const { return m_verbose; }

    private:
        void Print(const std::string& tag, const std::string& msg, WORD color) const {
            SetConsoleTextAttribute(m_hConsole, color);
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
            std::cout << std::endl;
        }

        HANDLE m_hConsole;
        WORD m_origAttrs;
        bool m_verbose;
    };

}
