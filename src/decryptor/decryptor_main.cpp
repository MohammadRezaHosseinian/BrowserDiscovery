// decryptor_main.cpp
// Streaming per-entry output + fully correct UTF-8 sanitizer
// Compatible with Windows 7 SP1 x64 / ARM64 and above.
//
// Key portability decisions:
//   - NO std::filesystem  →  uses Win32 CreateFileW/GetFileAttributesW directly.
//     std::filesystem in MSVC's STL calls CreateFile2 (Win8+), which is the
//     root cause of the "entry point not found" crash on Win7 VPS targets.
//   - _WIN32_WINNT / WINVER locked to 0x0601 here AND enforced via a
//     static_assert on NTDDI_VERSION so a mis-configured PCH can't silently
//     upgrade the target.
//   - /MT + libvcruntime.lib + libucrt.lib in the link step (see make.bat)
//     gives a fully self-contained binary with no VC redist dependency.
//   - BCrypt and Crypt32 are present on Win7 SP1; no newer APIs are used.

// These must come before any Windows header.
#undef  _WIN32_WINNT
#undef  WINVER
#undef  NTDDI_VERSION
#define _WIN32_WINNT  0x0601   
#define WINVER        0x0601
#define NTDDI_VERSION 0x06010000

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <nlohmann/json.hpp>

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <map>
#include <optional>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

static_assert(NTDDI_VERSION <= 0x06020000,
    "A header raised _WIN32_WINNT above Win8. "
    "This binary will fail on Win7 targets with 'CreateFile2 not found'.");

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

using json = nlohmann::json;

static void Log(const std::string& msg) {
    static std::ofstream logFile("decryptor_debug.log", std::ios::app);
    if (logFile.is_open()) {
        logFile << msg << "\n";
        logFile.flush();
    }
    std::cout << msg << "\n";
}

static bool PathExists(const std::wstring& path) {
    return ::GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

static bool IsFile(const std::wstring& path) {
    DWORD attr = ::GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) &&
        !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static ULONGLONG FileSize(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA info;
    if (!::GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &info))
        return 0;
    ULARGE_INTEGER uli;
    uli.HighPart = info.nFileSizeHigh;
    uli.LowPart = info.nFileSizeLow;
    return uli.QuadPart;
}

static std::wstring ParentDir(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return L".";
    return path.substr(0, pos);
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int len = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len <= 0) return {};
    std::wstring w(static_cast<size_t>(len - 1), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], len);
    return w;
}

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int len = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1,
        nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string s(static_cast<size_t>(len - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], len,
        nullptr, nullptr);
    return s;
}

static bool AtomicRename(const std::wstring& src, const std::wstring& dst) {
    return ::MoveFileExW(src.c_str(), dst.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}

static std::vector<uint8_t> FromBase64(const std::string& b64) {
    if (b64.empty()) return {};
    DWORD size = 0;
    if (!::CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64,
        nullptr, &size, nullptr, nullptr))
        return {};
    std::vector<uint8_t> data(size);
    if (!::CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64,
        data.data(), &size, nullptr, nullptr))
        return {};
    return data;
}

static std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.length() % 2 != 0) return bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        char buf[3] = { hex[i], hex[i + 1], '\0' };
        char* end = nullptr;
        long val = strtol(buf, &end, 16);
        if (*end != '\0') return {};
        bytes.push_back(static_cast<uint8_t>(val));
    }
    return bytes;
}

static std::optional<std::vector<uint8_t>> AesGcmDecrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& encryptedData)
{
    constexpr size_t PREFIX_LEN = 3;
    constexpr size_t IV_LEN = 12;
    constexpr size_t TAG_LEN = 16;
    constexpr size_t OVERHEAD = PREFIX_LEN + IV_LEN + TAG_LEN;

    if (encryptedData.size() < OVERHEAD)                          return std::nullopt;
    if (memcmp(encryptedData.data(), "v20", PREFIX_LEN) != 0)     return std::nullopt;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) return std::nullopt;
    auto algCloser = [](BCRYPT_ALG_HANDLE h) { if (h) BCryptCloseAlgorithmProvider(h, 0); };
    std::unique_ptr<void, decltype(algCloser)> algGuard(hAlg, algCloser);

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(status)) return std::nullopt;

    BCRYPT_KEY_HANDLE hKey = nullptr;
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (PUCHAR)key.data(), (ULONG)key.size(), 0);
    if (!NT_SUCCESS(status)) return std::nullopt;
    auto keyCloser = [](BCRYPT_KEY_HANDLE h) { if (h) BCryptDestroyKey(h); };
    std::unique_ptr<void, decltype(keyCloser)> keyGuard(hKey, keyCloser);

    const uint8_t* iv = encryptedData.data() + PREFIX_LEN;
    const uint8_t* tag = encryptedData.data() + (encryptedData.size() - TAG_LEN);
    const uint8_t* ct = iv + IV_LEN;
    ULONG ctLen = static_cast<ULONG>(encryptedData.size() - OVERHEAD);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv;
    authInfo.cbNonce = IV_LEN;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = TAG_LEN;

    std::vector<uint8_t> plain(ctLen > 0 ? ctLen : 1);
    ULONG outLen = 0;
    status = BCryptDecrypt(hKey, (PUCHAR)ct, ctLen, &authInfo,
        nullptr, 0, plain.data(), (ULONG)plain.size(),
        &outLen, 0);
    if (!NT_SUCCESS(status)) return std::nullopt;

    plain.resize(outLen);
    return plain;
}

static std::string ToUtf8Safe(const std::vector<uint8_t>& data) {
    static const char REPL[] = "\xEF\xBF\xBD";  

    std::string result;
    result.reserve(data.size());
    const uint8_t* b = data.data();
    const size_t   n = data.size();
    size_t i = 0;

    auto emit_repl = [&] { result += REPL; };
    auto cont = [&](size_t off) -> bool {
        return (i + off < n) && ((b[i + off] & 0xC0) == 0x80);
        };

    while (i < n) {
        uint8_t c = b[i];

        if (c < 0x80) { result.push_back((char)c); ++i; continue; }

        if (c < 0xC0) { emit_repl(); ++i; continue; }

        if (c < 0xE0) {
            if (c < 0xC2) { emit_repl(); ++i; continue; }  
            if (!cont(1)) { emit_repl(); ++i; continue; }
            result.push_back((char)c);
            result.push_back((char)b[i + 1]);
            i += 2; continue;
        }

        if (c < 0xF0) {
            if (!cont(1) || !cont(2)) { emit_repl(); ++i; continue; }
            uint8_t c1 = b[i + 1];
            if (c == 0xE0 && c1 < 0xA0) { emit_repl(); ++i; continue; }  
            if (c == 0xED && c1 >= 0xA0) { emit_repl(); ++i; continue; } 
            result.push_back((char)c);
            result.push_back((char)c1);
            result.push_back((char)b[i + 2]);
            i += 3; continue;
        }

        if (c < 0xF8) {
            if (c > 0xF4) { emit_repl(); ++i; continue; }  // > U+10FFFF
            if (!cont(1) || !cont(2) || !cont(3)) { emit_repl(); ++i; continue; }
            uint8_t c1 = b[i + 1];
            if (c == 0xF0 && c1 < 0x90) { emit_repl(); ++i; continue; }  
            if (c == 0xF4 && c1 > 0x8F) { emit_repl(); ++i; continue; }  
            result.push_back((char)c);
            result.push_back((char)c1);
            result.push_back((char)b[i + 2]);
            result.push_back((char)b[i + 3]);
            i += 4; continue;
        }

        emit_repl(); ++i;
    }
    return result;
}

class StreamingJsonWriter {
public:
    explicit StreamingJsonWriter(const std::wstring& finalPath)
        : finalPath_(finalPath), tempPath_(finalPath + L".tmp") {
    }

    bool Open(const json& browsers) {
        hFile_ = ::CreateFileW(
            tempPath_.c_str(),
            GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile_ == INVALID_HANDLE_VALUE) return false;

        std::string head = "{\n";
        if (!browsers.is_null()) {
            head += "    \"browsers\": ";
            head += browsers.dump(4);
            head += ",\n";
        }
        head += "    \"entries\": [\n";
        return Write(head);
    }

    bool WriteEntry(const json& entry) {
        std::string serialized;
        try {
            serialized = entry.dump(8);
        }
        catch (const std::exception& e) {
            Log(std::string("  [!] Entry serialization skipped: ") + e.what());
            return true;  
        }

        std::string fragment;
        if (!firstEntry_) fragment = ",\n";
        fragment += serialized;
        firstEntry_ = false;

        return Write(fragment);
    }

    bool Close(int total, int succeeded, int failed) {
        std::ostringstream footer;
        footer << "\n    ],\n"
            << "    \"summary\": {\n"
            << "        \"total_entries\": " << total << ",\n"
            << "        \"decrypted_ok\": " << succeeded << ",\n"
            << "        \"failed\": " << failed << "\n"
            << "    }\n"
            << "}\n";

        if (!Write(footer.str())) return false;

        ::FlushFileBuffers(hFile_);
        ::CloseHandle(hFile_);
        hFile_ = INVALID_HANDLE_VALUE;

        if (!AtomicRename(tempPath_, finalPath_)) {
            DWORD err = ::GetLastError();
            Log("Error: atomic rename failed (GLE=" + std::to_string(err) + ")");
            return false;
        }
        return true;
    }

    ~StreamingJsonWriter() {
        if (hFile_ != INVALID_HANDLE_VALUE) {
            ::CloseHandle(hFile_);
            ::DeleteFileW(tempPath_.c_str());
        }
    }

private:
    bool Write(const std::string& s) {
        if (s.empty()) return true;
        DWORD written = 0;
        BOOL ok = ::WriteFile(hFile_,
            s.data(), static_cast<DWORD>(s.size()),
            &written, nullptr);
        return ok && written == s.size();
    }

    std::wstring finalPath_;
    std::wstring tempPath_;
    HANDLE hFile_ = INVALID_HANDLE_VALUE;
    bool firstEntry_ = true;
};

int main(int argc, char* argv[]) {
    Log("=== Decryptor (Win7-compat, streaming, strict UTF-8) started ===");

    if (argc < 2) {
        Log("Usage: decryptor.exe <path_to_encrypted.json>");
        return 1;
    }

    std::wstring inputPathW = Utf8ToWide(argv[1]);
    if (!IsFile(inputPathW)) {
        Log("Error: Input file not found: " + std::string(argv[1]));
        return 1;
    }
    Log("Input file: " + std::string(argv[1]));

    json root;
    {
        HANDLE hIn = ::CreateFileW(inputPathW.c_str(),
            GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hIn == INVALID_HANDLE_VALUE) {
            Log("Error: Cannot open input file (GLE=" +
                std::to_string(::GetLastError()) + ")");
            return 1;
        }
        LARGE_INTEGER sz;
        ::GetFileSizeEx(hIn, &sz);
        std::string buf(static_cast<size_t>(sz.QuadPart), '\0');
        DWORD read = 0;
        ::ReadFile(hIn, &buf[0], static_cast<DWORD>(buf.size()), &read, nullptr);
        ::CloseHandle(hIn);
        buf.resize(read);

        try {
            root = json::parse(buf);
            Log("JSON parsed successfully.");
        }
        catch (const std::exception& e) {
            Log("Error parsing JSON: " + std::string(e.what()));
            return 1;
        }
    }

    struct BrowserKeys {
        std::vector<uint8_t> abe;
        std::vector<uint8_t> dpapi;
    };
    std::map<std::string, BrowserKeys> browserKeys;

    if (root.contains("browsers") && root["browsers"].is_object()) {
        for (auto& [browserId, browserInfo] : root["browsers"].items()) {
            BrowserKeys keys;

            auto loadHexKey = [&](const char* field, std::vector<uint8_t>& dest) {
                if (!browserInfo.contains(field) ||
                    !browserInfo[field].is_string()) return;
                std::string hex = browserInfo[field].get<std::string>();
                if (hex.empty()) return;
                auto kb = HexToBytes(hex);
                if (kb.size() == 32) {
                    dest = std::move(kb);
                    Log("Loaded " + std::string(field) + " key for " + browserId);
                }
                else {
                    Log("Warning: Invalid " + std::string(field) +
                        " key length for " + browserId +
                        " (got " + std::to_string(kb.size()) +
                        " bytes, expected 32)");
                }
                };

            loadHexKey("decrypted_abe", keys.abe);
            loadHexKey("decrypted_dpapi", keys.dpapi);

            if (!keys.abe.empty() || !keys.dpapi.empty())
                browserKeys[browserId] = std::move(keys);
        }
    }

    if (browserKeys.empty()) {
        Log("Error: No decryption keys found.");
        return 1;
    }

    std::wstring parentDir = ParentDir(inputPathW);
    std::wstring outputPathW = parentDir + L"\\decrypted.json";
    std::string  outputPathA = WideToUtf8(outputPathW);

    StreamingJsonWriter writer(outputPathW);
    json browsersNode = root.contains("browsers")
        ? root["browsers"]
        : json(nullptr);

    if (!writer.Open(browsersNode)) {
        Log("Error: Cannot create output file: " + outputPathA +
            " (GLE=" + std::to_string(::GetLastError()) + ")");
        return 1;
    }
    Log("Streaming output to: " + outputPathA);

    int total = 0, succeeded = 0, failed = 0;

    if (!root.contains("entries") || !root["entries"].is_array()) {
        Log("Warning: No 'entries' array found.");
    }
    else {
        for (const auto& entry : root["entries"]) {
            ++total;
            json outEntry = entry;

            std::string browserId = entry.value("browser_id", "");
            std::string encryptedB64 = entry.value("encrypted_text", "");

            auto finalize = [&](const char* msg, bool isFail) {
                outEntry["decrypted_text"] = msg;
                if (isFail) ++failed;
                writer.WriteEntry(outEntry);
                };

            if (browserId.empty() || encryptedB64.empty()) {
                finalize("[NO_DATA]", true); continue;
            }

            auto it = browserKeys.find(browserId);
            if (it == browserKeys.end()) {
                finalize("[NO_KEY_FOR_BROWSER]", true); continue;
            }

            auto encryptedBlob = FromBase64(encryptedB64);
            if (encryptedBlob.empty()) {
                finalize("[DECRYPT_FAILED: invalid base64]", true); continue;
            }

            bool ok = false;
            std::string plaintext;

            auto tryDecrypt = [&](const std::vector<uint8_t>& key,
                const char* label) -> bool {
                    if (key.empty()) return false;
                    auto dec = AesGcmDecrypt(key, encryptedBlob);
                    if (!dec || dec->empty()) return false;
                    plaintext = ToUtf8Safe(*dec);
                    Log(std::string("  [+] Decrypted with ") + label +
                        " for " + browserId);
                    return true;
                };

            ok = tryDecrypt(it->second.abe, "ABE") ||
                tryDecrypt(it->second.dpapi, "DPAPI");

            if (ok) {
                outEntry["decrypted_text"] = std::move(plaintext);
                ++succeeded;
            }
            else {
                outEntry["decrypted_text"] = "[DECRYPT_FAILED]";
                ++failed;
                Log("  [-] Decryption failed for: " +
                    entry.value("title", "<no title>"));
            }

            if (!writer.WriteEntry(outEntry)) {
                Log("Error: Write failed mid-stream. Aborting.");
                return 1;
            }
        }
    }

    if (!writer.Close(total, succeeded, failed)) {
        Log("Error: Failed to finalise output file.");
        return 1;
    }

    Log("Decryption complete.");
    Log("  Total             : " + std::to_string(total));
    Log("  Decrypted OK      : " + std::to_string(succeeded));
    Log("  Failed            : " + std::to_string(failed));
    Log("  Output            : " + outputPathA);

    if (IsFile(outputPathW) && FileSize(outputPathW) == 0) {
        Log("ERROR: Output file is zero bytes.");
        return 1;
    }

    return 0;
}
