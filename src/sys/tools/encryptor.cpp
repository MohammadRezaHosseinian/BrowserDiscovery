#include "../../crypto/crypto.hpp"
#include "../../crypto/key_derivation.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>

/**
 * Payload Encryptor Tool
 *
 * This tool encrypts the payload DLL using runtime-derived keys and generates
 * an embeddable C++ header for direct inclusion in the injector.
 *
 * The key derivation uses the same algorithm as the decryptor,
 * ensuring deterministic keys per build (based on __DATE__/__TIME__).
 *
 * IMPORTANT: The encryptor and injector MUST be built in the SAME
 * compilation session (same make.bat run) for keys to match.
 * This is because BUILD_SEED changes with __DATE__ and __TIME__.
 */

void PrintKeyInfo(const Crypto::RuntimeKeyProvider::KeyMaterial& km) {
    for (size_t i = 0; i < km.key.size(); ++i) {}
    for (size_t i = 0; i < km.nonce.size(); ++i) {}
}

bool WriteEmbeddedHeader(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream out(path);
    if (!out) return false;

    out << "#pragma once\n";
    out << "#include <cstdint>\n";
    out << "#include <cstddef>\n";
    out << "\n";
    out << "namespace Payload::Embedded {\n";
    out << "\n";
    out << "    static const uint8_t Data[] = {";

    for (size_t i = 0; i < data.size(); ++i) {
        if (i % 16 == 0) out << "\n        ";
        out << "0x" << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]);
        if (i < data.size() - 1) out << ",";
        if (i % 16 != 15 && i < data.size() - 1) out << " ";
    }

    out << "\n    };\n";
    out << "\n";
    out << "    static const size_t Size = sizeof(Data);\n";
    out << "\n";
    out << "} // namespace Payload::Embedded\n";

    return out.good();
}

int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 4) {
        return 1;
    }

    std::ifstream in(argv[1], std::ios::binary);
    if (!in) {
        return 1;
    }

    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    // Derive keys using the same algorithm as the decryptor
    auto keyMaterial = Crypto::RuntimeKeyProvider::GetPayloadKey();
    if (!keyMaterial.valid) {
        return 1;
    }
    std::cout << "[src/sys/tools/encryptor] [+] key : ";

    for (const auto& b : keyMaterial.key)
    {
        std::cout << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<unsigned int>(b);
    }

    std::cout << std::dec << '\n';
    PrintKeyInfo(keyMaterial);

    // Encrypt using ChaCha20 (XOR-based, so same function encrypts/decrypts)
    Crypto::ChaCha20::Crypt(keyMaterial.key.data(), keyMaterial.nonce.data(), data, 0);

    // Securely clear key material
    SecureZeroMemory(keyMaterial.key.data(), keyMaterial.key.size());
    SecureZeroMemory(keyMaterial.nonce.data(), keyMaterial.nonce.size());
    std::cout << "[src/sys/tools/encryptor] [+] keyMaterial.key   : " << keyMaterial.key.data() << "\n";
    std::cout << "[src/sys/tools/encryptor] [+] keyMaterial.size   : " << keyMaterial.key.size() << "\n";
    std::ofstream out(argv[2], std::ios::binary);
    if (!out) {
        return 1;
    }
    out.write(reinterpret_cast<const char*>(data.data()), data.size());
    out.close();

    // Generate embedded header if path provided
    if (argc == 4) {
        if (WriteEmbeddedHeader(argv[3], data)) {
        }
        else {
            return 1;
        }
    }

    return 0;
}
