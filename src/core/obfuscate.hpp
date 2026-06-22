// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include "version.hpp"

namespace Core {

    namespace detail {

        // Compile-time FNV-1a (recursive, stateless)
        constexpr uint64_t fnv1a_64(const char* str, size_t len, uint64_t hash = 14695981039346656037ULL) {
            return len == 0 ? hash
                : fnv1a_64(str + 1, len - 1,
                    (hash ^ static_cast<uint64_t>(*str)) * 1099511628211ULL);
        }

        // Three-source build key: date ^ time ^ version tag — maximises per-build entropy
        constexpr uint64_t BUILD_KEY =
            fnv1a_64(__DATE__, 11) ^
            fnv1a_64(__TIME__, 8) ^
            fnv1a_64(Core::BUILD_TAG, 7);

        // Full SFC64-inspired mixing: 4-round avalanche with rotations, no intermediate names
        constexpr uint64_t mix64(uint64_t v) {
            // round 1 — xorshift + multiply
            // round 2 — rotate-left 17 + xor
            // round 3 — multiply + xorshift
            // round 4 — finalise
            return
                (([](uint64_t x) constexpr -> uint64_t {
                x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ULL;
                x ^= x >> 27; x *= 0x94D049BB133111EBULL;
                return x ^ (x >> 31);
                    })(
                        (([](uint64_t x) constexpr -> uint64_t {
                            return ((x << 17) | (x >> 47)) ^ x;
                            })(v ^ (v >> 33)) * 0xFF51AFD7ED558CCDULL)
                        ));
        }

        // Position-dependent key byte derived from fully-mixed seed
        constexpr uint8_t key_byte(size_t pos, uint64_t seed) {
            return static_cast<uint8_t>(mix64(seed ^ (pos * 0x9E3779B97F4A7C15ULL) ^ (pos * pos * 0x6C62272E07BB0142ULL)));
        }

        // CBC-like chaining: each key byte is folded with the previous ciphertext byte,
        // making each position depend on all prior encrypted bytes (compile-time).
        // 'prev' is the IV; position 0 uses seed low-byte as IV.
        constexpr uint8_t chained_key_byte(size_t pos, uint64_t seed, uint8_t prev_cipher) {
            return key_byte(pos, seed) ^ (prev_cipher * 0x9BUL) ^ static_cast<uint8_t>(pos * 0x1BUL);
        }

        // Compile-time encrypt array builder via index_sequence
        template<size_t N, size_t... I>
        constexpr std::array<uint8_t, N> make_key_schedule(uint64_t seed, std::index_sequence<I...>) {
            std::array<uint8_t, N> ks{};
            uint8_t chain = static_cast<uint8_t>(seed);
            ((ks[I] = (chain = chained_key_byte(I, seed, chain))), ...);
            return ks;
        }

    } // namespace detail

    template<size_t N>
    class ObfuscatedString {
    public:
        // Compile-time constructor - encrypts the string using per-build key schedule
        constexpr ObfuscatedString(const char(&str)[N], uint64_t seed)
            : m_keys(detail::make_key_schedule<N>(seed, std::make_index_sequence<N>{}))
        {
            for (size_t i = 0; i < N; ++i)
                m_data[i] = static_cast<char>(static_cast<uint8_t>(str[i]) ^ m_keys[i]);
        }

        // Runtime decryption - returns the original string
        const char* c_str() const {
            thread_local char buffer[N];
            decrypt_impl(buffer);
            return buffer;
        }

        // Get decrypted string and store in provided buffer
        void decrypt_to(char* buffer) const {
            decrypt_impl(buffer);
        }

        constexpr size_t size() const { return N - 1; }

    private:
        std::array<char, N> m_data{};
        std::array<uint8_t, N> m_keys{};  // pre-derived; seed is NOT stored at runtime

        void decrypt_impl(char* buffer) const {
            for (size_t i = 0; i < N; ++i)
                buffer[i] = static_cast<char>(static_cast<uint8_t>(m_data[i]) ^ m_keys[i]);
        }
    };

    // Helper to create obfuscated string with unique seed per call site
    template<size_t N>
    constexpr auto make_obfuscated(const char(&str)[N], uint64_t line_seed) {
        return ObfuscatedString<N>(str, detail::BUILD_KEY ^ line_seed);
    }

} // namespace Core

// Macro that creates unique seed from line number
#define OBF(str) (::Core::make_obfuscated(str, __LINE__ * 0x85EBCA77C2B2AE63ULL))

// For wide strings
#define WOBF(str) (::Core::make_obfuscated_w(str, __LINE__ * 0x85EBCA77C2B2AE63ULL))