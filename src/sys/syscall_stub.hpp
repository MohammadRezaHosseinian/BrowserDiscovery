// src/sys/syscall_stub.hpp
#pragma once
#include <windows.h>

namespace Sys {
    // Creates an indirect syscall stub that loads the SSN and jumps to the raw gadget.
    // Returns a pointer to executable memory, or nullptr on failure.
    PVOID CreateIndirectStub(PVOID rawGadget, WORD ssn);

    // Optional: free all allocated stubs at process exit (not strictly necessary)
    void FreeIndirectStubs();
}