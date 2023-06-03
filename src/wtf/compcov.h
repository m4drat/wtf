// Theodor Arsenij 'm4drat' - May 26 2023

#pragma once

//
// Compcov maximum comparison length. Everything above this length will be
// ignored.
//

constexpr uint64_t COMPCOV_MAX_CMP_LENGTH = 34;

//
// Setup compcov hooks on different implementations of comparison functions:
// ntdll!strcmp, ucrtbase!strcmp, etc.
//

bool SetupCompcovHooks();

//
// Generic compcov handlers for different comparison functions. They might be
// useful if you want to add support for a custom comparison function, even if
// it uses a different calling convention. Just wrap the handler into a
// BreakpointHandler_t and use SetupCustom*Hook() functions.
//

void CompcovHandleStrcmp(Backend_t *Backend, Gva_t Str1Ptr, Gva_t Str2Ptr);
void CompcovHandleStrncmp(Backend_t *Backend, Gva_t Str1Ptr, Gva_t Str2Ptr,
                          uint64_t MaxCount);
void CompcovHandleWcscmp(Backend_t *Backend, Gva_t Wstr1Ptr, Gva_t Wstr2Ptr);
void CompcovHandleWcsncmp(Backend_t *Backend, Gva_t Wstr1Ptr, Gva_t Wstr2Ptr,
                          uint64_t MaxCount);
void CompcovHandleMemcmp(Backend_t *Backend, Gva_t Buf1Ptr, Gva_t Buf2Ptr,
                         uint64_t Size);

//
// Setup compcov-strcmp hook for a custom implementation of strcmp.
//

bool SetupCustomStrcmpHook(const char *Symbol,
                           const BreakpointHandler_t Handler);
bool SetupCustomStrcmpHook(const Gva_t Gva, const BreakpointHandler_t Handler);

//
// Setup compcov-strncmp hook for a custom implementation of strncmp.
//

bool SetupCustomStrncmpHook(const char *Symbol,
                            const BreakpointHandler_t Handler);
bool SetupCustomStrncmpHook(const Gva_t Gva, const BreakpointHandler_t Handler);

//
// Setup compcov-wcscmp hook for a custom implementation of wcscmp.
//

bool SetupCustomWcscmpHook(const char *Symbol,
                           const BreakpointHandler_t Handler);
bool SetupCustomWcscmpHook(const Gva_t Gva, const BreakpointHandler_t Handler);

//
// Setup compcov-wcsncmp hook for a custom implementation of wcsncmp.
//

bool SetupCustomWcsncmpHook(const char *Symbol,
                            const BreakpointHandler_t Handler);
bool SetupCustomWcsncmpHook(const Gva_t Gva, const BreakpointHandler_t Handler);

//
// Setup compcov-memcmp hook for a custom implementation of memcmp.
//

bool SetupCustomMemcmpHook(const char *Symbol,
                           const BreakpointHandler_t Handler);
bool SetupCustomMemcmpHook(const Gva_t Gva, const BreakpointHandler_t Handler);
