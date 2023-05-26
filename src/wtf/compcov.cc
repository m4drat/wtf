// Theodor Arsenij 'm4drat' - May 23 2023

#include "compcov.h"
#include "backend.h"
#include "debugger.h"
#include "globals.h"
#include "nt.h"
#include "utils.h"
#include <fmt/format.h>
#include <vector>

constexpr bool CompcovLoggingOn = false;

template <typename... Args_t>
void CompcovPrint(const char *Format, const Args_t &...args) {
  if constexpr (CompcovLoggingOn) {
    fmt::print("compcov: ");
    fmt::print(fmt::runtime(Format), args...);
  }
}

template <class T>
uint64_t CompcovStrlen2(const T *s1, const T *s2, uint64_t max_length) {

  // from https://github.com/googleprojectzero/CompareCoverage

  size_t len = 0;
  for (; len < max_length && s1[len] != 0x0 && s2[len] != 0x0; len++) {
  }

  return len;
}

template <class T>
void CompcovTrace(const uint64_t Rip, const T *Buffer1, const T *Buffer2,
                  const uint64_t Length) {
  uint64_t HashedLoc = SplitMix64(Rip);
  for (uint32_t i = 0; i < Length && Buffer1[i] == Buffer2[i]; i++) {
    // fmt::print("compcov: Got hit at idx Buffer[{}] = {}\n", i, Buffer1[i]);
    g_Backend->InsertCoverageEntry(Gva_t(HashedLoc + i));

    // if (Buffer1[i] == Buffer2[i]) {
    //   g_Backend->InsertCoverageEntry(Gva_t(HashedLoc + i + SuccessfulCmp));
    //   SuccessfulCmp++;
    // }
  }
}

void CompcovHookStrcmp(Backend_t *Backend) {
  Gva_t Str1Ptr = Gva_t(Backend->GetArg(0));
  Gva_t Str2Ptr = Gva_t(Backend->GetArg(1));

  std::array<uint8_t, COMPCOV_MAX_CMP_LENGTH + 1> Str1{};
  std::array<uint8_t, COMPCOV_MAX_CMP_LENGTH + 1> Str2{};

  Backend->VirtRead(Str1Ptr, Str1.data(), COMPCOV_MAX_CMP_LENGTH);
  Backend->VirtRead(Str2Ptr, Str2.data(), COMPCOV_MAX_CMP_LENGTH);

  uint64_t Length =
      CompcovStrlen2(Str1.data(), Str2.data(), COMPCOV_MAX_CMP_LENGTH);

  CompcovPrint("Strcmp(\"{}\", \"{}\", {})\n", (char *)Str1.data(),
               (char *)Str2.data(), Length);

  CompcovTrace(Backend->Rip(), Str1.data(), Str2.data(), Length);
}

void CompcovHookStrncmp(Backend_t *Backend) {
  Gva_t Str1Ptr = Gva_t(Backend->GetArg(0));
  Gva_t Str2Ptr = Gva_t(Backend->GetArg(1));
  uint64_t MaxCount = std::min(Backend->GetArg(2), COMPCOV_MAX_CMP_LENGTH);

  std::array<uint8_t, COMPCOV_MAX_CMP_LENGTH + 1> Str1{};
  std::array<uint8_t, COMPCOV_MAX_CMP_LENGTH + 1> Str2{};

  Backend->VirtRead(Str1Ptr, Str1.data(), MaxCount);
  Backend->VirtRead(Str2Ptr, Str2.data(), MaxCount);

  uint64_t Length = CompcovStrlen2(Str1.data(), Str2.data(), MaxCount);

  CompcovPrint("Strncmp(\"{}\", \"{}\", {})\n", (char *)Str1.data(),
               (char *)Str2.data(), Length);

  CompcovTrace(Backend->Rip(), Str1.data(), Str2.data(), Length);
}

void CompcovHookMemcmp(Backend_t *Backend) {
  Gva_t Buf1Ptr = Gva_t(Backend->GetArg(0));
  Gva_t Buf2Ptr = Gva_t(Backend->GetArg(1));
  uint64_t Size = std::min(Backend->GetArg(2), COMPCOV_MAX_CMP_LENGTH);

  std::array<uint8_t, COMPCOV_MAX_CMP_LENGTH + 1> Buf1{};
  std::array<uint8_t, COMPCOV_MAX_CMP_LENGTH + 1> Buf2{};

  Backend->VirtRead(Buf1Ptr, Buf1.data(), Size);
  Backend->VirtRead(Buf2Ptr, Buf2.data(), Size);

  if constexpr (CompcovLoggingOn) {
    std::string Buf1Hex(Buf1.size() * 2, ' ');
    Hexdump((uint64_t)Buf1.data(), Buf1Hex.data(), Size);

    std::string Buf2Hex(Buf2.size() * 2, ' ');
    Hexdump((uint64_t)Buf2.data(), Buf2Hex.data(), Size);

    CompcovPrint("Memcmp(\n");
    CompcovPrint("Buf1:\n{}\n", Buf1Hex);
    CompcovPrint("Buf2:\n{}\n", Buf2Hex);
    CompcovPrint(")\n");
  }

  CompcovPrint("Memcmp({}, {}, {})\n", (char *)Buf1.data(), (char *)Buf2.data(),
               Size);

  CompcovTrace(Backend->Rip(), Buf1.data(), Buf2.data(), Size);
}

bool SetupCompcovHooks() {
  bool Success = true;

  const std::vector<std::string_view> strcmp_functions = {"ntdll!strcmp",
                                                          "ucrtbase!strcmp"};
  const std::vector<std::string_view> strncmp_functions = {"ntdll!strncmp",
                                                           "ucrtbase!strncmp"};
  const std::vector<std::string_view> memcmp_functions = {
      "ntdll!memcmp", "vcruntime140!memcmp", "ucrtbase!memcmp"};

  for (auto &function : strcmp_functions) {
    if (!g_Backend->SetBreakpoint(function.data(), [](Backend_t *Backend) {
          CompcovPrint("hooking strcmp\n");
          CompcovHookStrcmp(Backend);
        })) {
      fmt::print("Failed to SetBreakpoint on {}\n", function);
      Success = false;
    }
  }

  for (auto &function : strncmp_functions) {
    if (!g_Backend->SetBreakpoint(function.data(), [](Backend_t *Backend) {
          CompcovPrint("hooking strncmp\n");
          CompcovHookStrncmp(Backend);
        })) {
      fmt::print("Failed to SetBreakpoint on {}\n", function);
      Success = false;
    }
  }

  for (auto &function : memcmp_functions) {
    if (!g_Backend->SetBreakpoint(function.data(), [](Backend_t *Backend) {
          CompcovPrint("hooking memcmp\n");
          CompcovHookMemcmp(Backend);
        })) {
      fmt::print("Failed to SetBreakpoint on ntdll!strcmp\n");
      Success = false;
    }
  }

  return Success;
}