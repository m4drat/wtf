// Theodor Arsenij 'm4drat' - May 23 2023

#include "compcov.h"
#include "backend.h"
#include "debugger.h"
#include "fmt/core.h"
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
void CompcovTrace(const uint64_t RetLoc, const T *Buffer1, const T *Buffer2,
                  const uint64_t Length) {
  uint64_t HashedLoc = SplitMix64(RetLoc);
  for (uint32_t i = 0; i < Length && Buffer1[i] == Buffer2[i]; i++) {
    // fmt::print("compcov: Got a hit: Buffer[{}] = {}\n", i, Buffer1[i]);
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

  std::array<uint8_t, COMPCOV_MAX_CMP_LENGTH + 2> Str1{};
  std::array<uint8_t, COMPCOV_MAX_CMP_LENGTH + 2> Str2{};

  bool Str1ReadRes =
      Backend->VirtRead(Str1Ptr, Str1.data(), COMPCOV_MAX_CMP_LENGTH + 1);
  bool Str2ReadRes =
      Backend->VirtRead(Str2Ptr, Str2.data(), COMPCOV_MAX_CMP_LENGTH + 1);

  //
  // Check whether we were able to read the strings.
  //

  if (!Str1ReadRes || !Str2ReadRes) {
    CompcovPrint("{}: Failed to read strings\n", __func__);
    return;
  }

  uint64_t Length =
      CompcovStrlen2(Str1.data(), Str2.data(), COMPCOV_MAX_CMP_LENGTH + 2);

  //
  // Skip if the comparison is too long, as we don't want to clutter the
  // coverage database.
  //

  if (Length > COMPCOV_MAX_CMP_LENGTH) {
    CompcovPrint("{}: MaxCount > COMPCOV_MAX_CMP_LENGTH\n", __func__);
    return;
  }

  //
  // As the breakpoint is set on the beginning of the function, we <<<should>>>
  // be able to extract the return address by reading the first QWORD from the
  // stack.
  //

  uint64_t RetLoc = Backend->VirtRead8(Gva_t(Backend->Rsp()));

  CompcovPrint("Strcmp(\"{}\", \"{}\", {}) -> {:#x}\n", (char *)Str1.data(),
               (char *)Str2.data(), Length, RetLoc);

  //
  // If the return location is 0, then the VirtRead8() failed.
  //

  if (RetLoc == 0) {
    CompcovPrint("{}: RetLoc == 0\n", __func__);
    return;
  }

  CompcovTrace(RetLoc, Str1.data(), Str2.data(), Length);
}

void CompcovHookStrncmp(Backend_t *Backend) {
  Gva_t Str1Ptr = Gva_t(Backend->GetArg(0));
  Gva_t Str2Ptr = Gva_t(Backend->GetArg(1));
  uint64_t MaxCount = Backend->GetArg(2);

  //
  // Skip if the comparison is too long, as we don't want to clutter the
  // coverage database.
  //

  if (MaxCount > COMPCOV_MAX_CMP_LENGTH) {
    CompcovPrint("{}: MaxCount > COMPCOV_MAX_CMP_LENGTH\n", __func__);
    return;
  }

  std::array<uint8_t, COMPCOV_MAX_CMP_LENGTH + 1> Str1{};
  std::array<uint8_t, COMPCOV_MAX_CMP_LENGTH + 1> Str2{};

  bool Str1ReadRes = Backend->VirtRead(Str1Ptr, Str1.data(), MaxCount);
  bool Str2ReadRes = Backend->VirtRead(Str2Ptr, Str2.data(), MaxCount);

  //
  // Check whether we were able to read the strings.
  //

  if (!Str1ReadRes || !Str2ReadRes) {
    CompcovPrint("{}: Failed to read strings\n", __func__);
    return;
  }

  uint64_t Length = CompcovStrlen2(Str1.data(), Str2.data(), MaxCount);

  //
  // As the breakpoint is set on the beginning of the function, we <<<should>>>
  // be able to extract the return address by reading the first QWORD from the
  // stack.
  //

  uint64_t RetLoc = Backend->VirtRead8(Gva_t(Backend->Rsp()));

  CompcovPrint("Strncmp(\"{}\", \"{}\", {}) -> {:#x}\n", (char *)Str1.data(),
               (char *)Str2.data(), Length, RetLoc);

  //
  // If the return location is 0, then the VirtRead8() failed.
  //

  if (RetLoc == 0) {
    CompcovPrint("{}: RetLoc == 0\n", __func__);
    return;
  }

  CompcovTrace(RetLoc, Str1.data(), Str2.data(), Length);
}

void CompcovHookMemcmp(Backend_t *Backend) {
  Gva_t Buf1Ptr = Gva_t(Backend->GetArg(0));
  Gva_t Buf2Ptr = Gva_t(Backend->GetArg(1));
  uint64_t Size = Backend->GetArg(2);

  //
  // Skip if the comparison is too long, as we don't want to clutter the
  // coverage database.
  //

  if (Size > COMPCOV_MAX_CMP_LENGTH) {
    CompcovPrint("{}: Size > COMPCOV_MAX_CMP_LENGTH\n", __func__);
    return;
  }

  std::array<uint8_t, COMPCOV_MAX_CMP_LENGTH + 1> Buf1{};
  std::array<uint8_t, COMPCOV_MAX_CMP_LENGTH + 1> Buf2{};

  bool Buf1ReadRes = Backend->VirtRead(Buf1Ptr, Buf1.data(), Size);
  bool Buf2ReadRes = Backend->VirtRead(Buf2Ptr, Buf2.data(), Size);

  //
  // Check whether we were able to read the buffers.
  //

  if (!Buf1ReadRes || !Buf2ReadRes) {
    CompcovPrint("{}: Failed to read buffers\n", __func__);
    return;
  }

  //
  // As the breakpoint is set on the beginning of the function, we <<<should>>>
  // be able to extract the return address by reading the first QWORD from the
  // stack.
  //

  uint64_t RetLoc = Backend->VirtRead8(Gva_t(Backend->Rsp()));

  CompcovPrint("Memcmp(\"{}\", \"{}\", {}) -> {:#x}\n",
               BytesToHexString(Buf1.data(), Size),
               BytesToHexString(Buf2.data(), Size), Size, RetLoc);

  //
  // If the return location is 0, then the VirtRead8() failed.
  //

  if (RetLoc == 0) {
    CompcovPrint("{}: RetLoc == 0\n", __func__);
    return;
  }

  CompcovTrace(RetLoc, Buf1.data(), Buf2.data(), Size);
}

bool SetupCompcovHooks() {
  bool Success = true;

  // @TODO: Hook more functions (wcscmp, CompareStringA, etc)

  const std::vector<std::string_view> strcmp_functions = {"ntdll!strcmp",
                                                          "ucrtbase!strcmp"};
  const std::vector<std::string_view> strncmp_functions = {"ntdll!strncmp",
                                                           "ucrtbase!strncmp"};
  const std::vector<std::string_view> memcmp_functions = {
      "ntdll!memcmp", "vcruntime140!memcmp", "ucrtbase!memcmp"};

  for (auto &function : strcmp_functions) {
    // @TODO: Currently we're "ignoring" the fact that SetBreakpoint can fail
    // (e.g. a breakpoint is already set on the function).
    // Probably, the best way to handle this is to replace already set
    // breakpoint with our own, but call the original BP-handler from it.
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