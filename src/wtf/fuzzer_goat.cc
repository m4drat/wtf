// Axel '0vercl0k' Souchet - July 31 2021
#include "backend.h"
#include "targets.h"
#include "crash_detection_umode.h"

#include <fmt/format.h>

namespace FuzzyGoat {

constexpr bool LoggingOn = true;

template <typename... Args_t>
void DebugPrint(const char *Format, const Args_t &...args) {
  if constexpr (LoggingOn) {
    fmt::print("FuzzyGoat: ");
    fmt::print(fmt::runtime(Format), args...);
  }
}

bool InsertTestcase(const uint8_t *Buffer, const size_t BufferSize) {
  // Write payload
  const Gva_t BufferPtr = Gva_t(g_Backend->Rcx());
  if (!g_Backend->VirtWriteDirty(BufferPtr, Buffer,
                                 BufferSize)) {
    DebugPrint("VirtWriteDirty failed\n");
    return false;
  }

  // Set size
  g_Backend->Rdx(BufferSize);

  return true;
}

bool Init(const Options_t &Opts, const CpuState_t &) {
  const Gva_t Rip = Gva_t(g_Backend->Rip());
  const Gva_t AfterCall = Rip + Gva_t(6);
  if (!g_Backend->SetBreakpoint(AfterCall, [](Backend_t *Backend) {
        DebugPrint("Back from call!\n");
        Backend->Stop(Ok_t());
      })) {
    DebugPrint("Failed to SetBreakpoint AfterCall\n");
    return false;
  }

  if (!SetupUsermodeCrashDetectionHooks()) {
    DebugPrint("Failed to SetupUsermodeCrashDetectionHooks\n");
    return false;
  }

  return true;
}

//
// Register the target.
//

Target_t FuzzyGoat("fuzzy_goat", Init, InsertTestcase);

} // namespace FuzzyGoat