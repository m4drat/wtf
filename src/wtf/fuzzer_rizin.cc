// Theodor Arsenij 'm4drat' - May 23 2023

#include "backend.h"
#include "compcov.h"
#include "crash_detection_umode.h"
#include "targets.h"

#include <fmt/format.h>
#include <stdlib.h>

namespace Rizin {

constexpr bool LoggingOn = false;

template <typename... Args_t>
void DebugPrint(const char *Format, const Args_t &...args) {
  if constexpr (LoggingOn) {
    fmt::print("Fuzzer Rizin: ");
    fmt::print(fmt::runtime(Format), args...);
  }
}

bool InsertTestcase(const uint8_t *Buffer, const size_t BufferSize) {
  if (BufferSize > 1200000 || BufferSize < 1) {
    DebugPrint("Invalid BufferSize\n");
    return true;
  }

  // Write payload
  const Gva_t BufferPtr = Gva_t(g_Backend->Rcx());
  if (!g_Backend->VirtWriteDirty(BufferPtr, Buffer, BufferSize)) {
    DebugPrint("VirtWriteDirty failed\n");
    return false;
  }

  // Set size
  g_Backend->Rdx(BufferSize);

  return true;
}

bool Init(const Options_t &Opts, const CpuState_t &) {
  DebugPrint("Initialization!\n");

  const Gva_t Rip = Gva_t(g_Backend->Rip());
  const Gva_t AfterCall = Rip + Gva_t(5);
  if (!g_Backend->SetBreakpoint(
          AfterCall, [](Backend_t *Backend) { Backend->Stop(Ok_t()); })) {
    DebugPrint("Failed to SetBreakpoint AfterCall\n");
    return false;
  }

  // if (!g_Backend->SetBreakpoint(
  //         "ntdll!RtlCaptureStackBackTrace", [](Backend_t *Backend) {
  //           DebugPrint("Before ntdll!RtlCaptureStackBackTrace!\n");
  //           DebugPrint("RtlCaptureStackBackTrace({:#x}, {:#x}, {:#x},
  //           {:#x})\n",
  //                      g_Backend->GetArg(0), g_Backend->GetArg(1),
  //                      g_Backend->GetArg(2), g_Backend->GetArg(3));
  //         })) {
  //   DebugPrint("Failed to SetBreakpoint on
  //   ntdll!RtlCaptureStackBackTrace\n"); return false;
  // }

  // const Gva_t AfterRtlCaptureStackBackTrace =
  //     Gva_t(g_Dbg.GetSymbol("ntdll!RtlpHpHeapHandleError") + 0x41);
  // if (!g_Backend->SetBreakpoint(
  //         AfterRtlCaptureStackBackTrace, [](Backend_t *Backend) {
  //           DebugPrint("After RtlCaptureStackBackTrace!\n");
  //           DebugPrint("RtlCaptureStackBackTrace -> {:#x}\n",
  //                      g_Backend->GetReg(Registers_t::Rax));
  //         })) {
  //   DebugPrint("Failed to SetBreakpoint on AfterRtlCaptureStackBackTrace\n");
  //   return false;
  // }

  if (!g_Backend->SetBreakpoint(
          "ntdll!RtlpHeapHandleError", [](Backend_t *Backend) {
            DebugPrint("Heap Error triggered!\n");

            const uint32_t FramesToCapture = 0x20;

            std::array<uint64_t, FramesToCapture> Backtrace;
            uint64_t BackTraceNtdll = g_Dbg.GetModuleBase("ntdll") + 0x167848;
            DebugPrint("BackTraceNtdll: {:#x}\n", BackTraceNtdll);

            for (uint32_t i = 0; i < FramesToCapture; ++i) {
              Backtrace[i] = g_Backend->VirtRead8(
                  Gva_t{BackTraceNtdll + i * sizeof(void *)});
              if (!Backtrace[i])
                break;

              DebugPrint("{:#x} -> {}\n", Backtrace[i],
                         g_Dbg.GetName(Backtrace[i], true));
            }

            Backend->Stop(Crash_t(std::format(
                "crash-heaperror-{:#x}-{:#x}-{:#x}-{:#x}-{:#x}-{:#x}-{:#x}",
                Backtrace[0], Backtrace[1], Backtrace[2], Backtrace[3],
                Backtrace[4], Backtrace[5], Backtrace[6])));
          })) {
    DebugPrint("Failed to SetBreakpoint on ntdll!RtlpHeapHandleError\n");
    return false;
  }

  if (!SetupUsermodeCrashDetectionHooks()) {
    DebugPrint("Failed to SetupUsermodeCrashDetectionHooks\n");
    return false;
  }

  if (!CompcovSetupCustomStrcmpHook("rz_fuzz!rz_str_cmp")) {
    DebugPrint("Failed to setup custom strcmp hook\n");
    // We're siletly ignoring this case, as for anything except BochsCPU this
    // will fail.
  }

  return true;
}

//
// Register the target.
//

Target_t Rizin(
    "rizin", Init, InsertTestcase, []() { return true; },
    HonggfuzzMutator_t::Create);

} // namespace Rizin