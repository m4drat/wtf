// Axel '0vercl0k' Souchet - February 26 2020
#pragma once
#include "backend.h"
#include "bochscpu.hpp"
#include "debugger.h"
#include "globals.h"
#include "human.h"
#include "kdmp-parser.h"
#include "platform.h"
#include "tsl/robin_map.h"
#include "tsl/robin_set.h"
#include "utils.h"
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <stdexcept>

struct BochscpuRunStats_t {
  uint64_t NumberInstructionsExecuted = 0;
  uint64_t NumberMemoryAccesses = 0;
  uint64_t AggregatedCodeCoverage = 0;
  uint64_t DirtyGpas = 0;
  uint64_t NumberEdges = 0;
  uint64_t NumberUniqueEdges = 0;

  void Print() const {
    fmt::print("--------------------------------------------------\n");
    fmt::print("Run stats:\n");
    fmt::print("Instructions executed: {} ({} unique)\n",
               NumberToHuman(NumberInstructionsExecuted),
               NumberToHuman(AggregatedCodeCoverage));
    const uint64_t DirtyMemoryBytes = DirtyGpas * Page::Size;
    fmt::print("          Dirty pages: {}\n", BytesToHuman(DirtyMemoryBytes));
    fmt::print("      Memory accesses: {}\n",
               BytesToHuman(NumberMemoryAccesses));
    fmt::print("       Edges executed: {} ({} unique)\n",
               NumberToHuman(NumberEdges), NumberToHuman(NumberUniqueEdges));
  }

  void Reset() {
    NumberInstructionsExecuted = 0;
    NumberMemoryAccesses = 0;
    NumberEdges = 0;
    NumberUniqueEdges = 0;
  }
};

//
// A structure to capture information about a single memory access; used for
// Tenet traces.
//

struct BochscpuMemAccess_t {
  const Gva_t VirtualAddress;
  const uintptr_t Len;
  const uint32_t MemAccess;
  explicit BochscpuMemAccess_t(const uint64_t VirtualAddress,
                               const uintptr_t Len, const uint32_t MemAccess)
      : VirtualAddress(VirtualAddress), Len(Len), MemAccess(MemAccess) {}
};

class BochscpuBackend_t : public Backend_t {

  //
  // Hardcore hash functions.
  //

  struct IdentityGpaHash {
    size_t operator()(const Gpa_t &Key) const { return Key.U64(); }
  };

  struct IdentityGvaHash {
    size_t operator()(const Gva_t &Key) const { return Key.U64(); }
  };

  //
  // Kernel dump parser.
  //

  kdmpparser::KernelDumpParser DmpParser_;

  //
  // Aggregated code coverage across runs. This is a list of unique RIP
  // addresses that have been executed.
  //

  tsl::robin_set<Gva_t, IdentityGvaHash> AggregatedCodeCoverage_;

  //
  // New code-coverage executed by the latest testcase.
  //

  tsl::robin_set<Gva_t> LastNewCoverage_;

  //
  // Unique GPAs that got written to.
  //

  tsl::robin_pg_set<Gpa_t, IdentityGpaHash> DirtyGpas_;

  //
  // Breakpoints. This maps a GVA to a breakpoint.
  //

  tsl::robin_map<Gva_t, BreakpointHandler_t> Breakpoints_;

  //
  // Cpu.
  //

  bochscpu_cpu_t Cpu_ = nullptr;

  struct Tenet_t {

    //
    // A copy of Cpu registers at t-1 (the previous instruction); used for Tenet
    // traces.
    //

    bochscpu_cpu_state_t CpuStatePrev_ = {};

    //
    // Boolean that tracks if the execution is past the first execution; used
    // for Tenet traces.
    //

    bool PastFirstInstruction_ = false;

    //
    // List of memory accesses; used for Tenet traces.
    //

    std::vector<BochscpuMemAccess_t> MemAccesses_;
  } Tenet_;

  //
  // Enable/disable the LAF.
  //

  bool LafEnabled_ = false;

  //
  // The hooks we define onto the Cpu.
  //

  bochscpu_hooks_t Hooks_ = {};

  //
  // The chain of hooks. We only use a set of hooks, so we need
  // only two entries (it has to end with a nullptr entry).
  //

  bochscpu_hooks_t *HookChain_[2] = {};

  //
  // Instruction limit.
  //

  uint64_t InstructionLimit_ = 0;

  //
  // Trace file.
  //

  FILE *TraceFile_ = nullptr;

  //
  // Trace type.
  //

  TraceType_t TraceType_ = TraceType_t::NoTrace;

  //
  // Did the testcase triggered a crash? A timeout? Or nothing?
  // This keeps track of that.
  //

  TestcaseResult_t TestcaseResult_ = Ok_t();

  //
  // Value of our cr3. This is useful to detect when we are leaving our
  // process.
  //

  uint64_t InitialCr3_ = 0;

  //
  // Stats of the run.
  //

  BochscpuRunStats_t RunStats_ = {};

  uint64_t Seed_ = 0;

  const uint8_t *TestcaseBuffer_ = nullptr;
  uint64_t TestcaseBufferSize_ = 0;

public:
  //
  // Ctor & cie.
  //

  BochscpuBackend_t();
  BochscpuBackend_t(const BochscpuBackend_t &) = delete;
  BochscpuBackend_t &operator=(const BochscpuBackend_t &) = delete;

  //
  // Initialize the backend.
  //

  bool Initialize(const Options_t &Opts, const CpuState_t &CpuState) override;

  //
  // Execution.
  //

  std::optional<TestcaseResult_t> Run(const uint8_t *Buffer,
                                      const uint64_t BufferSize) override;

  bool Restore(const CpuState_t &CpuState) override;

  void Stop(const TestcaseResult_t &Res) override;

  void SetLimit(const uint64_t InstructionLimit) override;

  //
  // Registers.
  //

  uint64_t GetReg(const Registers_t Reg) override;
  uint64_t SetReg(const Registers_t Reg, const uint64_t Value) override;

  //
  // Stats.
  //

  void PrintRunStats() override;

  //
  // Non-determinism.
  //

  uint64_t Rdrand() override;

  //
  // Tracing.
  //

  bool SetTraceFile(const fs::path &TestcaseTracePath,
                    const TraceType_t TraceType) override;

  //
  // Breakpoints.
  //

  bool SetBreakpoint(const Gva_t Gva,
                     const BreakpointHandler_t Handler) override;

  //
  // Virtual memory access.
  //

  bool DirtyGpa(const Gpa_t Gpa) override;

  bool VirtTranslate(const Gva_t Gva, Gpa_t &Gpa,
                     const MemoryValidate_t Validate) const override;

  uint8_t *PhysTranslate(const Gpa_t Gpa) const override;

  bool PageFaultsMemoryIfNeeded(const Gva_t Gva, const uint64_t Size) override;

  const uint8_t *GetPhysicalPage(const Gpa_t PhysicalAddress) const;

  const tsl::robin_set<Gva_t> &LastNewCoverage() const override;

  bool RevokeLastNewCoverage() override;

  bool InsertCoverageEntry(const Gva_t Gva) override;

  //
  // Hooks.
  //

  void PhyAccessHook(/*void *Context, */ uint32_t Id, uint64_t PhysicalAddress,
                     uintptr_t Len, uint32_t MemType, uint32_t MemAccess);

  void AfterExecutionHook(/*void *Context, */ uint32_t Id, void *Ins);

  void BeforeExecutionHook(/*void *Context, */ uint32_t Id, void *Ins);

  void LinAccessHook(/*void *Context, */ uint32_t Id, uint64_t VirtualAddress,
                     uint64_t PhysicalAddress, uintptr_t Len, uint32_t MemType,
                     uint32_t MemAccess);

  void InterruptHook(/*void *Context, */ uint32_t Id, uint32_t Vector);

  void ExceptionHook(/*void *Context, */ uint32_t Id, uint32_t Vector,
                     uint32_t ErrorCode);

  void TlbControlHook(/*void *Context, */ uint32_t Id, uint32_t What,
                      uint64_t NewCrValue);

  void OpcodeHook(/*void *Context, */ uint32_t Id, const void *Ins,
                  const uint8_t *Opcode, uintptr_t Len, bool Is32, bool Is64);

  void OpcodeHlt(/*void *Context, */ uint32_t Cpu);

  void RecordEdge(/*void *Context, */ uint32_t Cpu, uint64_t Rip,
                  uint64_t NextRip);

private:
  //
  // Dirty every physical pages included in a virtual memory range.
  //

  void DirtyVirtualMemoryRange(const Gva_t Gva, const uint64_t Len);

  //
  // Dirty every physical pages included in a physical memory range.
  //

  void DirtyPhysicalMemoryRange(const Gpa_t Gpa, const uint64_t Len);

  void LoadState(const CpuState_t &State);

  Gva_t GetFirstVirtualPageToFault(const Gva_t Gva, const size_t Size);

  const uint8_t *GetTestcaseBuffer();
  uint64_t GetTestcaseSize();

  //
  // Dump the register & memory deltas for Tenet.
  //

  void DumpTenetDelta(const bool Force = false);

  //
  // LAF/CompCov support.
  //

  static constexpr bool LafCompcovLoggingOn = false;

  template <typename... Args_t>
  void LafCompcovDebugPrint(const char *Format, const Args_t &...args) {
    if constexpr (LafCompcovLoggingOn) {
      fmt::print("laf/compcov: ");
      fmt::print(fmt::runtime(Format), args...);
    }
  }

  //
  // Enum of the Bochs CMP instructions. This should be kept in sync with the
  // Bochs. Handling logic can be found in bochs/cpu/arith32.cpp.
  //

  enum class BochsCmpIns_t : uint32_t {
    //
    // 64-bit comparison instructions.
    //
    BX_IA_CMP_RAXId = 0x491,
    BX_IA_CMP_EqsIb = 0x4a3,
    BX_IA_CMP_EqId = 0x49a, // CMP_EqIdM, CMP_EqIdR
    BX_IA_CMP_GqEq = 0x47f, // CMP_GqEqR, CMP_GqEqM
    BX_IA_CMP_EqGq = 0x488, // CMP_EqGqM

    //
    // 32-bit comparison instructions.
    //
    BX_IA_CMP_EAXId = 0x38,
    BX_IA_CMP_EdsIb = 0x6a,
    BX_IA_CMP_EdId = 0x61, // CMP_EdIdM, CMP_EdIdR
    BX_IA_CMP_GdEd = 0x86, // CMP_GdEdR, CMP_GdEdM
    BX_IA_CMP_EdGd = 0x1d, // CMP_EdGdM

    //
    // 16-bit comparison instructions.
    //
    BX_IA_CMP_AXIw = 0x2f,
    BX_IA_CMP_EwsIb = 0x58,
    BX_IA_CMP_EwIw = 0x4f, // CMP_EwIwM, CMP_EwIwR
    BX_IA_CMP_GwEw = 0x7e, // CMP_GwEwR, CMP_GwEwM
    BX_IA_CMP_EwGw = 0x14, // CMP_EwGwM
  };

  //
  // Converts BochsCmpIns_t to a string.
  //

  std::string_view BochsCmpInsToString(const BochsCmpIns_t Ins);

  //
  // Enum of instruction addressing modes.
  //

  enum class InsAddressingMode_t : uint8_t { Mem = 0, Reg = 16 };

  //
  // Get the addressing mode of a Bochs instruction.
  //

  InsAddressingMode_t BochsInsAddressingMode(bochscpu_instr_t *Ins) {
    uint32_t modc0 = bochscpu_instr_modC0(Ins);
    if (modc0 == 16) {
      return InsAddressingMode_t::Reg;
    } else if (modc0 == 0) {
      return InsAddressingMode_t::Mem;
    }

    throw std::runtime_error("unknown addressing mode");
  }

  //
  // Convert an instruction addressing mode to a string.
  //

  std::string_view
  BochsInsAddressingModeToString(const InsAddressingMode_t Mode) {
    switch (Mode) {
    case InsAddressingMode_t::Mem:
      return "Mem";
    case InsAddressingMode_t::Reg:
      return "Reg";
    }

    return "<unknown>";
  }

  //
  // Operand pair for CMP instructions.
  //

  template <class T> struct OpPair_t {
    T Op1;
    T Op2;
  };

  using OpPair64_t = OpPair_t<uint64_t>;
  using OpPair32_t = OpPair_t<uint32_t>;
  using OpPair16_t = OpPair_t<uint16_t>;

  //
  // Check if a register is a general purpose register.
  //

  bool IsGpReg(uint32_t RegId) { return RegId < bochscpu_total_gpregs(); }

  //
  // Log the result of a CMP instruction.
  //

  template <class T>
  void LafCompcovLogCmpComparison(bochscpu_instr_t *Ins,
                                  std::optional<OpPair_t<T>> Operands) {
    if constexpr (LafCompcovLoggingOn) {
      const Gva_t Rip = Gva_t(bochscpu_cpu_rip(Cpu_));

      //
      // Disassemble the instruction.
      //

      std::array<uint8_t, 128> InstructionBuffer;
      VirtRead(Rip, InstructionBuffer.data(), sizeof(InstructionBuffer));

      std::array<char, 256> DisasmBuffer;
      bochscpu_opcode_disasm(1, 1, 0, 0, InstructionBuffer.data(),
                             DisasmBuffer.data(), DisasmStyle::Intel);
      std::string DisasmString(DisasmBuffer.data());

      //
      // Extract Bochs instruction type and addressing mode.
      //

      std::string_view CmpInstrType = BochsCmpInsToString(
          static_cast<BochsCmpIns_t>(bochscpu_instr_bx_opcode(Ins)));
      std::string_view AddressingMode =
          BochsInsAddressingModeToString(BochsInsAddressingMode(Ins));

      if (!Operands.has_value()) {
        LafCompcovDebugPrint("Extraction failed for comparison : {:#18x} {:46} "
                             "-> {}{}(XXX, XXX)\n",
                             Rip, DisasmString, CmpInstrType, AddressingMode);
        return;
      }

      LafCompcovDebugPrint("Extracted operands for comparison: {:#18x} "
                           "{:46} "
                           "-> {}{}({:#x}, {:#x})\n",
                           Rip, DisasmString, CmpInstrType, AddressingMode,
                           Operands->Op1, Operands->Op2);
    }
  }

  //
  // LAF entry point. Tries to split various types of comparisons into smaller
  // comparisons. (e.g. 64-bit -> 8 x 8-bit, 32-bit -> 4 x 8-bit, etc)
  //

  void LafSplitCompares(bochscpu_instr_t *Ins);

  //
  // Tries to split an integer comparison.
  //

  bool LafTrySplitIntCmp(bochscpu_instr_t *Ins);

  //
  // Extracts immediate operand from a Bochs instruction.
  //

  template <typename T> T LafBochsInstrImm(bochscpu_instr_t *Ins) {
    static_assert(std::is_same<T, uint64_t>::value ||
                      std::is_same<T, uint32_t>::value ||
                      std::is_same<T, uint16_t>::value,
                  "Invalid operand size for LafBochsInstrImm");

    if constexpr (std::is_same<T, uint64_t>::value) {
      return bochscpu_instr_imm64(Ins);
    } else if constexpr (std::is_same<T, uint32_t>::value) {
      return bochscpu_instr_imm32(Ins);
    } else if constexpr (std::is_same<T, uint16_t>::value) {
      return bochscpu_instr_imm16(Ins);
    }
  }

  //
  // Reads a general-purpose register given its ID from the Bochs CPU.
  //

  template <typename T> T LafBochsGetGpReg(GpRegs GpReg) {
    static_assert(std::is_same<T, uint64_t>::value ||
                      std::is_same<T, uint32_t>::value ||
                      std::is_same<T, uint16_t>::value,
                  "Invalid operand size for LafBochsGetGpReg");

    if (!IsGpReg((uint32_t)GpReg)) {
      LafCompcovDebugPrint("Invalid general-purpose register ID {}\n", GpReg);
      throw std::runtime_error("Invalid general-purpose register ID");
    }

    if constexpr (std::is_same<T, uint64_t>::value) {
      return bochscpu_get_reg64(Cpu_, GpReg);
    } else if constexpr (std::is_same<T, uint32_t>::value) {
      return bochscpu_get_reg32(Cpu_, GpReg);
    } else if constexpr (std::is_same<T, uint16_t>::value) {
      return bochscpu_get_reg16(Cpu_, GpReg);
    }
  }

  //
  // Extracts operands for CMP instructions which compare an effective value
  // (memory) with an immediate. (CMP_EqIdM, CMP_EdIdM, CMP_EwIwM)
  //

  template <typename T>
  std::optional<OpPair_t<T>> LafCmpOperands_EIMem(bochscpu_instr_t *Ins) {
    static_assert(std::is_same<T, uint64_t>::value ||
                      std::is_same<T, uint32_t>::value ||
                      std::is_same<T, uint16_t>::value,
                  "Invalid operand size for LafBochsInstrReg");

    OpPair_t<T> Res = {};

    // Extract the first operand (memory location).
    Gva_t Address = Gva_t(bochscpu_instr_resolve_addr(Ins));
    if (!VirtReadStruct(Address, &Res.Op1)) {
      return {};
    }

    // Extract the second operand (immediate)
    Res.Op2 = LafBochsInstrImm<T>(Ins);

    return Res;
  }

  //
  // Extracts operands for CMP instructions which compare an effective value
  // (register) with an immediate. (CMP_EqIdR, CMP_EdIdR, CMP_EwIwR)
  //

  template <typename T>
  std::optional<OpPair_t<T>> LafCmpOperands_EIReg(bochscpu_instr_t *Ins) {
    static_assert(std::is_same<T, uint64_t>::value ||
                      std::is_same<T, uint32_t>::value ||
                      std::is_same<T, uint16_t>::value,
                  "Invalid operand size for LafBochsInstrReg");

    OpPair_t<T> Res = {};
    GpRegs GpReg = (GpRegs)bochscpu_instr_dst(Ins);

    // Extract the first operand (effective value from register).
    Res.Op1 = LafBochsGetGpReg<T>(GpReg);
    // Extract the second operand (immediate)
    Res.Op2 = LafBochsInstrImm<T>(Ins);

    return Res;
  }

  //
  // Generic operands extractor for CMP instructions which compare an effective
  // value with immediate (sign-extended) (either memory or register).
  //

  template <typename T>
  std::optional<OpPair_t<T>> LafCmpOperands_EsI(bochscpu_instr_t *Ins) {
    //
    // Extract operands depending on the addressing mode.
    //

    const InsAddressingMode_t AddrMod = BochsInsAddressingMode(Ins);
    if (AddrMod == InsAddressingMode_t::Mem) {
      return LafCmpOperands_EIMem<T>(Ins);
    } else if (AddrMod == InsAddressingMode_t::Reg) {
      return LafCmpOperands_EIReg<T>(Ins);
    }

    LafCompcovDebugPrint("Invalid AddrMod for CMP_EsI\n");
    return {};
  }

  //
  // Generic operands extractor for CMP instructions which compare an effective
  // value with immediate (either memory or register).
  //

  template <typename T>
  std::optional<OpPair_t<T>> LafCmpOperands_EI(bochscpu_instr_t *Ins) {
    //
    // Extract operands depending on the addressing mode.
    //

    const InsAddressingMode_t AddrMod = BochsInsAddressingMode(Ins);
    if (AddrMod == InsAddressingMode_t::Mem) {
      return LafCmpOperands_EIMem<T>(Ins);
    } else if (AddrMod == InsAddressingMode_t::Reg) {
      return LafCmpOperands_EIReg<T>(Ins);
    }

    LafCompcovDebugPrint("Invalid AddrMod for CMP_EI\n");
    return {};
  }

  //
  // Generic operands extractor for CMP instructions which compare a register
  // (only rax/eax/ax) with an immediate.
  //

  template <typename T>
  std::optional<OpPair_t<T>> LafCmpOperands_REGI(bochscpu_instr_t *Ins) {
    static_assert(std::is_same<T, uint64_t>::value ||
                      std::is_same<T, uint32_t>::value ||
                      std::is_same<T, uint16_t>::value,
                  "Invalid operand size for CMP_REGI");
    return LafCmpOperands_EIReg<T>(Ins);
  }

  //
  // Extracts operands for CMP instructions which compare a general purpose
  // register with an effective value (memory). (CMP_GqEqM, CMP_GdEdM,
  // CMP_GwEwM).
  //

  template <typename T>
  std::optional<OpPair_t<T>> LafCmpOperands_GEMem(bochscpu_instr_t *Ins) {
    static_assert(std::is_same<T, uint64_t>::value ||
                      std::is_same<T, uint32_t>::value ||
                      std::is_same<T, uint16_t>::value,
                  "Invalid operand size for LafBochsInstrReg");

    OpPair_t<T> Res = {};

    // Extract the first operand (general purpose register).
    GpRegs GpReg = (GpRegs)bochscpu_instr_dst(Ins);
    Res.Op1 = LafBochsGetGpReg<T>(GpReg);

    // Extract the second operand from memory.
    Gva_t Address = Gva_t(bochscpu_instr_resolve_addr(Ins));
    if (!VirtReadStruct(Address, &Res.Op2)) {
      return {};
    }

    return Res;
  }

  //
  // Extracts operands for CMP instructions which compare a general purpose
  // register with an effective value (register). (CMP_GqEqR, CMP_GdEdR,
  // CMP_GwEwR).
  //

  template <typename T>
  std::optional<OpPair_t<T>> LafCmpOperands_GEReg(bochscpu_instr_t *Ins) {
    static_assert(std::is_same<T, uint64_t>::value ||
                      std::is_same<T, uint32_t>::value ||
                      std::is_same<T, uint16_t>::value,
                  "Invalid operand size for LafBochsInstrReg");

    OpPair_t<T> Res = {};
    GpRegs GpReg1 = (GpRegs)bochscpu_instr_dst(Ins);
    GpRegs GpReg2 = (GpRegs)bochscpu_instr_src(Ins);

    // Extract the first operand (general purpose register).
    Res.Op1 = LafBochsGetGpReg<T>(GpReg1);
    // Extract the second operand (general purpose register?).
    Res.Op2 = LafBochsGetGpReg<T>(GpReg2);

    return Res;
  }

  //
  // Generic operands extractor for CMP instructions which compare a general
  // purpose register with an effective value (memory or register).
  //

  template <typename T>
  std::optional<OpPair_t<T>> LafCmpOperands_GE(bochscpu_instr_t *Ins) {
    //
    // Extract operands depending on the addressing mode.
    //

    const InsAddressingMode_t AddrMod = BochsInsAddressingMode(Ins);
    if (AddrMod == InsAddressingMode_t::Mem) {
      return LafCmpOperands_GEMem<T>(Ins);
    } else if (AddrMod == InsAddressingMode_t::Reg) {
      return LafCmpOperands_GEReg<T>(Ins);
    }

    LafCompcovDebugPrint("Invalid AddrMod for CMP_GE\n");
    return {};
  }

  //
  // Extracts operands for CMP instructions which compare an effective value
  // (memory) with a general purpose register. (CMP_EqGqM, CMP_EdGdM,
  // CMP_EwGwM).
  //

  template <typename T>
  std::optional<OpPair_t<T>> LafCmpOperands_EG(bochscpu_instr_t *Ins) {
    static_assert(std::is_same<T, uint64_t>::value ||
                      std::is_same<T, uint32_t>::value ||
                      std::is_same<T, uint16_t>::value,
                  "Invalid operand size for LafBochsInstrReg");
    OpPair_t<T> Res = {};

    // Extract the first operand - effective value from memory.
    Gva_t Address = Gva_t(bochscpu_instr_resolve_addr(Ins));
    if (!VirtReadStruct(Address, &Res.Op1)) {
      return {};
    }

    // Extract the second operand - general purpose register.
    GpRegs GpReg = (GpRegs)bochscpu_instr_src(Ins);
    Res.Op2 = LafBochsGetGpReg<T>(GpReg);

    return Res;
  }

  //
  // Comparison operands extraction.
  //

  std::optional<OpPair64_t> LafExtractCmp64BitOperands(bochscpu_instr_t *Ins);
  std::optional<OpPair32_t> LafExtractCmp32BitOperands(bochscpu_instr_t *Ins);
  std::optional<OpPair16_t> LafExtractCmp16BitOperands(bochscpu_instr_t *Ins);

  //
  // LAF handlers for CMP instructions.
  //

  void LafHandle64BitIntCmp(uint64_t Op1, uint64_t Op2);
  void LafHandle32BitIntCmp(uint32_t Op1, uint32_t Op2);
  void LafHandle16BitIntCmp(uint16_t Op1, uint16_t Op2);

  bool LafTrySplitIntSub(bochscpu_instr_t *Ins);
  bool LafTrySplitIntCmpXchg(bochscpu_instr_t *Ins);
};
