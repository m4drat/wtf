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

  //
  // LAF/CompCov support.
  //

  enum class BochsCmpIns_t : uint32_t {
    // 64-bit comparisons.
    // Register <-> Immediate doubleword.
    BX_IA_CMP_RAXId = 0x491,
    // Effective quadword <-> Immediate byte sign-extended to quadword.
    BX_IA_CMP_EqsIb = 0x4a3,
    // Effective quadword <-> Immediate doubleword.
    BX_IA_CMP_EqId = 0x49a,
    // Register <-> Effective quadword.
    BX_IA_CMP_GqEq = 0x47f,
    // Effective quadword <-> Register.
    BX_IA_CMP_EqGq = 0x488,

    // 32-bit comparisons.
    BX_IA_CMP_EAXId = 0x38,
    BX_IA_CMP_EdsIb = 0x6a,
    BX_IA_CMP_EdId = 0x61,
    BX_IA_CMP_GdEd = 0x86,
    BX_IA_CMP_EdGd = 0x1d,

    // 16-bit comparisons.
    BX_IA_CMP_AXIw = 0x2f,
    BX_IA_CMP_EwsIb = 0x58,
    BX_IA_CMP_EwIw = 0x4f,
    BX_IA_CMP_GwEw = 0x7e,
    BX_IA_CMP_EwGw = 0x14,
  };

  template <class T> struct OpPair_t {
    T Op1;
    T Op2;
  };

  using OpPair64_t = OpPair_t<uint64_t>;
  using OpPair32_t = OpPair_t<uint32_t>;
  using OpPair16_t = OpPair_t<uint16_t>;

  void LafSplitCompares(bochscpu_instr_t *Ins);

  bool LafTrySplitIntCmp(bochscpu_instr_t *Ins);

  template <typename T> OpPair_t<T> LafCmpOperands_REGI(bochscpu_instr_t *Ins) {
    OpPair_t<T> Res = {};
    if constexpr (std::is_same<T, uint64_t>::value) {
    } else if constexpr (std::is_same<T, uint32_t>::value) {
    } else if constexpr (std::is_same<T, uint16_t>::value) {
    } else {
      throw std::runtime_error("Invalid operand size for CMP_REGI?!");
    }

    return Res;
  }

  template <typename T> OpPair_t<T> LafCmpOperands_EsI(bochscpu_instr_t *Ins) {
    OpPair_t<T> Res = {};
    if constexpr (std::is_same<T, uint64_t>::value) {
      // BX_CPU_C::CMP_EqIdR
      Res.Op1 = bochscpu_get_reg64(Cpu_, bochscpu_instr_dst(Ins));
      Res.Op2 = bochscpu_instr_imm64(Ins);
    } else if constexpr (std::is_same<T, uint32_t>::value) {
      // BX_CPU_C::CMP_EdIdR
      Res.Op1 = bochscpu_get_reg32(Cpu_, bochscpu_instr_dst(Ins));
      Res.Op2 = bochscpu_instr_imm32(Ins);
    } else if constexpr (std::is_same<T, uint16_t>::value) {
      // BX_CPU_C::CMP_EwIwR
      Res.Op1 = bochscpu_get_reg16(Cpu_, bochscpu_instr_dst(Ins));
      Res.Op2 = bochscpu_instr_imm16(Ins);
    } else {
      throw std::runtime_error("Invalid operand size for CMP_E?sI?!");
    }

    return Res;
  }

  template <typename T> OpPair_t<T> LafCmpOperands_EI(bochscpu_instr_t *Ins) {
    OpPair_t<T> Res = {};
    if constexpr (std::is_same<T, uint64_t>::value) {
    } else if constexpr (std::is_same<T, uint32_t>::value) {
    } else if constexpr (std::is_same<T, uint16_t>::value) {
    } else {
      throw std::runtime_error("Invalid operand size for CMP_E?I?!");
    }

    return Res;
  }

  template <typename T> OpPair_t<T> LafCmpOperands_GE(bochscpu_instr_t *Ins) {
    OpPair_t<T> Res = {};
    if constexpr (std::is_same<T, uint64_t>::value) {
    } else if constexpr (std::is_same<T, uint32_t>::value) {
    } else if constexpr (std::is_same<T, uint16_t>::value) {
    } else {
      throw std::runtime_error("Invalid operand size for CMP_G?E?!");
    }

    return Res;
  }

  template <typename T> OpPair_t<T> LafCmpOperands_EG(bochscpu_instr_t *Ins) {
    OpPair_t<T> Res = {};
    Gva_t Address = Gva_t(bochscpu_instr_resolve_addr(Ins));

    if constexpr (std::is_same<T, uint64_t>::value) {
      // BX_CPU_C::CMP_EqGqM
      Res.Op1 = VirtRead8(Address);
      Res.Op2 = bochscpu_get_reg64(Cpu_, bochscpu_instr_src(Ins));
    } else if constexpr (std::is_same<T, uint32_t>::value) {
      // BX_CPU_C::CMP_EdGdM
      Res.Op1 = VirtRead4(Address);
      Res.Op2 = bochscpu_get_reg64(Cpu_, bochscpu_instr_src(Ins));
    } else if constexpr (std::is_same<T, uint16_t>::value) {
      // BX_CPU_C::CMP_EwGwM
      Res.Op1 = VirtRead2(Address);
      Res.Op2 = bochscpu_get_reg64(Cpu_, bochscpu_instr_src(Ins));
    } else {
      throw std::runtime_error("Invalid operand size for CMP_E?G?!");
    }

    return Res;
  }

  OpPair64_t LafExtract64BitOperands(bochscpu_instr_t *Ins);
  OpPair32_t LafExtract32BitOperands(bochscpu_instr_t *Ins);
  OpPair16_t LafExtract16BitOperands(bochscpu_instr_t *Ins);

  void LafHandle64BitIntCmp(uint64_t Op1, uint64_t Op2);
  void LafHandle32BitIntCmp(uint32_t Op1, uint32_t Op2);
  void LafHandle16BitIntCmp(uint16_t Op1, uint16_t Op2);

  bool LafTrySplitIntSub(bochscpu_instr_t *Ins);
  bool LafTrySplitIntCmpXchg(bochscpu_instr_t *Ins);

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
};
