// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module declares interfaces to VMM functions.
//
#include "stdafx.h"
#include "vmx.h"
#include "log.h"
#include "asm.h"
#include "misc.h"
#include "ia32_type.h"
#include "vmx_type.h"

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

// Represents raw structure of stack of VMM when VmxVmExitHandler() is called
struct VMM_STACK {
  ULONG_PTR r15;
  ULONG_PTR r14;
  ULONG_PTR r13;
  ULONG_PTR r12;
  ULONG_PTR r11;
  ULONG_PTR r10;
  ULONG_PTR r9;
  ULONG_PTR r8;
  ULONG_PTR rdi;
  ULONG_PTR rsi;
  ULONG_PTR rbp;
  ULONG_PTR rsp;
  ULONG_PTR rbx;
  ULONG_PTR rdx;
  ULONG_PTR rcx;
  ULONG_PTR rax;
  ULONG_PTR Reserved;
  PER_PROCESSOR_DATA *ProcessorData;
};

// Things need to be read and written by each VM-exit handler
struct GUEST_CONTEXT {
  union {
    VMM_STACK *Stack;
    GP_REGISTERS *GpRegs;
  };
  EFLAGS Rflags;
  ULONG_PTR Rip;
  ULONG_PTR Cr8;
  KIRQL Irql;
  bool VmContinue;
};
static_assert(sizeof(GUEST_CONTEXT) == 40, "Size check");

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C bool VmxVmExitHandler(_Inout_ VMM_STACK *Stack);

EXTERN_C static void VmxpHandleCpuid(_Inout_ GUEST_CONTEXT *GuestContext);

EXTERN_C static void VmxpHandleRdtsc(_Inout_ GUEST_CONTEXT *GuestContext);

EXTERN_C static void VmxpHandleRdtscp(_Inout_ GUEST_CONTEXT *GuestContext);

EXTERN_C static void VmxpHandleXsetbv(_Inout_ GUEST_CONTEXT *GuestContext);

EXTERN_C static void VmxpHandleMsrReadAccess(
    _Inout_ GUEST_CONTEXT *GuestContext);

EXTERN_C static void VmxpHandleMsrWriteAccess(
    _Inout_ GUEST_CONTEXT *GuestContext);

EXTERN_C static void VmxpHandleMsrAccess(_Inout_ GUEST_CONTEXT *GuestContext,
                                         _In_ bool ReadAccess);

EXTERN_C static void VmxpHandleGdtrOrIdtrAccess(
    _Inout_ GUEST_CONTEXT *GuestContext);

EXTERN_C static void VmxpHandleLdtrOrTrAccess(
    _Inout_ GUEST_CONTEXT *GuestContext);

EXTERN_C static void VmxpHandleDrAccess(_Inout_ GUEST_CONTEXT *GuestContext);

EXTERN_C static void VmxpHandleCrAccess(_Inout_ GUEST_CONTEXT *GuestContext);

EXTERN_C static void VmxpHandleVmx(_Inout_ GUEST_CONTEXT *GuestContext);

EXTERN_C static void VmxpHandleVmCall(_Inout_ GUEST_CONTEXT *GuestContext);

EXTERN_C static void VmxpHandleInvalidateInternalCaches(
    _Inout_ GUEST_CONTEXT *GuestContext);

EXTERN_C static ULONG_PTR *VmxpSelectRegister(_In_ ULONG Index,
                                              _In_ GUEST_CONTEXT *GuestContext);

EXTERN_C static void VmxpDumpGuestSelectors();

EXTERN_C static SIZE_T VmxpVmRead(_In_ SIZE_T Field);

EXTERN_C static VMX_STATUS VmxpVmWrite(_In_ SIZE_T Field,
                                       _In_ SIZE_T FieldValue);

EXTERN_C static void VmxpAdjustGuestInstructionPointer(_In_ ULONG_PTR GuestRip);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// A high level VMX handler called from AsmVmExitHandler().
// Return true for vmresume, or return false for vmxoff.
_Use_decl_annotations_ EXTERN_C bool VmxVmExitHandler(VMM_STACK *Stack) {
  // Raise IRQL as quick as possible
  const auto guestIrql = KeGetCurrentIrql();
  const auto guestCr8 = __readcr8();
  if (guestIrql < DISPATCH_LEVEL) {
    KeRaiseIrqlToDpcLevel();
  }
  NT_ASSERT(Stack->Reserved == 0xffffffffffffffff);

  // Capture the current guest state
  GUEST_CONTEXT guestContext = {Stack,
                                VmxpVmRead(GUEST_RFLAGS),
                                VmxpVmRead(GUEST_RIP),
                                guestCr8,
                                guestIrql,
                                true};
  guestContext.GpRegs->rsp = VmxpVmRead(GUEST_RSP);

  // Dispatch the current VM-exit event
  const VM_EXIT_INFORMATION exitReason = {
      static_cast<ULONG32>(VmxpVmRead(VM_EXIT_REASON))};

  switch (exitReason.Fields.Reason) {
    case EXIT_REASON_CPUID:
      VmxpHandleCpuid(&guestContext);
      break;
    case EXIT_REASON_INVD:
      VmxpHandleInvalidateInternalCaches(&guestContext);
      break;
    case EXIT_REASON_RDTSC:
      VmxpHandleRdtsc(&guestContext);
      break;
    case EXIT_REASON_CR_ACCESS:
      VmxpHandleCrAccess(&guestContext);
      break;
    case EXIT_REASON_DR_ACCESS:
      VmxpHandleDrAccess(&guestContext);
      break;
    case EXIT_REASON_MSR_READ:
      VmxpHandleMsrReadAccess(&guestContext);
      break;
    case EXIT_REASON_MSR_WRITE:
      VmxpHandleMsrWriteAccess(&guestContext);
      break;
    case EXIT_REASON_GDTR_OR_IDTR_ACCESS:
      VmxpHandleGdtrOrIdtrAccess(&guestContext);
      break;
    case EXIT_REASON_LDTR_OR_TR_ACCESS:
      VmxpHandleLdtrOrTrAccess(&guestContext);
      break;
    case EXIT_REASON_VMCALL:
      VmxpHandleVmCall(&guestContext);
      break;
    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMLAUNCH:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMOFF:
    case EXIT_REASON_VMON:
      VmxpHandleVmx(&guestContext);
      break;
    case EXIT_REASON_RDTSCP:
      VmxpHandleRdtscp(&guestContext);
      break;
    case EXIT_REASON_XSETBV:
      VmxpHandleXsetbv(&guestContext);
      break;
    default:
      DBG_BREAK();
      VmxpDumpGuestSelectors();
      break;
  }

  if (guestContext.Irql < DISPATCH_LEVEL) {
    KeLowerIrql(guestContext.Irql);
  }

  // Apply (possibly) updated CR8 by the handler
  __writecr8(guestContext.Cr8);
  return guestContext.VmContinue;
}

// CPUID
_Use_decl_annotations_ EXTERN_C static void VmxpHandleCpuid(
    GUEST_CONTEXT *GuestContext) {
  unsigned int cpuInfo[4] = {};
  const auto functionId = static_cast<int>(GuestContext->GpRegs->rax);
  const auto subFunctionId = static_cast<int>(GuestContext->GpRegs->rcx);

  if (functionId == 0 && subFunctionId == SUSHI_BACKDOOR_CODE) {
    // Say "I love sushi" when the back-door code was given
    GuestContext->GpRegs->rbx = 'ol I';
    GuestContext->GpRegs->rdx = 's ev';
    GuestContext->GpRegs->rcx = 'ihsu';
  } else {
    __cpuidex(reinterpret_cast<int *>(cpuInfo), functionId, subFunctionId);
    GuestContext->GpRegs->rax = cpuInfo[0];
    GuestContext->GpRegs->rbx = cpuInfo[1];
    GuestContext->GpRegs->rcx = cpuInfo[2];
    GuestContext->GpRegs->rdx = cpuInfo[3];
  }

  VmxpAdjustGuestInstructionPointer(GuestContext->Rip);
}

// RDTSC
_Use_decl_annotations_ EXTERN_C static void VmxpHandleRdtsc(
    GUEST_CONTEXT *GuestContext) {
  ULARGE_INTEGER tsc = {};
  tsc.QuadPart = __rdtsc();
  GuestContext->GpRegs->rdx = tsc.HighPart;
  GuestContext->GpRegs->rax =
      tsc.LowPart & 0xffffff00;  // Drop lowest 8 bits for demo

  // Log when the guest is in an interesting address
  if (MiscIsInterestingAddress(GuestContext->Rip)) {
    LOG_DEBUG_SAFE("GuestRip= %p, Rdtsc  => %p", GuestContext->Rip,
                   tsc.QuadPart);
  }
  VmxpAdjustGuestInstructionPointer(GuestContext->Rip);
}

// RDTSCP
_Use_decl_annotations_ EXTERN_C static void VmxpHandleRdtscp(
    GUEST_CONTEXT *GuestContext) {
  unsigned int tscAux = 0;
  ULARGE_INTEGER tsc = {};
  tsc.QuadPart = __rdtscp(&tscAux);
  GuestContext->GpRegs->rdx = tsc.HighPart;
  GuestContext->GpRegs->rax =
      tsc.LowPart & 0xffffff00;  // Drop lowest 8 bits for demo
  GuestContext->GpRegs->rcx = tscAux;

  VmxpAdjustGuestInstructionPointer(GuestContext->Rip);
}

// XSETBV. It is executed at the time of system resuming
_Use_decl_annotations_ EXTERN_C static void VmxpHandleXsetbv(
    GUEST_CONTEXT *GuestContext) {
  AsmXsetbv(static_cast<ULONG>(GuestContext->GpRegs->rcx),
            static_cast<ULONG>(GuestContext->GpRegs->rdx),
            static_cast<ULONG>(GuestContext->GpRegs->rax));

  VmxpAdjustGuestInstructionPointer(GuestContext->Rip);
}

// RDMSR
_Use_decl_annotations_ EXTERN_C static void VmxpHandleMsrReadAccess(
    GUEST_CONTEXT *GuestContext) {
  VmxpHandleMsrAccess(GuestContext, true);
}

// WRMSR
_Use_decl_annotations_ EXTERN_C static void VmxpHandleMsrWriteAccess(
    GUEST_CONTEXT *GuestContext) {
  VmxpHandleMsrAccess(GuestContext, false);
}

// RDMSR and WRMSR
_Use_decl_annotations_ EXTERN_C static void VmxpHandleMsrAccess(
    GUEST_CONTEXT *GuestContext, bool ReadAccess) {
  size_t vmcsField = 0;
  switch (GuestContext->GpRegs->rcx) {
    case IA32_SYSENTER_CS:
      vmcsField = GUEST_SYSENTER_CS;
      break;
    case IA32_SYSENTER_ESP:
      vmcsField = GUEST_SYSENTER_ESP;
      break;
    case IA32_SYSENTER_EIP:
      vmcsField = GUEST_SYSENTER_EIP;
      break;
    case IA32_GS_BASE:
      vmcsField = GUEST_GS_BASE;
      break;
    case IA32_FS_BASE:
      vmcsField = GUEST_FS_BASE;
      break;
    default:
      break;
  }

  // This unconditional __readmsr and __writemsr can cause #GP resulting in bug
  // check. A proper way to solve this is check supported MSR values beforehand
  // and inject an exception when unsupported MSR values are given.
  LARGE_INTEGER msrValue = {};
  if (ReadAccess) {
    if (vmcsField) {
      msrValue.QuadPart = VmxpVmRead(vmcsField);
    } else {
      msrValue.QuadPart =
          __readmsr(static_cast<ULONG>(GuestContext->GpRegs->rcx));
    }
    GuestContext->GpRegs->rax = msrValue.LowPart;
    GuestContext->GpRegs->rdx = msrValue.HighPart;

    // Log when the guest is in an interesting address
    if (MiscIsInterestingAddress(GuestContext->Rip)) {
      LOG_INFO_SAFE("GuestRip= %p, RDMSR(%p)", GuestContext->Rip,
                    GuestContext->GpRegs->rcx);
    }
  } else {
    msrValue.LowPart = static_cast<ULONG>(GuestContext->GpRegs->rax);
    msrValue.HighPart = static_cast<ULONG>(GuestContext->GpRegs->rdx);
    if (vmcsField) {
      VmxpVmWrite(vmcsField, msrValue.QuadPart);
    } else {
      __writemsr(static_cast<ULONG>(GuestContext->GpRegs->rcx),
                 msrValue.QuadPart);
    }
  }

  VmxpAdjustGuestInstructionPointer(GuestContext->Rip);
}

// LIDT, SIDT, LGDT and SGDT
_Use_decl_annotations_ EXTERN_C static void VmxpHandleGdtrOrIdtrAccess(
    GUEST_CONTEXT *GuestContext) {
  const GDTR_OR_IDTR_ACCESS_QUALIFICATION exitQualification = {
      static_cast<ULONG32>(VmxpVmRead(VMX_INSTRUCTION_INFO))};

  NT_ASSERT(exitQualification.Fields.AddressSize != BIT_16);
  NT_ASSERT(exitQualification.Fields.OperandSize == BIT_32);

  // Calculate an address to be used for the instruction
  const auto displacement = VmxpVmRead(EXIT_QUALIFICATION);

  // Base
  ULONG_PTR baseValue = 0;
  if (!exitQualification.Fields.BaseRegisterInvalid) {
    const auto registerUsed =
        VmxpSelectRegister(exitQualification.Fields.BaseRegister, GuestContext);
    baseValue = *registerUsed;
  }

  // Index
  ULONG_PTR indexValue = 0;
  if (!exitQualification.Fields.IndexRegisterInvalid) {
    const auto registerUsed = VmxpSelectRegister(
        exitQualification.Fields.IndexRegister, GuestContext);
    indexValue = *registerUsed;
    switch (exitQualification.Fields.Scalling) {
      // clang-format off
    case NO_SCALING: indexValue = indexValue; break;
    case SCALE_BY_2: indexValue = indexValue * 2; break;
    case SCALE_BY_4: indexValue = indexValue * 4; break;
    case SCALE_BY_8: indexValue = indexValue * 8; break;
    default: break;
        // clang-format on
    }
  }

  auto operationAddress = baseValue + indexValue + displacement;
  if (exitQualification.Fields.AddressSize == BIT_32) {
    operationAddress &= 0xffffffff;
  }

  // Emulate the instruction
  auto descriptorTableReg = reinterpret_cast<IDTR *>(operationAddress);
  switch (exitQualification.Fields.InstructionIdentity) {
    case SGDT:
      descriptorTableReg->Address = VmxpVmRead(GUEST_GDTR_BASE);
      descriptorTableReg->Limit =
          static_cast<unsigned short>(VmxpVmRead(GUEST_GDTR_LIMIT));
      break;
    case SIDT:
      descriptorTableReg->Address = VmxpVmRead(GUEST_IDTR_BASE);
      descriptorTableReg->Limit =
          static_cast<unsigned short>(VmxpVmRead(GUEST_IDTR_LIMIT));
      break;
    case LGDT:
      VmxpVmWrite(GUEST_GDTR_BASE, descriptorTableReg->Address);
      VmxpVmWrite(GUEST_GDTR_LIMIT, descriptorTableReg->Limit);
      break;
    case LIDT:
      VmxpVmWrite(GUEST_IDTR_BASE, descriptorTableReg->Address);
      VmxpVmWrite(GUEST_IDTR_LIMIT, descriptorTableReg->Limit);
      break;
  }

  // Log when the guest is in an interesting address
  if (MiscIsInterestingAddress(GuestContext->Rip)) {
    LOG_INFO_SAFE(
        "GuestRip= %p, %s%sDT(Base=%p, Limit=%04X, at %p)", GuestContext->Rip,
        ((exitQualification.Fields.InstructionIdentity & 2) ? "L" : "S"),
        ((exitQualification.Fields.InstructionIdentity & 1) ? "I" : "G"),
        descriptorTableReg->Address, descriptorTableReg->Limit,
        operationAddress);
  }

  VmxpAdjustGuestInstructionPointer(GuestContext->Rip);
}

// LLDT, LTR, SLDT, and STR
_Use_decl_annotations_ EXTERN_C static void VmxpHandleLdtrOrTrAccess(
    GUEST_CONTEXT *GuestContext) {
  const LDTR_OR_TR_ACCESS_QUALIFICATION exitQualification = {
      static_cast<ULONG32>(VmxpVmRead(VMX_INSTRUCTION_INFO))};

  // Calculate an address or a register to be used for the instruction
  const auto displacement = VmxpVmRead(EXIT_QUALIFICATION);

  ULONG_PTR operationAddress = 0;
  if (exitQualification.Fields.RegisterAccess) {
    // Register
    const auto registerUsed =
        VmxpSelectRegister(exitQualification.Fields.Register1, GuestContext);
    operationAddress = reinterpret_cast<ULONG_PTR>(registerUsed);
  } else {
    // Base
    ULONG_PTR baseValue = 0;
    if (!exitQualification.Fields.BaseRegisterInvalid) {
      const auto registerUsed = VmxpSelectRegister(
          exitQualification.Fields.BaseRegister, GuestContext);
      baseValue = *registerUsed;
    }

    // Index
    ULONG_PTR indexValue = 0;
    if (!exitQualification.Fields.IndexRegisterInvalid) {
      const auto registerUsed = VmxpSelectRegister(
          exitQualification.Fields.IndexRegister, GuestContext);
      indexValue = *registerUsed;
      switch (exitQualification.Fields.Scalling) {
        // clang-format off
      case NO_SCALING: indexValue = indexValue; break;
      case SCALE_BY_2: indexValue = indexValue * 2; break;
      case SCALE_BY_4: indexValue = indexValue * 4; break;
      case SCALE_BY_8: indexValue = indexValue * 8; break;
      default: break;
          // clang-format on
      }
    }

    operationAddress = baseValue + indexValue + displacement;
    if (exitQualification.Fields.AddressSize == BIT_32) {
      operationAddress &= 0xffffffff;
    }
  }

  // Emulate the instruction
  auto selector = reinterpret_cast<USHORT *>(operationAddress);
  switch (exitQualification.Fields.InstructionIdentity) {
    case SLDT:
      *selector = static_cast<USHORT>(VmxpVmRead(GUEST_LDTR_SELECTOR));
      break;
    case STR:
      *selector = static_cast<USHORT>(VmxpVmRead(GUEST_TR_SELECTOR));
      break;
    case LLDT:
      VmxpVmWrite(GUEST_LDTR_SELECTOR, *selector);
      break;
    case LTR:
      VmxpVmWrite(GUEST_TR_SELECTOR, *selector);
      break;
  }

  VmxpAdjustGuestInstructionPointer(GuestContext->Rip);
}

// MOV to / from DRx
_Use_decl_annotations_ EXTERN_C static void VmxpHandleDrAccess(
    GUEST_CONTEXT *GuestContext) {
  const MOV_DR_QUALIFICATION exitQualification = {
      VmxpVmRead(EXIT_QUALIFICATION)};
  const auto registerUsed =
      VmxpSelectRegister(exitQualification.Fields.Register, GuestContext);

  // Log when the guest is in an interesting address
  if (MiscIsInterestingAddress(GuestContext->Rip)) {
    LOG_INFO_SAFE(
        "GuestRip= %p, DR=%d, %s, Register=%2d (%p)", GuestContext->Rip,
        exitQualification.Fields.DebuglRegister,
        ((exitQualification.Fields.Direction == MOVE_TO_DR) ? "Write"
                                                            : "Read "),
        exitQualification.Fields.Register, *registerUsed);
  }

  // Emulate the instruction
  switch (exitQualification.Fields.Direction) {
    case MOVE_TO_DR:
      switch (exitQualification.Fields.DebuglRegister) {
        // clang-format off
        case 0: __writedr(0, *registerUsed); break;
        case 1: __writedr(1, *registerUsed); break;
        case 2: __writedr(2, *registerUsed); break;
        case 3: __writedr(3, *registerUsed); break;
        case 4: __writedr(4, *registerUsed); break;
        case 5: __writedr(5, *registerUsed); break;
        case 6: __writedr(6, *registerUsed); break;
        case 7: __writedr(7, *registerUsed); break;
        default: break;
          // clang-format on
      }
      break;
    case MOVE_FROM_DR:
      switch (exitQualification.Fields.DebuglRegister) {
        // clang-format off
        case 0: *registerUsed = __readdr(0); break;
        case 1: *registerUsed = __readdr(1); break;
        case 2: *registerUsed = __readdr(2); break;
        case 3: *registerUsed = __readdr(3); break;
        case 4: *registerUsed = __readdr(4); break;
        case 5: *registerUsed = __readdr(5); break;
        case 6: *registerUsed = __readdr(6); break;
        case 7: *registerUsed = __readdr(7); break;
        default: break;
          // clang-format on
      }
      break;
    default:
      /* UNREACHABLE */
      DBG_BREAK();
      break;
  }

  VmxpAdjustGuestInstructionPointer(GuestContext->Rip);
}

// MOV to / from CRx
_Use_decl_annotations_ EXTERN_C static void VmxpHandleCrAccess(
    GUEST_CONTEXT *GuestContext) {
  const MOV_CR_QUALIFICATION exitQualification = {
      VmxpVmRead(EXIT_QUALIFICATION)};

  const auto registerUsed =
      VmxpSelectRegister(exitQualification.Fields.Register, GuestContext);

  bool wantToContinue = true;
  switch (exitQualification.Fields.AccessType) {
    case MOVE_TO_CR: {
      switch (exitQualification.Fields.ControlRegister) {
        // CR0 <- Reg
        case 0:
          // Log when the guest is in an interesting address
          if (MiscIsInterestingAddress(GuestContext->Rip)) {
            const CR0_REG cr0current = {VmxpVmRead(GUEST_CR0)};
            const CR0_REG cr0requested = {*registerUsed};
            // And WP is being changed
            if (cr0current.Fields.WP != cr0requested.Fields.WP) {
              LOG_INFO_SAFE("GuestRip= %p, CR0WP Modification %p(%d) -> %p(%d)",
                            GuestContext->Rip, cr0current.All,
                            cr0current.Fields.WP, cr0requested.All,
                            cr0requested.Fields.WP);
              // Stop execution when WP is being enabled and the current context
              // seems to be interesting as well.
              if (!cr0current.Fields.WP && cr0requested.Fields.WP &&
                  MiscIsInterestingContext(GuestContext->GpRegs)) {
                DBG_BREAK();
                wantToContinue = false;
              }
            }
          }
          VmxpVmWrite(GUEST_CR0, *registerUsed);
          VmxpVmWrite(CR0_READ_SHADOW, *registerUsed);
          break;

        // CR3 <- Reg
        case 3:
          // Log when the guest is in an interesting address
          if (MiscIsInterestingAddress(GuestContext->Rip)) {
            // And values of current and requested CR3 are the same
            if (VmxpVmRead(GUEST_CR3) == *registerUsed) {
              LOG_INFO_SAFE("GuestRip= %p, TLB Flush with CR3 %p",
                            GuestContext->Rip, *registerUsed);
            }
          }
          VmxpVmWrite(GUEST_CR3, *registerUsed);
          break;

        // CR4 <- Reg
        case 4:
          // Log when the guest is in an interesting address
          if (MiscIsInterestingAddress(GuestContext->Rip)) {
            const CR4_REG cr4current = {VmxpVmRead(GUEST_CR4)};
            const CR4_REG cr4requested = {*registerUsed};
            // And PGE is being changed
            if (cr4current.Fields.PGE != cr4requested.Fields.PGE) {
              LOG_INFO_SAFE("GuestRip= %p, TLB Flush with CR4 %p(%d) -> %p(%d)",
                            GuestContext->Rip, cr4current.All,
                            cr4current.Fields.PGE, cr4requested.All,
                            cr4requested.Fields.PGE);
            }
          }
          VmxpVmWrite(GUEST_CR4, *registerUsed);
          VmxpVmWrite(CR4_READ_SHADOW, *registerUsed);
          break;

        // CR8 <- Reg
        case 8:
          // Log when the guest is in an interesting address
          if (MiscIsInterestingAddress(GuestContext->Rip)) {
            // And CR8 is being raised to any of certain values
            if (*registerUsed > GuestContext->Cr8 &&
                (*registerUsed == DISPATCH_LEVEL ||
                 *registerUsed == HIGH_LEVEL)) {
              LOG_INFO_SAFE("GuestRip= %p, CR8 %d -> %d", GuestContext->Rip,
                            GuestContext->Cr8, *registerUsed);
            }
          }
          GuestContext->Cr8 = *registerUsed;
          break;

        default:
          /* UNREACHABLE */
          DBG_BREAK();
          break;
      }
    } break;

    // Note that MOV from CRx should never cause VM-exit with the current
    // settings. This is just for case when you enable it.
    case MOVE_FROM_CR: {
      switch (exitQualification.Fields.ControlRegister) {
        // Reg <- CR3
        case 3:
          *registerUsed = VmxpVmRead(GUEST_CR3);
          break;

        // Reg <- CR8
        case 8:
          *registerUsed = GuestContext->Cr8;
          break;

        default:
          /* UNREACHABLE */
          DBG_BREAK();
          break;
      }
    } break;

    // Unimplemented
    case CLTS:
    case LMSW:
    default:
      DBG_BREAK();
      break;
  }

  if (wantToContinue) {
    // Just continue as usual
    VmxpAdjustGuestInstructionPointer(GuestContext->Rip);
  } else {
    //
    // Detected a PatchGuard context and want to stop its execution.
    //
    // Here we assume that the detected PatchGuard context is running on the 2nd
    // validation routine and not the 1st, DPC routine. Since AsmWaitForever()
    // lower IRQL forcibly, calling it from the DPC routine results in bug
    // check.
    //
    // In this PoC project, it does not support termination from the DPC
    // routine,
    // but it is still safe because the DPC routine checks only very critical
    // aspects for PatchGuard itself (such as ExQueueWorkItem() and
    // ExpWorkerThread()), and the demo does not modify any of them, thus, the
    // DPC routine will never detect corruption and modify CR0.
    //
    // If you want to kill the context at the DPC routine, you could disassemble
    // the return address and modify code to let the context return without
    // doing anything devastating.
    //
    VmxpVmWrite(GUEST_RIP, reinterpret_cast<ULONG_PTR>(AsmWaitForever));
  }
}

// VMX instructions except for VMCALL
_Use_decl_annotations_ EXTERN_C static void VmxpHandleVmx(
    GUEST_CONTEXT *GuestContext) {
  // CONVENTIONS
  GuestContext->Rflags.Fields.CF = true;  // Error without status
  GuestContext->Rflags.Fields.PF = false;
  GuestContext->Rflags.Fields.AF = false;
  GuestContext->Rflags.Fields.ZF = false;  // Error without status
  GuestContext->Rflags.Fields.SF = false;
  GuestContext->Rflags.Fields.OF = false;
  VmxpVmWrite(GUEST_RFLAGS, GuestContext->Rflags.All);
  VmxpAdjustGuestInstructionPointer(GuestContext->Rip);
}

// VMCALL
_Use_decl_annotations_ EXTERN_C static void VmxpHandleVmCall(
    GUEST_CONTEXT *GuestContext) {
  // VMCALL for Sushi expects that rcx holds a command number, and rdx holds an
  // address of a context parameter optionally
  const auto hypercallNumber = GuestContext->GpRegs->rcx;
  const auto context = reinterpret_cast<void *>(GuestContext->GpRegs->rdx);

  if (hypercallNumber == SUSHI_BACKDOOR_CODE) {
    // Unloading requested
    DBG_BREAK();

    // The processor sets ffff to limits of IDT and GDT when VM-exit occurred.
    // It is not correct value but fine to ignore since vmresume loads correct
    // values from VMCS. But here, we are going to skip vmresume and simply
    // return to where VMCALL is executed. It results in keeping those broken
    // values and ends up with bug check 109, so we should fix them manually.
    const auto gdtLimit = VmxpVmRead(GUEST_GDTR_LIMIT);
    const auto gdtBase = VmxpVmRead(GUEST_GDTR_BASE);
    const auto idtLimit = VmxpVmRead(GUEST_IDTR_LIMIT);
    const auto idtBase = VmxpVmRead(GUEST_IDTR_BASE);
    GDTR gdtr = {static_cast<USHORT>(gdtLimit), gdtBase};
    IDTR idtr = {static_cast<USHORT>(idtLimit), idtBase};
    __lgdt(&gdtr);
    __lidt(&idtr);

    // Store an address of the management structure to the context parameter
    const auto resultPtr = reinterpret_cast<PER_PROCESSOR_DATA **>(context);
    *resultPtr = GuestContext->Stack->ProcessorData;
    LOG_DEBUG_SAFE("context at %p %p", context,
                   GuestContext->Stack->ProcessorData);

    // Set rip to the next instruction of VMCALL
    const auto exitInstructionLength = VmxpVmRead(VM_EXIT_INSTRUCTION_LEN);
    const auto addressToReturn = GuestContext->Rip + exitInstructionLength;

    // Since rflags is overwritten after VMXOFF, we should manually indicates
    // that VMCALL was successful by clearing those flags.
    GuestContext->Rflags.Fields.CF = false;
    GuestContext->Rflags.Fields.ZF = false;

    // Set registers used after VMXOFF to recover the context
    GuestContext->GpRegs->rcx = addressToReturn;
    GuestContext->GpRegs->rdx = GuestContext->GpRegs->rsp;
    GuestContext->GpRegs->r8 = GuestContext->Rflags.All;
    GuestContext->VmContinue = false;

  } else {
    // Unsupported hypercall. Handle like other VMX instructions
    VmxpHandleVmx(GuestContext);
  }
}

// INVD
_Use_decl_annotations_ EXTERN_C static void VmxpHandleInvalidateInternalCaches(
    GUEST_CONTEXT *GuestContext) {
  AsmInvalidateInternalCaches();
  VmxpAdjustGuestInstructionPointer(GuestContext->Rip);
}

// Selects a register to be used based on the Index
_Use_decl_annotations_ EXTERN_C static ULONG_PTR *VmxpSelectRegister(
    ULONG Index, GUEST_CONTEXT *GuestContext) {
  ULONG_PTR *registerUsed = nullptr;
  switch (Index) {
    // clang-format off
  case 0: registerUsed = &GuestContext->GpRegs->rax; break;
  case 1: registerUsed = &GuestContext->GpRegs->rcx; break;
  case 2: registerUsed = &GuestContext->GpRegs->rdx; break;
  case 3: registerUsed = &GuestContext->GpRegs->rbx; break;
  case 4: registerUsed = &GuestContext->GpRegs->rsp; break;
  case 5: registerUsed = &GuestContext->GpRegs->rbp; break;
  case 6: registerUsed = &GuestContext->GpRegs->rsi; break;
  case 7: registerUsed = &GuestContext->GpRegs->rdi; break;
  case 8: registerUsed = &GuestContext->GpRegs->r8; break;
  case 9: registerUsed = &GuestContext->GpRegs->r9; break;
  case 10: registerUsed = &GuestContext->GpRegs->r10; break;
  case 11: registerUsed = &GuestContext->GpRegs->r11; break;
  case 12: registerUsed = &GuestContext->GpRegs->r12; break;
  case 13: registerUsed = &GuestContext->GpRegs->r13; break;
  case 14: registerUsed = &GuestContext->GpRegs->r14; break;
  case 15: registerUsed = &GuestContext->GpRegs->r15; break;
  default: DBG_BREAK(); break;
      // clang-format on
  }
  return registerUsed;
}

// Dumps guest's selectors
_Use_decl_annotations_ EXTERN_C static void VmxpDumpGuestSelectors() {
  LOG_DEBUG_SAFE("es %04x %p %08x %08x", VmxpVmRead(GUEST_ES_SELECTOR),
                 VmxpVmRead(GUEST_ES_BASE), VmxpVmRead(GUEST_ES_LIMIT),
                 VmxpVmRead(GUEST_ES_AR_BYTES));
  LOG_DEBUG_SAFE("cs %04x %p %08x %08x", VmxpVmRead(GUEST_CS_SELECTOR),
                 VmxpVmRead(GUEST_CS_BASE), VmxpVmRead(GUEST_CS_LIMIT),
                 VmxpVmRead(GUEST_CS_AR_BYTES));
  LOG_DEBUG_SAFE("ss %04x %p %08x %08x", VmxpVmRead(GUEST_SS_SELECTOR),
                 VmxpVmRead(GUEST_SS_BASE), VmxpVmRead(GUEST_SS_LIMIT),
                 VmxpVmRead(GUEST_SS_AR_BYTES));
  LOG_DEBUG_SAFE("ds %04x %p %08x %08x", VmxpVmRead(GUEST_DS_SELECTOR),
                 VmxpVmRead(GUEST_DS_BASE), VmxpVmRead(GUEST_DS_LIMIT),
                 VmxpVmRead(GUEST_DS_AR_BYTES));
  LOG_DEBUG_SAFE("fs %04x %p %08x %08x", VmxpVmRead(GUEST_FS_SELECTOR),
                 VmxpVmRead(GUEST_FS_BASE), VmxpVmRead(GUEST_FS_LIMIT),
                 VmxpVmRead(GUEST_FS_AR_BYTES));
  LOG_DEBUG_SAFE("gs %04x %p %08x %08x", VmxpVmRead(GUEST_GS_SELECTOR),
                 VmxpVmRead(GUEST_GS_BASE), VmxpVmRead(GUEST_GS_LIMIT),
                 VmxpVmRead(GUEST_GS_AR_BYTES));
  LOG_DEBUG_SAFE("ld %04x %p %08x %08x", VmxpVmRead(GUEST_LDTR_SELECTOR),
                 VmxpVmRead(GUEST_LDTR_BASE), VmxpVmRead(GUEST_LDTR_LIMIT),
                 VmxpVmRead(GUEST_LDTR_AR_BYTES));
  LOG_DEBUG_SAFE("tr %04x %p %08x %08x", VmxpVmRead(GUEST_TR_SELECTOR),
                 VmxpVmRead(GUEST_TR_BASE), VmxpVmRead(GUEST_TR_LIMIT),
                 VmxpVmRead(GUEST_TR_AR_BYTES));
}

// A wrapper for vmx_vmread
_Use_decl_annotations_ EXTERN_C static SIZE_T VmxpVmRead(SIZE_T Field) {
  size_t fieldValue = 0;
  const auto vmxStatus =
      static_cast<VMX_STATUS>(__vmx_vmread(Field, &fieldValue));
  if (vmxStatus != VMX_OK) {
    LOG_ERROR_SAFE("__vmx_vmread(0x%08x) failed with an error %d", Field,
                   vmxStatus);
    DBG_BREAK();
  }
  return fieldValue;
}

// A wrapper for vmx_vmwrite
_Use_decl_annotations_ EXTERN_C static VMX_STATUS VmxpVmWrite(
    SIZE_T Field, SIZE_T FieldValue) {
  const auto vmxStatus =
      static_cast<VMX_STATUS>(__vmx_vmwrite(Field, FieldValue));
  if (vmxStatus != VMX_OK) {
    LOG_ERROR_SAFE("__vmx_vmwrite(0x%08x) failed with an error %d", Field,
                   vmxStatus);
    DBG_BREAK();
  }
  return vmxStatus;
}

// Sets rip to the next instruction
_Use_decl_annotations_ EXTERN_C static void VmxpAdjustGuestInstructionPointer(
    ULONG_PTR GuestRip) {
  const auto exitInstructionLength = VmxpVmRead(VM_EXIT_INSTRUCTION_LEN);
  VmxpVmWrite(GUEST_RIP, GuestRip + exitInstructionLength);
}
