// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module defines misc functions.
//
#include "stdafx.h"
#include "misc.h"
#include "log.h"
#include "asm.h"
#include "util.h"

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

struct PgContext {
  UCHAR Reserved1[0xc8];
  ULONG_PTR ExAcquireResourceSharedLite_8;  // + 0xc8
  ULONG_PTR Reserved2;
  ULONG_PTR ExAcquireResourceSharedLite_10;  // + 0xd8 for Windows 10
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C PVOID NTAPI RtlPcToFileHeader(_In_ PVOID PcValue,
                                       _Out_ PVOID *BaseOfImage);

EXTERN_C static PER_PROCESSOR_DATA *MiscpVmCallUnload();

DECLSPEC_NORETURN EXTERN_C void MiscWaitForever(_In_ const ALL_REGISTERS *Regs,
                                                _In_ ULONG_PTR Rsp);

EXTERN_C void MiscDumpGpRegisters(_In_ const ALL_REGISTERS *Regs,
                                  _In_ ULONG_PTR Rsp);

EXTERN_C static bool MiscpIsPgContext(_In_ ULONG_PTR Address);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

// An address of ExAcquireResourceSharedLite. Used to verify the if the address
// is a PatchGuard context.
static ULONG_PTR g_MiscpExAcquireResourceSharedLite = 0;

// Ranges of modules which very frequently causes VM-exit. Used as a quick
// filter to avoid calling RtlPcToFileHeader() too often.
static ULONG_PTR g_MiscpNtosBase = 0;
static ULONG_PTR g_MiscpNtosEnd = 0;
static ULONG_PTR g_MiscpHalBase = 0;
static ULONG_PTR g_MiscpHalEnd = 0;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Initialize misc functions
ALLOC_TEXT(INIT, MiscInitializeRuntimeInfo)
_Use_decl_annotations_ EXTERN_C NTSTATUS MiscInitializeRuntimeInfo() {
  // Solve an address of ExAcquireResourceSharedLite. Note that it is not going
  // to be a real address when DriverVerifier is active in the system.
  UNICODE_STRING procName = RTL_CONSTANT_STRING(L"ExAcquireResourceSharedLite");
  g_MiscpExAcquireResourceSharedLite =
      reinterpret_cast<ULONG_PTR>(MmGetSystemRoutineAddress(&procName));

  // Get a list of system modules currently loaded
  auto status = AuxKlibInitialize();
  if (!NT_SUCCESS(status)) {
    return status;
  }

  ULONG bufferSize = 0;
  status = AuxKlibQueryModuleInformation(
      &bufferSize, sizeof(AUX_MODULE_EXTENDED_INFO), nullptr);
  if (!NT_SUCCESS(status) || !bufferSize) {
    return status;
  }

  bufferSize += (sizeof(AUX_MODULE_EXTENDED_INFO) * 2);
  auto modules = reinterpret_cast<AUX_MODULE_EXTENDED_INFO *>(
      ExAllocatePoolWithTag(PagedPool, bufferSize, SUSHI_POOL_TAG_NAME));
  if (!modules) {
    return STATUS_MEMORY_NOT_ALLOCATED;
  }

  status = AuxKlibQueryModuleInformation(
      &bufferSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
  if (!NT_SUCCESS(status)) {
    goto End;
  }

  // Enumerate the list and get ranges of some modules
  status = STATUS_UNSUCCESSFUL;
  const auto numberOfModules = bufferSize / sizeof(AUX_MODULE_EXTENDED_INFO);
  for (auto i = 0; i < numberOfModules; ++i) {
    const auto currentModule = &modules[i];
    const auto imageName = reinterpret_cast<const char *>(
        currentModule->FullPathName + currentModule->FileNameOffset);
    const auto imageBase =
        reinterpret_cast<ULONG_PTR>(currentModule->BasicInfo.ImageBase);
    LOG_DEBUG("%p - %p : %s", imageBase, imageBase + currentModule->ImageSize,
              imageName);
    if (_stricmp(imageName, "ntoskrnl.exe") == 0) {
      g_MiscpNtosBase = imageBase;
      g_MiscpNtosEnd = imageBase + currentModule->ImageSize;
    } else if (_stricmp(imageName, "hal.dll") == 0) {
      g_MiscpHalBase = imageBase;
      g_MiscpHalEnd = imageBase + currentModule->ImageSize;
    }
    if (g_MiscpNtosBase && g_MiscpHalBase) {
      status = STATUS_SUCCESS;
      break;
    }
  }

End:;
  ExFreePoolWithTag(modules, SUSHI_POOL_TAG_NAME);
  return status;
}

// Allocates continuous physical memory
_Use_decl_annotations_ EXTERN_C void *MiscAllocateContiguousMemory(
    SIZE_T NumberOfBytes) {
  PHYSICAL_ADDRESS highestAcceptableAddress = {};
  highestAcceptableAddress.QuadPart = -1;
  return MmAllocateContiguousMemory(NumberOfBytes, highestAcceptableAddress);
}

// Frees an address allocated by MiscAllocateContiguousMemory()
_Use_decl_annotations_ EXTERN_C void MiscFreeContiguousMemory(
    void *BaseAddress) {
  MmFreeContiguousMemory(BaseAddress);
}

// Stops virtualization through a hypercall and frees all related memory
_Use_decl_annotations_ EXTERN_C NTSTATUS MiscStopVM(void *Context) {
  UNREFERENCED_PARAMETER(Context);

  LOG_INFO("Terminating VMX for the processor %d",
           KeGetCurrentProcessorNumber());

  // Stop virtualization and get an address of the management structure
  auto ProcessorData = MiscpVmCallUnload();
  if (!ProcessorData) {
    return STATUS_UNSUCCESSFUL;
  }

  // Frees all related memory
  if (ProcessorData->MsrBitmap) {
    MiscFreeContiguousMemory(ProcessorData->MsrBitmap);
  }
  if (ProcessorData->VmmStackTop) {
    MiscFreeContiguousMemory(ProcessorData->VmmStackTop);
  }
  if (ProcessorData->VmcsRegion) {
    MiscFreeContiguousMemory(ProcessorData->VmcsRegion);
  }
  if (ProcessorData->VmxonRegion) {
    MiscFreeContiguousMemory(ProcessorData->VmxonRegion);
  }
  if (ProcessorData) {
    ExFreePoolWithTag(ProcessorData, SUSHI_POOL_TAG_NAME);
  }

  return STATUS_SUCCESS;
}

// Stops virtualization through a hypercall and returns an address of the
// management structure
_Use_decl_annotations_ EXTERN_C static PER_PROCESSOR_DATA *MiscpVmCallUnload() {
  PER_PROCESSOR_DATA *context = nullptr;
  auto status = MiscVmCall(SUSHI_BACKDOOR_CODE, &context);
  if (!NT_SUCCESS(status)) {
    return nullptr;
  }
  return context;
}

// Executes VMCALL
_Use_decl_annotations_ EXTERN_C NTSTATUS MiscVmCall(ULONG_PTR HyperCallNumber,
                                                    void *Context) {
  __try {
    const auto vmxStatus = AsmVmxCall(HyperCallNumber, Context);
    return (vmxStatus == VMX_OK) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    const auto status = GetExceptionCode();
    DBG_BREAK();
    return status;
  }
}

// Checks if the Address is out of any kernel modules. Beware that this is not
// comprehensive check to detect all possible patterns of the interesting things
// 
_Use_decl_annotations_ EXTERN_C bool MiscIsInterestingAddress(
    ULONG_PTR Address) {
  if (Address >= reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) &&
      !UtilIsInBounds(Address, g_MiscpNtosBase, g_MiscpNtosEnd) &&
      !UtilIsInBounds(Address, g_MiscpHalBase, g_MiscpHalEnd)) {
    void *base = nullptr;
    if (!RtlPcToFileHeader(reinterpret_cast<void *>(Address), &base)) {
      return true;
    }
  }
  return false;
}

// Wait forever in order to disable this PatchGuard context.
// Note that this function should not be executed from the first validation
// routine that runs as DPC. Since DPC routine cannot lower IRQL, execution of
// this routine results in bug check.
_Use_decl_annotations_ EXTERN_C void MiscWaitForever(const ALL_REGISTERS *Regs,
                                                     ULONG_PTR Rsp) {
  UNREFERENCED_PARAMETER(Regs);
  UNREFERENCED_PARAMETER(Rsp);

  LOG_INFO_SAFE(
      "I got tired of protecting your system and want to sleep. Bye.");
  DBG_BREAK();

#pragma warning(push)
#pragma warning(disable : 28138)
  // The constant argument should instead be variable	The constant argument
  // '0' should instead be variable.
  KeLowerIrql(PASSIVE_LEVEL);
#pragma warning(push)

  // Wait until this thread ends == never returns
  auto status = KeWaitForSingleObject(PsGetCurrentThread(), Executive,
                                      KernelMode, FALSE, nullptr);

  LOG_ERROR_SAFE("Oops!! %p", status);
  DBG_BREAK();
}

_Use_decl_annotations_ EXTERN_C void MiscDumpGpRegisters(
    const ALL_REGISTERS *Regs, ULONG_PTR Rsp) {
  auto currentIrql = KeGetCurrentIrql();
  if (currentIrql < DISPATCH_LEVEL) {
    KeRaiseIrqlToDpcLevel();
  }

  LOG_DEBUG_SAFE(
      "%p "
      "rax= %p rbx= %p rcx= %p "
      "rdx= %p rsi= %p rdi= %p "
      "rsp= %p rbp= %p "
      " r8= %p  r9= %p r10= %p "
      "r11= %p r12= %p r13= %p "
      "r14= %p r15= %p efl= %08x",
      _ReturnAddress(), Regs->rax, Regs->rbx, Regs->rcx, Regs->rdx, Regs->rsi,
      Regs->rdi, Rsp, Regs->rbp, Regs->r8, Regs->r9, Regs->r10, Regs->r11,
      Regs->r12, Regs->r13, Regs->r14, Regs->r15, Regs->rflags.All);

  if (currentIrql < DISPATCH_LEVEL) {
    KeLowerIrql(currentIrql);
  }
}

// Checks if the context have a reference to the PatchGuard context.
_Use_decl_annotations_ EXTERN_C bool MiscIsInterestingContext(
    const GP_REGISTERS *Regs) {
  if (MiscpIsPgContext(Regs->rax) || MiscpIsPgContext(Regs->rbx) ||
      MiscpIsPgContext(Regs->rcx) || MiscpIsPgContext(Regs->rdx) ||
      MiscpIsPgContext(Regs->r9) || MiscpIsPgContext(Regs->r10) ||
      MiscpIsPgContext(Regs->r11) || MiscpIsPgContext(Regs->r12) ||
      MiscpIsPgContext(Regs->r13) || MiscpIsPgContext(Regs->r14) ||
      MiscpIsPgContext(Regs->r15) || MiscpIsPgContext(Regs->rbp) ||
      MiscpIsPgContext(Regs->rdi) || MiscpIsPgContext(Regs->rsi)) {
    return true;
  }
  return false;
}

// Checks if the Address is the PatchGuard context
_Use_decl_annotations_ EXTERN_C static bool MiscpIsPgContext(
    ULONG_PTR Address) {
  const auto pExAcquireResourceSharedLite = g_MiscpExAcquireResourceSharedLite;
  const auto pgContext = reinterpret_cast<PgContext *>(Address);
  if (UtilIsAccessibleAddress(&pgContext->ExAcquireResourceSharedLite_8) &&
      pgContext->ExAcquireResourceSharedLite_8 ==
          pExAcquireResourceSharedLite) {
    LOG_INFO_SAFE("PatchGuard Context = %p", Address);
    return true;
  }
  if (UtilIsAccessibleAddress(&pgContext->ExAcquireResourceSharedLite_10) &&
      pgContext->ExAcquireResourceSharedLite_10 ==
          pExAcquireResourceSharedLite) {
    LOG_INFO_SAFE("PatchGuard Context = %p", Address);
    return true;
  }

  return false;
}
