// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module defines utility functions.
//
#include "stdafx.h"
#include "util.h"

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

// Masks to select bits used for getting PTEs.
#ifdef _AMD64_
static const auto UTILP_PXI_MASK = 0x1ff;
static const auto UTILP_PPI_MASK = 0x3ffff;
static const auto UTILP_PDI_MASK = 0x7ffffff;
static const auto UTILP_PTI_MASK = 0xfffffffff;
#else
static const auto UTILP_PDI_MASK = 0xffffffff;
static const auto UTILP_PTI_MASK = 0xffffffff;
#endif

#if defined(_AMD64_) && !defined(PXE_BASE)
#define PXE_BASE 0xFFFFF6FB7DBED000UI64
#define PXE_SELFMAP 0xFFFFF6FB7DBEDF68UI64
#define PPE_BASE 0xFFFFF6FB7DA00000UI64
#define PDE_BASE 0xFFFFF6FB40000000UI64
#define PTE_BASE 0xFFFFF68000000000UI64

#define PXE_TOP 0xFFFFF6FB7DBEDFFFUI64
#define PPE_TOP 0xFFFFF6FB7DBFFFFFUI64
#define PDE_TOP 0xFFFFF6FB7FFFFFFFUI64
#define PTE_TOP 0xFFFFF6FFFFFFFFFFUI64

#define PDE_KTBASE_AMD64 PPE_BASE

#define PTI_SHIFT 12
#define PDI_SHIFT 21
#define PPI_SHIFT 30
#define PXI_SHIFT 39
#endif

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct WINDOWS_RT_PTE {
  ULONG NoExecute : 1;
  ULONG Present : 1;
  ULONG Unknown1 : 5;
  ULONG Writable : 1;
  ULONG Unknown2 : 4;
  ULONG PageFrameNumber : 20;
};
static_assert(sizeof(WINDOWS_RT_PTE) == 4, "Size check");

struct WINDOWS_AMD64_PTE {
  ULONG64 Present : 1;
  ULONG64 Write : 1;
  ULONG64 Owner : 1;
  ULONG64 WriteThrough : 1;
  ULONG64 CacheDisable : 1;
  ULONG64 Accessed : 1;
  ULONG64 Dirty : 1;
  ULONG64 LargePage : 1;
  ULONG64 Global : 1;
  ULONG64 CopyOnWrite : 1;
  ULONG64 Prototype : 1;
  ULONG64 reserved0 : 1;
  ULONG64 PageFrameNumber : 28;
  ULONG64 reserved1 : 12;
  ULONG64 SoftwareWsIndex : 11;
  ULONG64 NoExecute : 1;
};
static_assert(sizeof(WINDOWS_AMD64_PTE) == 8, "Size check");

#ifdef _AMD64_
using HARDWARE_PTE = WINDOWS_AMD64_PTE;
#else
using HARDWARE_PTE = WINDOWS_RT_PTE;
#endif

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C void NTAPI KeSweepIcacheRange(_In_ BOOLEAN AllProcessors,
                                       _In_ PVOID BaseAddress,
                                       _In_ ULONG Length);

#ifdef _AMD64_
EXTERN_C static HARDWARE_PTE *UtilpAddressToPxe(_In_ const void *Address);

EXTERN_C static HARDWARE_PTE *UtilpAddressToPpe(_In_ const void *Address);
#endif

EXTERN_C static HARDWARE_PTE *UtilpAddressToPde(_In_ const void *Address);

EXTERN_C static HARDWARE_PTE *UtilpAddressToPte(_In_ const void *Address);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Execute a given callback routine on all processors in DPC_LEVEL. Returns
// STATUS_SUCCESS when all callback returned STATUS_SUCCESS as well. When
// one of callbacks returns anything but STATUS_SUCCESS, this function stops
// to call remaining callbacks and returns the value.
_Use_decl_annotations_ EXTERN_C NTSTATUS
UtilForEachProcessor(NTSTATUS (*CallbackRoutine)(void *), void *Context) {
  const auto numberOfProcessors = KeQueryActiveProcessorCount(nullptr);
  for (ULONG processorNumber = 0; processorNumber < numberOfProcessors;
       processorNumber++) {
    // Switch the current processor
    const auto oldAffinity = KeSetSystemAffinityThreadEx(
        static_cast<KAFFINITY>(1ull << processorNumber));
    const auto oldIrql = KeRaiseIrqlToDpcLevel();

    // Execute callback
    const auto status = CallbackRoutine(Context);

    KeLowerIrql(oldIrql);
    KeRevertToUserAffinityThreadEx(oldAffinity);
    if (!NT_SUCCESS(status)) {
      return status;
    }
  }
  return STATUS_SUCCESS;
}

// Sleep the current thread's execution for Millisecond milli-seconds.
ALLOC_TEXT(PAGED, UtilSleep)
_Use_decl_annotations_ EXTERN_C NTSTATUS UtilSleep(LONG Millisecond) {
  PAGED_CODE();

  LARGE_INTEGER interval = {};
  interval.QuadPart = -(10000 * Millisecond);  // msec
  return KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

// memmem().
_Use_decl_annotations_ EXTERN_C void *UtilMemMem(const void *SearchBase,
                                                 SIZE_T SearchSize,
                                                 const void *Pattern,
                                                 SIZE_T PatternSize) {
  if (PatternSize > SearchSize) {
    return nullptr;
  }
  auto searchBase = static_cast<const char *>(SearchBase);
  for (size_t i = 0; i <= SearchSize - PatternSize; i++) {
    if (!memcmp(Pattern, &searchBase[i], PatternSize)) {
      return const_cast<char *>(&searchBase[i]);
    }
  }
  return nullptr;
}

// Invalidates an instruction cache for the specified region.
_Use_decl_annotations_ EXTERN_C void UtilInvalidateInstructionCache(
    void *BaseAddress, SIZE_T Length) {
#ifdef _AMD64_
  UNREFERENCED_PARAMETER(BaseAddress);
  UNREFERENCED_PARAMETER(Length);
  __faststorefence();
#else
  KeSweepIcacheRange(TRUE, BaseAddress, Length);
#endif
}

// Does memcpy safely even if Destination is a read only region.
_Use_decl_annotations_ EXTERN_C NTSTATUS UtilForceMemCpy(void *Destination,
                                                         const void *Source,
                                                         SIZE_T Length) {
  auto mdl = IoAllocateMdl(Destination, static_cast<ULONG>(Length), FALSE,
                           FALSE, nullptr);
  if (!mdl) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  MmBuildMdlForNonPagedPool(mdl);

#pragma warning(push)
#pragma warning(disable : 28145)
  //
  // Following MmMapLockedPagesSpecifyCache() call causes bug check in case
  // you are using Driver Verifier. The reason is explained as follows:
  //
  // A driver must not try to create more than one system-address-space
  // mapping for an MDL. Additionally, because an MDL that is built by the
  // MmBuildMdlForNonPagedPool routine is already mapped to the system
  // address space, a driver must not try to map this MDL into the system
  // address space again by using the MmMapLockedPagesSpecifyCache routine.
  // -- MSDN
  //
  // This flag modification hacks Driver Verifier's check and prevent leading
  // bug check.
  //
  mdl->MdlFlags &= ~MDL_SOURCE_IS_NONPAGED_POOL;
  mdl->MdlFlags |= MDL_PAGES_LOCKED;
#pragma warning(pop)

  auto writableDest = MmMapLockedPagesSpecifyCache(
      mdl, KernelMode, MmCached, nullptr, FALSE, NormalPagePriority);
  if (!writableDest) {
    IoFreeMdl(mdl);
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  memcpy(writableDest, Source, Length);
  MmUnmapLockedPages(writableDest, mdl);
  IoFreeMdl(mdl);
  return STATUS_SUCCESS;
}

// Return true if the given address is accessible. It does not prevent a race
// condition.
_Use_decl_annotations_ EXTERN_C bool UtilIsAccessibleAddress(
    const void *Address) {
#ifdef _AMD64_
  const auto pxe = UtilpAddressToPxe(Address);
  const auto ppe = UtilpAddressToPpe(Address);
  const auto pde = UtilpAddressToPde(Address);
  const auto pte = UtilpAddressToPte(Address);
  if ((!pxe->Present) || (!ppe->Present) || (!pde->Present) ||
      (!pde->LargePage && (!pte || !pte->Present))) {
    return false;
  }
#else
  const auto pde = UtilpAddressToPde(Address);
  const auto pte = UtilpAddressToPte(Address);
  if (!pde->Present || !pde->PageFrameNumber || !pte->Present ||
      !pte->PageFrameNumber) {
    return false;
  }
#endif
  return true;
}

/*
Virtual Address Interpretation For Handling PTEs

-- On x64
Sign extension                     16 bits
Page map level 4 selector           9 bits
Page directory pointer selector     9 bits
Page directory selector             9 bits
Page table selector                 9 bits
Byte within page                   12 bits
11111111 11111111 11111000 10000000 00000011 01010011 00001010 00011000
^^^^^^^^ ^^^^^^^^ ~~~~~~~~ ~^^^^^^^ ^^~~~~~~ ~~~^^^^^ ^^^^~~~~ ~~~~~~~~
Sign extension    PML4      PDPT      PD        PT        Offset

-- On ARM
Page directory selector            10 bits
Page table selector                10 bits
Byte within page                   12 bits
10000011 01100000 11010010 01110101
~~~~~~~~ ~~^^^^^^ ^^^^~~~~ ~~~~~~~~
PD         PT         Offset

*/

#ifdef _AMD64_

// Return an address of PXE
_Use_decl_annotations_ EXTERN_C static HARDWARE_PTE *UtilpAddressToPxe(
    const void *Address) {
  const auto addr = reinterpret_cast<ULONG_PTR>(Address);
  const auto index = (addr >> PXI_SHIFT) & UTILP_PXI_MASK;
  const auto offset = index * sizeof(HARDWARE_PTE);
  return reinterpret_cast<HARDWARE_PTE *>(PXE_BASE + offset);
}

// Return an address of PPE
_Use_decl_annotations_ EXTERN_C static HARDWARE_PTE *UtilpAddressToPpe(
    const void *Address) {
  const auto addr = reinterpret_cast<ULONG_PTR>(Address);
  const auto index = (addr >> PPI_SHIFT) & UTILP_PPI_MASK;
  const auto offset = index * sizeof(HARDWARE_PTE);
  return reinterpret_cast<HARDWARE_PTE *>(PPE_BASE + offset);
}

#endif

// Return an address of PDE
_Use_decl_annotations_ EXTERN_C static HARDWARE_PTE *UtilpAddressToPde(
    const void *Address) {
  const auto addr = reinterpret_cast<ULONG_PTR>(Address);
  const auto index = (addr >> PDI_SHIFT) & UTILP_PDI_MASK;
  const auto offset = index * sizeof(HARDWARE_PTE);
  return reinterpret_cast<HARDWARE_PTE *>(PDE_BASE + offset);
}

// Return an address of PTE
_Use_decl_annotations_ EXTERN_C static HARDWARE_PTE *UtilpAddressToPte(
    const void *Address) {
  const auto addr = reinterpret_cast<ULONG_PTR>(Address);
  const auto index = (addr >> PTI_SHIFT) & UTILP_PTI_MASK;
  const auto offset = index * sizeof(HARDWARE_PTE);
  return reinterpret_cast<HARDWARE_PTE *>(PTE_BASE + offset);
}