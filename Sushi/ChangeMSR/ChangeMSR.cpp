// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements a demo of MSR moditication to triggar PatchGuard crash
//
#include "stdafx.h"
#include "../Sushi/ia32_type.h"
#include "../Sushi/log.h"
#include "../Sushi/util.h"

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

static const ULONG POOL_TAG_NAME = ' RSM';

#if DBG
static const auto LOG_LEVEL =
    LOG_PUT_LEVEL_DEBUG | LOG_OPT_DISABLE_FUNCTION_NAME;
#else
static const auto LOG_LEVEL =
    LOG_PUT_LEVEL_INFO | LOG_OPT_DISABLE_FUNCTION_NAME;
#endif

////////////////////////////////////////////////////////////////////////////////
//
// types
//

#include <pshpack1.h>
struct JMP_CODE {
  UCHAR jmp[6];
  ULONG_PTR address;
};
static_assert(sizeof(JMP_CODE) == 14, "Size check");
#include <poppack.h>

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C DRIVER_INITIALIZE DriverEntry;

EXTERN_C static DRIVER_UNLOAD DriverUnload;

EXTERN_C static NTSTATUS MsrHookCallback(_In_opt_ void* Context);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static UCHAR* g_Trampoline = nullptr;
static ULONG_PTR g_MSRs[64] = {};

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Entry point
ALLOC_TEXT(INIT, DriverEntry)
_Use_decl_annotations_ EXTERN_C NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);
  PAGED_CODE();

  auto status = STATUS_UNSUCCESSFUL;
  DriverObject->DriverUnload = DriverUnload;

  DBG_BREAK();

  status = LogInitialization(LOG_LEVEL, nullptr, DriverObject, nullptr);
  if (!NT_SUCCESS(status)) {
    ExFreePoolWithTag(g_Trampoline, POOL_TAG_NAME);
  }

  // Build the following code as a SYSENTER handler on NonPagedPool
  //
  // FF 25 00 00 00 00                       jmp     cs:jmp_address
  // FF FF FF FF FF FF FF FF jmp_address     dq 0FFFFFFFFFFFFFFFFh
  const JMP_CODE jmpCode = {{0xff, 0x25}, __readmsr(IA32_LSTAR)};

  g_Trampoline = reinterpret_cast<UCHAR*>(ExAllocatePoolWithTag(
      NonPagedPoolExecute, sizeof(jmpCode), POOL_TAG_NAME));
  if (!g_Trampoline) {
    LogTermination();
    return STATUS_MEMORY_NOT_ALLOCATED;
  }
  RtlCopyMemory(g_Trampoline, &jmpCode, sizeof(jmpCode));

  // Modify MSR
  UtilForEachProcessor(MsrHookCallback, nullptr);
  return status;
}

ALLOC_TEXT(PAGED, DriverUnload)
_Use_decl_annotations_ EXTERN_C static void DriverUnload(
    PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);
  PAGED_CODE();

  DBG_BREAK();

  // Restore MSR
  UtilForEachProcessor(MsrHookCallback, nullptr);
  ExFreePoolWithTag(g_Trampoline, POOL_TAG_NAME);
  LogTermination();
}

// Modify or restore MSR
_Use_decl_annotations_ EXTERN_C static NTSTATUS MsrHookCallback(void* Context) {
  UNREFERENCED_PARAMETER(Context);

  auto oldmsr = &g_MSRs[KeGetCurrentProcessorNumber()];
  if (*oldmsr == 0) {
    // Modify
    *oldmsr = __readmsr(IA32_LSTAR);
    __writemsr(IA32_LSTAR, reinterpret_cast<ULONG_PTR>(g_Trampoline));
    LOG_INFO("MSR(%08x) %p => %p", IA32_LSTAR, *oldmsr, g_Trampoline);
  } else {
    // Restore
    __writemsr(IA32_LSTAR, *oldmsr);
    LOG_INFO("MSR(%08x) %p => %p", IA32_LSTAR, g_Trampoline, *oldmsr);
  }
  return STATUS_SUCCESS;
}
