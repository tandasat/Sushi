// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements an entry point of the driver.
//
#include "stdafx.h"
#include "ia32_type.h"
#include "vmx_type.h"
#include "vminit.h"
#include "misc.h"
#include "util.h"
#include "log.h"
#include "asm.h"

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

static const wchar_t SUSHIP_LOG_FILE_PATH[] = L"\\SystemRoot\\Sushi.log";

#if DBG
static const auto SUSHIP_LOG_LEVEL =
    LOG_PUT_LEVEL_DEBUG | LOG_OPT_DISABLE_FUNCTION_NAME;
#else
static const auto SUSHIP_LOG_LEVEL =
    LOG_PUT_LEVEL_INFO | LOG_OPT_DISABLE_FUNCTION_NAME;
#endif

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C DRIVER_INITIALIZE DriverEntry;

EXTERN_C static DRIVER_UNLOAD SushipDriverUnload;

EXTERN_C static KSTART_ROUTINE SushipVmxOffThreadRoutine;

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

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
  DriverObject->DriverUnload = SushipDriverUnload;

  DBG_BREAK();

  status = LogInitialization(SUSHIP_LOG_LEVEL, SUSHIP_LOG_FILE_PATH,
                             DriverObject, nullptr);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = MiscInitializeRuntimeInfo();
  if (!NT_SUCCESS(status)) {
    LogTermination();
    return status;
  }

  status = UtilForEachProcessor(VminitStartVM, nullptr);
  if (!NT_SUCCESS(status)) {
    UtilForEachProcessor(MiscStopVM, nullptr);
    LogTermination();
    return status;
  }

  LOG_INFO("The VMM was installed.");
  return status;
}

ALLOC_TEXT(PAGED, SushipDriverUnload)
_Use_decl_annotations_ EXTERN_C static void SushipDriverUnload(
    PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);
  PAGED_CODE();

  DBG_BREAK();
  HANDLE threadHandle = nullptr;
  auto status =
      PsCreateSystemThread(&threadHandle, GENERIC_ALL, nullptr, nullptr,
                           nullptr, SushipVmxOffThreadRoutine, nullptr);
  if (NT_SUCCESS(status)) {
    status = ZwWaitForSingleObject(threadHandle, FALSE, nullptr);
    status = ZwClose(threadHandle);
  } else {
    DBG_BREAK();
  }
  LogTermination();
}

ALLOC_TEXT(PAGED, SushipVmxOffThreadRoutine)
_Use_decl_annotations_ EXTERN_C static VOID SushipVmxOffThreadRoutine(
    void* StartContext) {
  UNREFERENCED_PARAMETER(StartContext);
  PAGED_CODE();
  LOG_INFO("Uninstalling VMM.");
  auto status = UtilForEachProcessor(MiscStopVM, nullptr);
  LOG_INFO("The VMM was uninstalled.");

  PsTerminateSystemThread(status);
}
