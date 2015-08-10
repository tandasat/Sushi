// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements an entry point of the driver.
//
#include "stdafx.h"
#include "log.h"
#include "vminit.h"
#include "misc.h"
#include "util.h"

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

  // Initialize log functions
  bool needReinitialization = false;
  status = LogInitialization(SUSHIP_LOG_LEVEL, SUSHIP_LOG_FILE_PATH);
  if (status == STATUS_REINITIALIZATION_NEEDED) {
    needReinitialization = true;
  } else if (!NT_SUCCESS(status)) {
    return status;
  }

  // Initialize misc functions
  status = MiscInitializeRuntimeInfo();
  if (!NT_SUCCESS(status)) {
    LogTermination();
    return status;
  }

  // Virtualize all processors
  status = UtilForEachProcessor(VminitStartVM, nullptr);
  if (!NT_SUCCESS(status)) {
    UtilForEachProcessor(MiscStopVM, nullptr);
    LogTermination();
    return status;
  }

  // Register re-initialization for the log functions if needed
  if (needReinitialization) {
    LogRegisterReinitialization(DriverObject);
  }

  LOG_INFO("The VMM has been installed.");
  return status;
}

// Unload handler
ALLOC_TEXT(PAGED, SushipDriverUnload)
_Use_decl_annotations_ EXTERN_C static void SushipDriverUnload(
    PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);
  PAGED_CODE();

  DBG_BREAK();

  // Create a thread dedicated to de-virtualizing processors. For some reasons,
  // de-virtualizing processors from this thread makes the system stop
  // processing all timer related events and functioning properly.
  HANDLE threadHandle = nullptr;
  auto status =
      PsCreateSystemThread(&threadHandle, GENERIC_ALL, nullptr, nullptr,
                           nullptr, SushipVmxOffThreadRoutine, nullptr);
  if (NT_SUCCESS(status)) {
    // Wait until the thread ends its work.
    status = ZwWaitForSingleObject(threadHandle, FALSE, nullptr);
    status = ZwClose(threadHandle);
  } else {
    DBG_BREAK();
  }

  // Terminates the log functions
  LogTermination();
}

// De-virtualizing all processors
ALLOC_TEXT(PAGED, SushipVmxOffThreadRoutine)
_Use_decl_annotations_ EXTERN_C static VOID SushipVmxOffThreadRoutine(
    void* StartContext) {
  UNREFERENCED_PARAMETER(StartContext);
  PAGED_CODE();

  LOG_INFO("Uninstalling VMM.");
  auto status = UtilForEachProcessor(MiscStopVM, nullptr);
  LOG_INFO("The VMM has been uninstalled.");

  PsTerminateSystemThread(status);
}
