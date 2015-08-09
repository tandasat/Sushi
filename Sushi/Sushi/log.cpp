// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements logging functions.
//
#include "stdafx.h"
#include "log.h"

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constant and macro
//

// A size for log buffer in NonPagedPool. Two buffers are allocated with this
// size. Exceeded logs are ignored silently. Make it bigger if a buffered log
// size often reach this size.
static const auto LOGP_BUFFER_SIZE_IN_PAGES = 10ul;

// An actual log buffer size in bytes.
static const auto LOGP_BUFFER_SIZE = PAGE_SIZE * LOGP_BUFFER_SIZE_IN_PAGES;

// A size that is usable for logging. Minus one because the last byte is kept
// for \0.
static const auto LOGP_BUFFER_USABLE_SIZE = LOGP_BUFFER_SIZE - 1;

// An interval to flush buffered log entries into a log file.
static const auto LOGP_AUTO_FLUSH_INTERVAL_MSEC = 50;

static const ULONG LOGP_POOL_TAG_NAME = ' gol';

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct LogBufferInfo {
  volatile char *LogBufferHead;  // A pointer to a buffer currently used.
                                 // It is either LogBuffer1 or LogBuffer2.
  volatile char *LogBufferTail;  // A pointer to where the next log should
                                 // be written.
  char *LogBuffer1;
  char *LogBuffer2;
  SIZE_T LogMaximumUsage;  // Holds the biggest buffer usage to
                           // determine a necessary buffer size.
  HANDLE LogFileHandle;
  KSPIN_LOCK SpinLock;
  ERESOURCE Resource;
  bool ResourceInitialized;
  volatile bool BufferFlushThreadShouldBeAlive;
  HANDLE BufferFlushThreadHandle;
  PDRIVER_OBJECT DriverObject;
  PDEVICE_OBJECT DeviceObject;
  wchar_t LogFilePath[MAX_PATH];
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C NTKERNELAPI UCHAR *NTAPI
PsGetProcessImageFileName(_In_ PEPROCESS Process);

EXTERN_C static NTSTATUS LogpInitializeBufferInfo(
    _In_ const wchar_t *LogFilePath, _In_ PDRIVER_OBJECT DriverObject,
    _In_opt_ PDEVICE_OBJECT DeviceObject, _Inout_ LogBufferInfo *Info);

EXTERN_C static NTSTATUS LogpInitializeLogFile(_Inout_ LogBufferInfo *Info);

EXTERN_C static DRIVER_REINITIALIZE LogpReinitializationRoutine;

EXTERN_C static void LogpFinalizeBufferInfo(_In_ LogBufferInfo *Info);

#ifdef _X86_
_Requires_lock_not_held_(*SpinLock) _Acquires_lock_(*SpinLock)
    _IRQL_requires_max_(DISPATCH_LEVEL) _IRQL_saves_
    _IRQL_raises_(DISPATCH_LEVEL) inline KIRQL
    KeAcquireSpinLockRaiseToDpc(_Inout_ PKSPIN_LOCK SpinLock);
#endif

EXTERN_C static NTSTATUS LogpMakePrefix(_In_ ULONG Level,
                                        _In_ const char *FunctionName,
                                        _In_ const char *LogMessage,
                                        _Out_ char *LogBuffer,
                                        _In_ size_t LogBufferLength);

EXTERN_C static const char *LogpFindBaseFunctionName(
    _In_ const char *FunctionName);

EXTERN_C static NTSTATUS LogpPut(_In_ char *Message, _In_ ULONG Attribute);

EXTERN_C static NTSTATUS LogpWriteLogBufferToFile(_Inout_ LogBufferInfo *Info,
                                                  _In_ bool PrintOut);

EXTERN_C static NTSTATUS LogpWriteMessageToFile(_In_ const char *Message,
                                                _In_ const LogBufferInfo &Info);

EXTERN_C static NTSTATUS LogpBufferMessage(_In_ const char *Message,
                                           _Inout_ LogBufferInfo *Info);

EXTERN_C static bool LogpIsLogFileEnabled(_In_ const LogBufferInfo &Info);

EXTERN_C static bool LogpIsLogFileActivated(_In_ const LogBufferInfo &Info);

EXTERN_C static bool LogpIsLogNeeded(_In_ ULONG Level);

EXTERN_C static KSTART_ROUTINE LogpBufferFlushThreadRoutine;

EXTERN_C static NTSTATUS LogpSleep(_In_ LONG Millisecond);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static auto g_LogpDebugFlag = LOG_PUT_LEVEL_DISABLE;
static LogBufferInfo g_LogpLogBufferInfo = {};

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

ALLOC_TEXT(INIT, LogInitialization)
_Use_decl_annotations_ EXTERN_C NTSTATUS
LogInitialization(ULONG Flag, const wchar_t *LogFilePath,
                  PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT DeviceObject) {
  PAGED_CODE();

  auto status = STATUS_SUCCESS;

  g_LogpDebugFlag = Flag;

  if (DeviceObject && !LogFilePath) {
    return STATUS_INVALID_PARAMETER;
  }

  // Initialize a log file if a log file path is specified.
  if (LogFilePath) {
    status = LogpInitializeBufferInfo(LogFilePath, DriverObject, DeviceObject,
                                      &g_LogpLogBufferInfo);
    if (!NT_SUCCESS(status)) {
      return status;
    }
  }

  // Test the log.
  status = LOG_INFO(
      "Log has been initialized (Flag= %08x, Buffer= %p %p, File= %S).", Flag,
      g_LogpLogBufferInfo.LogBuffer1, g_LogpLogBufferInfo.LogBuffer2,
      LogFilePath);
  if (!NT_SUCCESS(status)) {
    goto Fail;
  }
  return status;

Fail:;
  if (LogFilePath) {
    LogpFinalizeBufferInfo(&g_LogpLogBufferInfo);
  }
  return status;
}

// Initialize a log file related code such as a flushing thread.
ALLOC_TEXT(INIT, LogpInitializeBufferInfo)
_Use_decl_annotations_ EXTERN_C static NTSTATUS LogpInitializeBufferInfo(
    const wchar_t *LogFilePath, PDRIVER_OBJECT DriverObject,
    PDEVICE_OBJECT DeviceObject, LogBufferInfo *Info) {
  NT_ASSERT(LogFilePath);
  NT_ASSERT(Info);

  Info->DriverObject = DriverObject;
  Info->DeviceObject = DeviceObject;
  KeInitializeSpinLock(&Info->SpinLock);

  auto status = RtlStringCchCopyW(
      Info->LogFilePath, RTL_NUMBER_OF_FIELD(LogBufferInfo, LogFilePath),
      LogFilePath);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = ExInitializeResourceLite(&Info->Resource);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  Info->ResourceInitialized = true;

  if (Info->DeviceObject) {
    // We can handle IRP_MJ_SHUTDOWN in order to flush buffered log entries.
    status = IoRegisterShutdownNotification(Info->DeviceObject);
    if (!NT_SUCCESS(status)) {
      LogpFinalizeBufferInfo(Info);
      return status;
    }
  }

  // Allocate two log buffers on NonPagedPool.
  Info->LogBuffer1 = reinterpret_cast<char *>(ExAllocatePoolWithTag(
      NonPagedPoolNx, LOGP_BUFFER_SIZE, LOGP_POOL_TAG_NAME));
  if (!Info->LogBuffer1) {
    LogpFinalizeBufferInfo(Info);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  Info->LogBuffer2 = reinterpret_cast<char *>(ExAllocatePoolWithTag(
      NonPagedPoolNx, LOGP_BUFFER_SIZE, LOGP_POOL_TAG_NAME));
  if (!Info->LogBuffer2) {
    LogpFinalizeBufferInfo(Info);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Initialize these buffers
  RtlFillMemory(Info->LogBuffer1, LOGP_BUFFER_SIZE, 0xff);  // for debug
  Info->LogBuffer1[0] = '\0';
  Info->LogBuffer1[LOGP_BUFFER_SIZE - 1] = '\0';  // at the end

  RtlFillMemory(Info->LogBuffer2, LOGP_BUFFER_SIZE, 0xff);  // for debug
  Info->LogBuffer2[0] = '\0';
  Info->LogBuffer2[LOGP_BUFFER_SIZE - 1] = '\0';  // at the end

  // Buffer should be used is LogBuffer1, and location should be written logs
  // is the head of the buffer.
  Info->LogBufferHead = Info->LogBuffer1;
  Info->LogBufferTail = Info->LogBuffer1;

  status = LogpInitializeLogFile(Info);
  if (status == STATUS_OBJECT_PATH_NOT_FOUND) {
    IoRegisterBootDriverReinitialization(Info->DriverObject,
                                         LogpReinitializationRoutine, Info);
    LOG_INFO("The log file will be activated later.");
    status = STATUS_SUCCESS;
  }
  return status;
}

ALLOC_TEXT(PAGED, LogpInitializeLogFile)
_Use_decl_annotations_ EXTERN_C static NTSTATUS LogpInitializeLogFile(
    LogBufferInfo *Info) {
  PAGED_CODE();

  if (Info->LogFileHandle) {
    return STATUS_SUCCESS;
  }

  // Initialize a log file
  UNICODE_STRING logFilePathU = {};
  RtlInitUnicodeString(&logFilePathU, Info->LogFilePath);

  OBJECT_ATTRIBUTES oa = {};
  InitializeObjectAttributes(&oa, &logFilePathU,
                             OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr,
                             nullptr);

  IO_STATUS_BLOCK ioStatus = {};
  auto status = ZwCreateFile(
      &Info->LogFileHandle, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &ioStatus,
      nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
      FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Initialize a log buffer flush thread.
  Info->BufferFlushThreadShouldBeAlive = true;
  status = PsCreateSystemThread(&Info->BufferFlushThreadHandle, GENERIC_ALL,
                                nullptr, nullptr, nullptr,
                                LogpBufferFlushThreadRoutine, Info);
  if (!NT_SUCCESS(status)) {
    ZwClose(Info->LogFileHandle);
    Info->LogFileHandle = nullptr;
    Info->BufferFlushThreadShouldBeAlive = false;
  }
  return status;
}

ALLOC_TEXT(PAGED, LogpReinitializationRoutine)
_Use_decl_annotations_ EXTERN_C VOID static LogpReinitializationRoutine(
    _DRIVER_OBJECT *DriverObject, PVOID Context, ULONG Count) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(Count);
  NT_ASSERT(Context);

  DBG_BREAK();

  auto info = reinterpret_cast<LogBufferInfo *>(Context);
  auto status = LogpInitializeLogFile(info);
  NT_ASSERT(NT_SUCCESS(status));
  if (NT_SUCCESS(status)) {
    LOG_INFO("The log file has been activated.");
  }
}

// Terminates the log functions without releasing resources.
ALLOC_TEXT(PAGED, LogIrpShutdownHandler)
_Use_decl_annotations_ EXTERN_C void LogIrpShutdownHandler() {
  PAGED_CODE();

  LOG_DEBUG("Flushing... (Max log usage = %08x bytes)",
            g_LogpLogBufferInfo.LogMaximumUsage);
  LOG_INFO("Bye!");
  g_LogpDebugFlag = LOG_PUT_LEVEL_DISABLE;

  // Wait until the log buffer is emptied.
  auto &info = g_LogpLogBufferInfo;
  while (info.LogBufferHead[0]) {
    LogpSleep(LOGP_AUTO_FLUSH_INTERVAL_MSEC);
  }
}

// Terminates the log functions.
ALLOC_TEXT(PAGED, LogTermination)
_Use_decl_annotations_ EXTERN_C void LogTermination() {
  PAGED_CODE();

  LOG_DEBUG("Finalizing... (Max log usage = %08x bytes)",
            g_LogpLogBufferInfo.LogMaximumUsage);
  LOG_INFO("Bye!");
  g_LogpDebugFlag = LOG_PUT_LEVEL_DISABLE;
  LogpFinalizeBufferInfo(&g_LogpLogBufferInfo);
}

// Terminates a log file related code.
ALLOC_TEXT(PAGED, LogpFinalizeBufferInfo)
_Use_decl_annotations_ EXTERN_C static void LogpFinalizeBufferInfo(
    LogBufferInfo *Info) {
  PAGED_CODE();
  NT_ASSERT(Info);

  // Closing the log buffer flush thread.
  if (Info->BufferFlushThreadHandle) {
    Info->BufferFlushThreadShouldBeAlive = false;
    auto status =
        ZwWaitForSingleObject(Info->BufferFlushThreadHandle, FALSE, nullptr);
    if (!NT_SUCCESS(status)) {
      DBG_BREAK();
    }
    ZwClose(Info->BufferFlushThreadHandle);
    Info->BufferFlushThreadHandle = nullptr;
  }

  // Cleaning up other things.
  if (Info->LogFileHandle) {
    ZwClose(Info->LogFileHandle);
    Info->LogFileHandle = nullptr;
  }
  if (Info->LogBuffer2) {
    ExFreePoolWithTag(Info->LogBuffer2, LOGP_POOL_TAG_NAME);
    Info->LogBuffer2 = nullptr;
  }
  if (Info->LogBuffer1) {
    ExFreePoolWithTag(Info->LogBuffer1, LOGP_POOL_TAG_NAME);
    Info->LogBuffer1 = nullptr;
  }

  if (Info->DeviceObject) {
    IoUnregisterShutdownNotification(Info->DeviceObject);
  }
  if (Info->ResourceInitialized) {
    ExDeleteResourceLite(&Info->Resource);
    Info->ResourceInitialized = false;
  }
}

#ifdef _X86_
_Use_decl_annotations_ KIRQL KeAcquireSpinLockRaiseToDpc(PKSPIN_LOCK SpinLock) {
  KIRQL irql = {};
  KeAcquireSpinLock(SpinLock, &irql);
  return irql;
}
#endif

// Actual implementation of logging API.
_Use_decl_annotations_ EXTERN_C NTSTATUS LogpPrint(ULONG Level,
                                                   const char *FunctionName,
                                                   const char *Format, ...) {
  auto status = STATUS_SUCCESS;

  if (!LogpIsLogNeeded(Level)) {
    return status;
  }

  va_list args;
  va_start(args, Format);
  char logMessage[412];
  status =
      RtlStringCchVPrintfA(logMessage, RTL_NUMBER_OF(logMessage), Format, args);
  va_end(args);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (logMessage[0] == '\0') {
    return STATUS_INVALID_PARAMETER;
  }

  const auto pureLevel = Level & 0xf0;
  const auto attribute = Level & 0x0f;

  // A single entry of log should not exceed 512 bytes. See
  // Reading and Filtering Debugging Messages in MSDN for details.
  char message[512];
  static_assert(RTL_NUMBER_OF(message) <= 512,
                "One log message should not exceed 512 bytes.");
  status = LogpMakePrefix(pureLevel, FunctionName, logMessage, message,
                          RTL_NUMBER_OF(message));
  if (!NT_SUCCESS(status)) {
    return status;
  }

  return LogpPut(message, attribute);
}

// Concatenates meta information such as the current time and a process ID to
// user given log message.
_Use_decl_annotations_ EXTERN_C static NTSTATUS LogpMakePrefix(
    ULONG Level, const char *FunctionName, const char *LogMessage,
    char *LogBuffer, size_t LogBufferLength) {
  char const *levelString = nullptr;
  switch (Level) {
    case LOGP_LEVEL_DEBUG:
      levelString = "DBG\t";
      break;
    case LOGP_LEVEL_INFO:
      levelString = "INF\t";
      break;
    case LOGP_LEVEL_WARN:
      levelString = "WRN\t";
      break;
    case LOGP_LEVEL_ERROR:
      levelString = "ERR\t";
      break;
    default:
      return STATUS_INVALID_PARAMETER;
  }

  auto status = STATUS_SUCCESS;

  char timeBuffer[20] = {};
  if ((g_LogpDebugFlag & LOG_OPT_DISABLE_TIME) == 0) {
    // Want the current time.
    TIME_FIELDS timeFields;
    LARGE_INTEGER systemTime, localTime;
    KeQuerySystemTime(&systemTime);
    ExSystemTimeToLocalTime(&systemTime, &localTime);
    RtlTimeToTimeFields(&localTime, &timeFields);

    status = RtlStringCchPrintfA(timeBuffer, RTL_NUMBER_OF(timeBuffer),
                                 "%02u:%02u:%02u.%03u\t", timeFields.Hour,
                                 timeFields.Minute, timeFields.Second,
                                 timeFields.Milliseconds);
    if (!NT_SUCCESS(status)) {
      return status;
    }
  }

  // Want the function name
  char functionNameBuffer[50] = {};
  if ((g_LogpDebugFlag & LOG_OPT_DISABLE_FUNCTION_NAME) == 0) {
    const auto baseFunctionName = LogpFindBaseFunctionName(FunctionName);
    status = RtlStringCchPrintfA(functionNameBuffer,
                                 RTL_NUMBER_OF(functionNameBuffer), "%-40s\t",
                                 baseFunctionName);
    if (!NT_SUCCESS(status)) {
      return status;
    }
  }

  // Want the processor number
  char processroNumber[10] = {};
  if ((g_LogpDebugFlag & LOG_OPT_DISABLE_PROCESSOR_NUMBER) == 0) {
    status =
        RtlStringCchPrintfA(processroNumber, RTL_NUMBER_OF(processroNumber),
                            "#%lu\t", KeGetCurrentProcessorNumber());
    if (!NT_SUCCESS(status)) {
      return status;
    }
  }

  //
  // It uses PsGetProcessId(PsGetCurrentProcess()) instead of
  // PsGetCurrentThreadProcessId() because the later sometimes returns
  // unwanted value, for example:
  //  PID == 4 but its image name != ntoskrnl.exe
  // The author is guessing that it is related to attaching processes but
  // not quite sure. The former way works as expected.
  //
  status = RtlStringCchPrintfA(
      LogBuffer, LogBufferLength, "%s%s%s%5Iu\t%5Iu\t%-15s\t%s%s\r\n",
      timeBuffer, levelString, processroNumber,
      reinterpret_cast<ULONG_PTR>(PsGetProcessId(PsGetCurrentProcess())),
      reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId()),
      PsGetProcessImageFileName(PsGetCurrentProcess()), functionNameBuffer,
      LogMessage);
  return status;
}

// Returns the function's base name, for example,
// NamespaceName::ClassName::MethodName will be returned as MethodName.
_Use_decl_annotations_ EXTERN_C static const char *LogpFindBaseFunctionName(
    const char *FunctionName) {
  if (!FunctionName) {
    return nullptr;
  }

  auto ptr = FunctionName;
  auto name = FunctionName;
  while (*(ptr++)) {
    if (*ptr == ':') {
      name = ptr + 1;
    }
  }
  return name;
}

// Logs the entry according to Attribute and the thread condition.
_Use_decl_annotations_ EXTERN_C static NTSTATUS LogpPut(char *Message,
                                                        ULONG Attribute) {
  auto status = STATUS_SUCCESS;

  // Log the entry to a file or buffer.
  auto &info = g_LogpLogBufferInfo;
  if (LogpIsLogFileEnabled(info)) {
    // Can it log it to a file now?
    if (((Attribute & LOGP_LEVEL_OPT_SAFE) == 0) &&
        KeGetCurrentIrql() == PASSIVE_LEVEL && !KeAreAllApcsDisabled() &&
        LogpIsLogFileActivated(info)) {
      // Yes, it can. Do it.
      LogpWriteLogBufferToFile(&info, false);
      status = LogpWriteMessageToFile(Message, info);
    } else {
      // No, it cannot. Buffer it.
      status = LogpBufferMessage(Message, &info);
    }
  }

  // Can it safely be printed?
  if ((Attribute & LOGP_LEVEL_OPT_SAFE) == 0 &&
      KeGetCurrentIrql() < CLOCK_LEVEL) {
    const auto locationOfCR = strlen(Message) - 2;
    Message[locationOfCR] = '\n';
    Message[locationOfCR + 1] = '\0';
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", Message);
  }
  return status;
}

// Switch the current log buffer and save the contents of old buffer to the log
// file. This function does not flush the log file, so code should call
// LogpWriteMessageToFile() or ZwFlushBuffersFile() later.
_Use_decl_annotations_ EXTERN_C static NTSTATUS LogpWriteLogBufferToFile(
    LogBufferInfo *Info, bool PrintOut) {
  NT_ASSERT(Info);
  NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

  auto status = STATUS_SUCCESS;

  // Enter a critical section and acquire a reader lock for Info in order to
  // write a log file safely.
  ExEnterCriticalRegionAndAcquireResourceExclusive(&Info->Resource);

  // Acquire a spin lock for Info.LogBuffer(s) in order to switch its head
  // safely.
  const auto irql = KeAcquireSpinLockRaiseToDpc(&Info->SpinLock);
  auto oldLogBuffer = const_cast<char *>(Info->LogBufferHead);
  if (oldLogBuffer[0]) {
    Info->LogBufferHead = (oldLogBuffer == Info->LogBuffer1) ? Info->LogBuffer2
                                                             : Info->LogBuffer1;
    Info->LogBufferHead[0] = '\0';
    Info->LogBufferTail = Info->LogBufferHead;
  }
  KeReleaseSpinLock(&Info->SpinLock, irql);

  // Write all log entries in old log buffer.
  IO_STATUS_BLOCK ioStatus = {};
  for (auto currentLogEntry = oldLogBuffer; currentLogEntry[0]; /**/) {
    const auto currentLogEntryLength = strlen(currentLogEntry);
    status =
        ZwWriteFile(Info->LogFileHandle, nullptr, nullptr, nullptr, &ioStatus,
                    currentLogEntry, static_cast<ULONG>(currentLogEntryLength),
                    nullptr, nullptr);
    if (!NT_SUCCESS(status)) {
      // It could happen when you did not register IRP_SHUTDOWN and call
      // LogIrpShutdownHandler() and the system tried to log to a file after
      // a file system was unmounted.
      DBG_BREAK();
    }

    if (PrintOut) {
      const auto locationOfCR = currentLogEntryLength - 2;
      currentLogEntry[locationOfCR] = '\n';
      currentLogEntry[locationOfCR + 1] = '\0';
      DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", currentLogEntry);
    }

    currentLogEntry += currentLogEntryLength + 1;
  }
  oldLogBuffer[0] = '\0';

  ExReleaseResourceAndLeaveCriticalRegion(&Info->Resource);
  return status;
}

// Logs the current log entry to and flush the log file.
_Use_decl_annotations_ EXTERN_C static NTSTATUS LogpWriteMessageToFile(
    const char *Message, const LogBufferInfo &Info) {
  NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

  IO_STATUS_BLOCK ioStatus = {};
  auto status =
      ZwWriteFile(Info.LogFileHandle, nullptr, nullptr, nullptr, &ioStatus,
                  const_cast<char *>(Message),
                  static_cast<ULONG>(strlen(Message)), nullptr, nullptr);
  if (!NT_SUCCESS(status)) {
    // It could happen when you did not register IRP_SHUTDOWN and call
    // LogIrpShutdownHandler() and the system tried to log to a file after
    // a file system was unmounted.
    DBG_BREAK();
  }
  status = ZwFlushBuffersFile(Info.LogFileHandle, &ioStatus);
  return status;
}

// Buffer the log entry to the log buffer.
_Use_decl_annotations_ EXTERN_C static NTSTATUS LogpBufferMessage(
    const char *Message, LogBufferInfo *Info) {
  NT_ASSERT(Info);

  // Acquire a spin lock to add the log safely.
  const auto oldIrql = KeGetCurrentIrql();
  if (oldIrql < DISPATCH_LEVEL) {
    KeAcquireSpinLockRaiseToDpc(&Info->SpinLock);
  } else {
    KeAcquireSpinLockAtDpcLevel(&Info->SpinLock);
  }
  NT_ASSERT(KeGetCurrentIrql() >= DISPATCH_LEVEL);

  // Copy the current log to the buffer.
  size_t usedBufferSize = Info->LogBufferTail - Info->LogBufferHead;
  auto status =
      RtlStringCchCopyA(const_cast<char *>(Info->LogBufferTail),
                        LOGP_BUFFER_USABLE_SIZE - usedBufferSize, Message);

  // Update Info.LogMaximumUsage if necessary.
  if (NT_SUCCESS(status)) {
    const auto messageLength = strlen(Message) + 1;
    Info->LogBufferTail += messageLength;
    usedBufferSize += messageLength;
    if (usedBufferSize > Info->LogMaximumUsage) {
      Info->LogMaximumUsage = usedBufferSize;  // Update
    }
  } else {
    Info->LogMaximumUsage = LOGP_BUFFER_SIZE;  // Indicates overflow
  }
  *Info->LogBufferTail = '\0';

  if (oldIrql < DISPATCH_LEVEL) {
    KeReleaseSpinLock(&Info->SpinLock, oldIrql);
  } else {
    KeReleaseSpinLockFromDpcLevel(&Info->SpinLock);
  }
  return status;
}

// Returns true when a log file is enabled.
_Use_decl_annotations_ EXTERN_C static bool LogpIsLogFileEnabled(
    const LogBufferInfo &Info) {
  if (Info.LogBuffer1) {
    NT_ASSERT(Info.LogBuffer2);
    NT_ASSERT(Info.LogBufferHead);
    NT_ASSERT(Info.LogBufferTail);
    return true;
  }
  NT_ASSERT(!Info.LogBuffer2);
  NT_ASSERT(!Info.LogBufferHead);
  NT_ASSERT(!Info.LogBufferTail);
  return false;
}

// Returns true when a log file is opened.
_Use_decl_annotations_ EXTERN_C static bool LogpIsLogFileActivated(
    const LogBufferInfo &Info) {
  if (Info.BufferFlushThreadShouldBeAlive) {
    NT_ASSERT(Info.BufferFlushThreadHandle);
    NT_ASSERT(Info.LogFileHandle);
    return true;
  }
  NT_ASSERT(!Info.BufferFlushThreadHandle);
  NT_ASSERT(!Info.LogFileHandle);
  return false;
}

// Returns true when logging is necessary according to the log's severity and
// a set log level.
_Use_decl_annotations_ EXTERN_C static bool LogpIsLogNeeded(ULONG Level) {
  return !!(g_LogpDebugFlag & Level);
}

// A thread runs as long as info.BufferFlushThreadShouldBeAlive is true and
// flushes a log buffer to a log file every LOGP_AUTO_FLUSH_INTERVAL_MSEC msec.
ALLOC_TEXT(PAGED, LogpBufferFlushThreadRoutine)
_Use_decl_annotations_ EXTERN_C static VOID LogpBufferFlushThreadRoutine(
    void *StartContext) {
  PAGED_CODE();
  auto status = STATUS_SUCCESS;
  auto info = reinterpret_cast<LogBufferInfo *>(StartContext);
  LOG_DEBUG("Log thread started.");
  NT_ASSERT(LogpIsLogFileActivated(*info));

  while (info->BufferFlushThreadShouldBeAlive) {
    LogpSleep(LOGP_AUTO_FLUSH_INTERVAL_MSEC);
    if (info->LogBufferHead[0]) {
      NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
      NT_ASSERT(!KeAreAllApcsDisabled());
      status = LogpWriteLogBufferToFile(info, true);
      // Do not flush the file for overall performance. Even a case of
      // bug check, we should be able to recover logs by looking at both
      // log buffers.
    }
  }
  PsTerminateSystemThread(status);
}

// Sleep the current thread's execution for Millisecond milliseconds.
ALLOC_TEXT(PAGED, LogpSleep)
_Use_decl_annotations_ EXTERN_C static NTSTATUS LogpSleep(LONG Millisecond) {
  PAGED_CODE();

  LARGE_INTEGER interval = {};
  interval.QuadPart = -(10000 * Millisecond);  // msec
  return KeDelayExecutionThread(KernelMode, FALSE, &interval);
}
