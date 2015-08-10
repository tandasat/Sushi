// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module declares interfaces to logging functions.
//
#pragma once

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

//
// Does log with respective severities. Here are some ideas to decide which
// level is appropriate:
//  DEBUG: For developers.
//  INFO: For all.
//  WARN: For all. It may require some attention but does not prevent the
//        program working properly.
//  ERROR: For all. It stops the program working properly.
//
#define LOG_DEBUG(format, ...) \
  LogpPrint(LOGP_LEVEL_DEBUG, __FUNCTION__, (format), __VA_ARGS__)
#define LOG_INFO(format, ...) \
  LogpPrint(LOGP_LEVEL_INFO, __FUNCTION__, (format), __VA_ARGS__)
#define LOG_WARN(format, ...) \
  LogpPrint(LOGP_LEVEL_WARN, __FUNCTION__, (format), __VA_ARGS__)
#define LOG_ERROR(format, ...) \
  LogpPrint(LOGP_LEVEL_ERROR, __FUNCTION__, (format), __VA_ARGS__)

// Buffers the log to buffer. It is recommended to use it when a status of
// callee is no predictable in order to avoid bug checks.
#define LOG_DEBUG_SAFE(format, ...)                                         \
  LogpPrint(LOGP_LEVEL_DEBUG | LOGP_LEVEL_OPT_SAFE, __FUNCTION__, (format), \
            __VA_ARGS__)
#define LOG_INFO_SAFE(format, ...)                                         \
  LogpPrint(LOGP_LEVEL_INFO | LOGP_LEVEL_OPT_SAFE, __FUNCTION__, (format), \
            __VA_ARGS__)
#define LOG_WARN_SAFE(format, ...)                                         \
  LogpPrint(LOGP_LEVEL_WARN | LOGP_LEVEL_OPT_SAFE, __FUNCTION__, (format), \
            __VA_ARGS__)
#define LOG_ERROR_SAFE(format, ...)                                         \
  LogpPrint(LOGP_LEVEL_ERROR | LOGP_LEVEL_OPT_SAFE, __FUNCTION__, (format), \
            __VA_ARGS__)

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

// (internal) Save this log to buffer and not try to write to a log file.
static const auto LOGP_LEVEL_OPT_SAFE = 0x1ul;

// (internal) Log levels.
static const auto LOGP_LEVEL_DEBUG = 0x10ul;
static const auto LOGP_LEVEL_INFO = 0x20ul;
static const auto LOGP_LEVEL_WARN = 0x40ul;
static const auto LOGP_LEVEL_ERROR = 0x80ul;

// For LogInitialization(). Specifies what level of verbosity is needed.
static const auto LOG_PUT_LEVEL_DEBUG =
    LOGP_LEVEL_ERROR | LOGP_LEVEL_WARN | LOGP_LEVEL_INFO | LOGP_LEVEL_DEBUG;
static const auto LOG_PUT_LEVEL_INFO =
    LOGP_LEVEL_ERROR | LOGP_LEVEL_WARN | LOGP_LEVEL_INFO;
static const auto LOG_PUT_LEVEL_WARN = LOGP_LEVEL_ERROR | LOGP_LEVEL_WARN;
static const auto LOG_PUT_LEVEL_ERROR = LOGP_LEVEL_ERROR;
static const auto LOG_PUT_LEVEL_DISABLE = 0x00ul;

// For LogInitialization(). Does not log a current time.
static const auto LOG_OPT_DISABLE_TIME = 0x100ul;

// For LogInitialization(). Does not log a current function name.
static const auto LOG_OPT_DISABLE_FUNCTION_NAME = 0x200ul;

// For LogInitialization(). Does not log a current processor number.
static const auto LOG_OPT_DISABLE_PROCESSOR_NUMBER = 0x400ul;

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

// Initialize the log system.
// Returns STATUS_SUCCESS when it succeeded, or returns
// STATUS_REINITIALIZATION_NEEDED when re-initialization with
// LogRegisterReinitialization() is required.
EXTERN_C NTSTATUS LogInitialization(_In_ ULONG Flag,
                                    _In_opt_ const wchar_t *FilePath);

// Register re-initialization. DriverEntry() must return STATUS_SUCCESS when
// this function is called.
EXTERN_C void LogRegisterReinitialization(_In_ PDRIVER_OBJECT DriverObject);

// Terminates the log system quickly. It should be called from an
// IRP_MJ_SHUTDOWN handler.
EXTERN_C void LogIrpShutdownHandler();

// Terminates the log system. It should be called from a DriverUnload routine.
EXTERN_C void LogTermination();

// (internal) Use LOG_*() macros instead.
EXTERN_C NTSTATUS LogpPrint(_In_ ULONG Level, _In_ const char *FunctionName,
                            _In_ const char *Format, ...);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//
