// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module declares interfaces to utility functions.
//
#pragma once

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

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C NTSTATUS UtilForEachProcessor(_In_ NTSTATUS (*CallbackRoutine)(void *),
                                       _In_opt_ void *Context);

EXTERN_C NTSTATUS UtilSleep(_In_ LONG Millisecond);

EXTERN_C void *UtilMemMem(_In_ const void *SearchBase, _In_ SIZE_T SearchSize,
                          _In_ const void *Pattern, _In_ SIZE_T PatternSize);

EXTERN_C void UtilInvalidateInstructionCache(_In_ void *BaseAddress,
                                             _In_ SIZE_T Length);

EXTERN_C NTSTATUS UtilForceMemCpy(_In_ void *Destination,
                                  _In_ const void *Source, _In_ SIZE_T Length);

EXTERN_C bool UtilIsAccessibleAddress(_In_ const void *Address);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

template <typename T>
inline bool UtilIsInBounds(_In_ const T &Value, _In_ const T &Min,
                           _In_ const T &Max) {
  return (Min <= Value) && (Value <= Max);
}
