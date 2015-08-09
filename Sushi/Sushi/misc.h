// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module declares interfaces to misc functions.
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

EXTERN_C NTSTATUS MiscInitializeRuntimeInfo();

EXTERN_C void *MiscAllocateContiguousMemory(_In_ SIZE_T NumberOfBytes);

EXTERN_C void MiscFreeContiguousMemory(_In_ void *BaseAddress);

EXTERN_C NTSTATUS MiscVmCall(_In_ ULONG_PTR HyperCallNumber,
                             _In_opt_ void *Context);

EXTERN_C NTSTATUS MiscStopVM(_In_opt_ void *Context);

EXTERN_C bool MiscIsInterestingAddress(_In_ ULONG_PTR Address);

EXTERN_C bool MiscIsInterestingContext(_In_ const struct GP_REGISTERS *Regs);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//
