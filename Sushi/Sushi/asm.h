// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module declares interfaces to logging functions.
//
#pragma once
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

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C bool AsmInitialieVM(_In_ void (*VmInitializationRoutine)(
    ULONG_PTR GuestStackPointer, ULONG_PTR GuestInstructionPointer));

EXTERN_C void AsmVmmEntryPoint();

EXTERN_C VMX_STATUS AsmVmxCall(_In_ ULONG_PTR HyperCallNumber,
                               _In_opt_ void *Context);

EXTERN_C void AsmWriteGDT(_In_ const GDTR *Gdtr);

EXTERN_C void AsmReadGDT(_Out_ GDTR *Gdtr);

EXTERN_C void AsmWriteLDTR(_In_ USHORT LocalSegmengSelector);

EXTERN_C USHORT AsmReadLDTR();

EXTERN_C void AsmWriteTR(_In_ USHORT TaskRegister);

EXTERN_C USHORT AsmReadTR();

EXTERN_C void AsmWriteES(_In_ USHORT SegmentSelector);

EXTERN_C USHORT AsmReadES();

EXTERN_C void AsmWriteCS(_In_ USHORT SegmentSelector);

EXTERN_C USHORT AsmReadCS();

EXTERN_C void AsmWriteSS(_In_ USHORT SegmentSelector);

EXTERN_C USHORT AsmReadSS();

EXTERN_C void AsmWriteDS(_In_ USHORT SegmentSelector);

EXTERN_C USHORT AsmReadDS();

EXTERN_C void AsmWriteFS(_In_ USHORT SegmentSelector);

EXTERN_C USHORT AsmReadFS();

EXTERN_C void AsmWriteGS(_In_ USHORT SegmentSelector);

EXTERN_C USHORT AsmReadGS();

EXTERN_C ULONG_PTR AsmLoadAccessRightsByte(_In_ ULONG_PTR SegmentSelector);

EXTERN_C void AsmInvalidateInternalCaches();

EXTERN_C void AsmWriteCR2(_In_ ULONG_PTR Cr2);

EXTERN_C void AsmUndefinedInstruction();

EXTERN_C void AsmXsetbv(_In_ ULONG32 Index, _In_ ULONG32 HighValue,
                        _In_ ULONG32 LowValue);

EXTERN_C void AsmWaitForever();

EXTERN_C void AsmTrampoline();

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

EXTERN_C inline void __sgdt(_Out_ void *Gdtr) {
  AsmReadGDT(static_cast<GDTR *>(Gdtr));
}

EXTERN_C inline void __lgdt(_In_ void *Gdtr) {
  AsmWriteGDT(static_cast<GDTR *>(Gdtr));
}
