// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module defines constants and structures defined by the x86-64 archtecture
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

//
// EFLAGS
//  2.3 SYSTEM FLAGS AND FIELDS IN THE EFLAGS REGISTER
//
union EFLAGS {
  ULONG_PTR All;
  struct {
    unsigned CF : 1;          // [0] Carry flag
    unsigned Reserved1 : 1;   // [1]  Always 1
    unsigned PF : 1;          // [2] Parity flag
    unsigned Reserved2 : 1;   // [3] Always 0
    unsigned AF : 1;          // [4] Borrow flag
    unsigned Reserved3 : 1;   // [5] Always 0
    unsigned ZF : 1;          // [6] Zero flag
    unsigned SF : 1;          // [7] Sign flag
    unsigned TF : 1;          // [8] Trap flag
    unsigned IF : 1;          // [9] Interrupt flag
    unsigned DF : 1;          // [10]
    unsigned OF : 1;          // [11]
    unsigned IOPL : 2;        // [12-13] I/O privilege level
    unsigned NT : 1;          // [14] Nested task flag
    unsigned Reserved4 : 1;   // [15] Always 0
    unsigned RF : 1;          // [16] Resume flag
    unsigned VM : 1;          // [17] Virtual 8086 mode
    unsigned AC : 1;          // [18] Alignment check
    unsigned VIF : 1;         // [19] Virtual interrupt flag
    unsigned VIP : 1;         // [20] Virtual interrupt pending
    unsigned ID : 1;          // [21] Identification flag
    unsigned Reserved5 : 10;  // [22-31] Always 0
  } Fields;
};
static_assert(sizeof(EFLAGS) == sizeof(void*), "Size check");

//
// For PUSHAQ
//
struct GP_REGISTERS {
  ULONG_PTR r15;
  ULONG_PTR r14;
  ULONG_PTR r13;
  ULONG_PTR r12;
  ULONG_PTR r11;
  ULONG_PTR r10;
  ULONG_PTR r9;
  ULONG_PTR r8;
  ULONG_PTR rdi;
  ULONG_PTR rsi;
  ULONG_PTR rbp;
  ULONG_PTR rsp;
  ULONG_PTR rbx;
  ULONG_PTR rdx;
  ULONG_PTR rcx;
  ULONG_PTR rax;
};

//
// For the sequence of pushfq, PUSHAQ
//
struct ALL_REGISTERS {
  ULONG_PTR r15;
  ULONG_PTR r14;
  ULONG_PTR r13;
  ULONG_PTR r12;
  ULONG_PTR r11;
  ULONG_PTR r10;
  ULONG_PTR r9;
  ULONG_PTR r8;
  ULONG_PTR rdi;
  ULONG_PTR rsi;
  ULONG_PTR rbp;
  ULONG_PTR rsp;
  ULONG_PTR rbx;
  ULONG_PTR rdx;
  ULONG_PTR rcx;
  ULONG_PTR rax;
  EFLAGS rflags;
};

//
// CONTROL REGISTERS
// CR0
//
union CR0_REG {
  ULONG_PTR All;
  struct {
    unsigned PE : 1;          // [0] Protected Mode Enabled
    unsigned MP : 1;          // [1] Monitor Coprocessor FLAG
    unsigned EM : 1;          // [2] Emulate FLAG
    unsigned TS : 1;          // [3] Task Switched FLAG
    unsigned ET : 1;          // [4] Extension Type FLAG
    unsigned NE : 1;          // [5] Numeric Error
    unsigned Reserved1 : 10;  // [6-15]
    unsigned WP : 1;          // [16] Write Protect
    unsigned Reserved2 : 1;   // [17]
    unsigned AM : 1;          // [18] Alignment Mask
    unsigned Reserved3 : 10;  // [19-28]
    unsigned NW : 1;          // [29] Not Write-Through
    unsigned CD : 1;          // [30] Cache Disable
    unsigned PG : 1;          // [31] Paging Enabled
  } Fields;
};
static_assert(sizeof(CR0_REG) == sizeof(void*), "Size check");

//
// CR4
//
union CR4_REG {
  ULONG_PTR All;
  struct {
    unsigned VME : 1;         // [0] Virtual Mode Extensions
    unsigned PVI : 1;         // [1] Protected-Mode Virtual Interrupts
    unsigned TSD : 1;         // [2] Time Stamp Disable
    unsigned DE : 1;          // [3] Debugging Extensions
    unsigned PSE : 1;         // [4] Page Size Extensions
    unsigned PAE : 1;         // [5] Physical Address Extension
    unsigned MCE : 1;         // [6] Machine-Check Enable
    unsigned PGE : 1;         // [7] Page Global Enable
    unsigned PCE : 1;         // [8] Performance-Monitoring Counter Enable
    unsigned OSFXSR : 1;      // [9] OS Support for FXSAVE/FXRSTOR
    unsigned OSXMMEXCPT : 1;  // [10] OS Support for Unmasked SIMD Exceptions
    unsigned Reserved1 : 2;   // [11-12]
    unsigned VMXE : 1;        // [13] Virtual Machine Extensions Enabled
    unsigned SMXE : 1;        // [14] SMX-Enable Bit
    unsigned Reserved2 : 2;   // [15-16]
    unsigned PCIDE : 1;       // [17] PCID Enable
    unsigned OSXSAVE : 1;     // [18] XSAVE and Processor Extended States-Enable
    unsigned Reserved3 : 1;   // [19]
    unsigned SMEP : 1;  // [20] Supervisor Mode Execution Protection Enable
    unsigned SMAP : 1;  // [21] Supervisor Mode Access Protection Enable
  } Fields;
};
static_assert(sizeof(CR4_REG) == sizeof(void*), "Size check");

//
// IDTR/GDTR
// MEMORY-MANAGEMENT REGISTERS
//
#include <pshpack1.h>
struct IDTR {
  unsigned short Limit;
  ULONG_PTR Address;
};
typedef IDTR GDTR;
static_assert(sizeof(IDTR) == 10, "Size check");
static_assert(sizeof(GDTR) == 10, "Size check");
#include <poppack.h>

//
// Segment Selectors
//
#include <pshpack1.h>
union SEG_SELECTOR {
  unsigned short All;
  struct {
    unsigned short RPL : 2;  // Requested Privilege Level
    unsigned short TI : 1;   // Table Indicator
    unsigned short Index : 13;
  } Fields;
};
static_assert(sizeof(SEG_SELECTOR) == 2, "Size check");
#include <poppack.h>

//
// Segment Desctiptor
//
union SEG_DESCRIPTOR {
  unsigned __int64 All;
  struct {
    unsigned LimitLow : 16;
    unsigned BaseLow : 16;
    unsigned BaseMid : 8;
    unsigned Type : 4;
    unsigned System : 1;
    unsigned DPL : 2;
    unsigned Present : 1;
    unsigned LimitHi : 4;
    unsigned AVL : 1;
    unsigned L : 1;  // 64-bit code segment (IA-32e mode only)
    unsigned DB : 1;
    unsigned Gran : 1;
    unsigned BaseHi : 8;
  } Fields;
};
static_assert(sizeof(SEG_DESCRIPTOR) == 8, "Size check");

struct SEG_DESCRIPTOR64 {
  SEG_DESCRIPTOR Descriptor;
  unsigned __int32 BaseUpper32;
  unsigned __int32 Reserved;
};
static_assert(sizeof(SEG_DESCRIPTOR64) == 16, "Size check");

//
// CPU_FEATURES_ECX
//  CPUID - CPU Identification
//  Figure 3-7.  Feature Information Returned in the ECX Register
//
union CPU_FEATURES_ECX {
  ULONG_PTR All;
  struct {
    unsigned SSE3 : 1;       // SSE3 Extensions
    unsigned PCLMULQDQ : 1;  // Carryless Multiplication
    unsigned DTES64 : 1;     // 64-bit DS Area
    unsigned MONITOR : 1;    // MONITOR/WAIT
    unsigned DS_CPL : 1;     // CPL qualified Debug Store
    unsigned VMX : 1;        // Virtual Machine Technology
    unsigned SMX : 1;        // Safer Mode Extensions
    unsigned EST : 1;        // Enhanced Intel Speedstep Technology
    unsigned TM2 : 1;        // Thermal monitor 2
    unsigned SSSE3 : 1;      // SSSE3 extensions
    unsigned CID : 1;        // L1 context ID
    unsigned Reserved1 : 1;  //
    unsigned FMA : 1;        // Fused Multiply Add
    unsigned CX16 : 1;       // CMPXCHG16B
    unsigned xTPR : 1;       // Update control
    unsigned PDCM : 1;       // Performance/Debug capability MSR
    unsigned Reserved2 : 2;  //
    unsigned DCA : 1;        //
    unsigned SSE4_1 : 1;     //
    unsigned SSE4_2 : 1;     //
    unsigned x2APIC : 1;     //
    unsigned MOVBE : 1;      //
    unsigned POPCNT : 1;     //
    unsigned Reserved3 : 1;  //
    unsigned AES : 1;        //
    unsigned XSAVE : 1;      //
    unsigned OSXSAVE : 1;    //
    unsigned Reserved4 : 2;  //
    unsigned Reserved5 : 1;  //  Always 0
  } Fields;
};
static_assert(sizeof(CPU_FEATURES_ECX) == sizeof(void*), "Size check");

struct HARDWARE_PTE {
  ULONG64 Valid : 1;
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
static_assert(sizeof(HARDWARE_PTE) == sizeof(void*), "Size check");

// MODEL-SPECIFIC REGISTERS (MSRS)
enum MSR_CODE : unsigned int {
  IA32_FEATURE_CONTROL = 0x03A,
  IA32_SYSENTER_CS = 0x174,
  IA32_SYSENTER_ESP = 0x175,
  IA32_SYSENTER_EIP = 0x176,
  IA32_DEBUGCTL = 0x1D9,
  IA32_VMX_BASIC = 0x480,
  IA32_VMX_PINBASED_CTLS = 0x481,
  IA32_VMX_PROCBASED_CTLS = 0x482,
  IA32_VMX_EXIT_CTLS = 0x483,
  IA32_VMX_ENTRY_CTLS = 0x484,
  IA32_VMX_MISC = 0x485,
  IA32_VMX_CR0_FIXED0 = 0x486,
  IA32_VMX_CR0_FIXED1 = 0x487,
  IA32_VMX_CR4_FIXED0 = 0x488,
  IA32_VMX_CR4_FIXED1 = 0x489,
  IA32_VMX_VMCS_ENUM = 0x48A,
  IA32_VMX_PROCBASED_CTLS2 = 0x48B,
  IA32_VMX_EPT_VPID_CAP = 0x48C,

  IA32_EFER = 0xC0000080,
  IA32_STAR = 0xC0000081,
  IA32_LSTAR = 0xC0000082,
  IA32_FMASK = 0xC0000084,
  IA32_FS_BASE = 0xC0000100,
  IA32_GS_BASE = 0xC0000101,
  IA32_KERNEL_GS_BASE = 0xC0000102,
  IA32_TSC_AUX = 0xC0000103,
};
