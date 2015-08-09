// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module defines constants and structures related to VMX features
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

// OVERVIEW
static const SIZE_T MAXIMUM_VMCS_SIZE = 4096;

enum VMX_STATUS : unsigned char {
  VMX_OK = 0,
  VMX_ERROR_WITH_STATUS = 1,
  VMX_ERROR_WITHOUT_STATUS = 2,
};

// FIELD ENCODING IN VMCS
enum VMCS_ENCODE {
  VIRTUAL_PROCESSOR_ID = 0x00000000,  // 16-Bit Control Field
  POSTED_INTERRUPT_NOTIFICATION = 0x00000002,
  EPTP_INDEX = 0x00000004,
  GUEST_ES_SELECTOR = 0x00000800,  // 16-Bit Guest-State Fields
  GUEST_CS_SELECTOR = 0x00000802,
  GUEST_SS_SELECTOR = 0x00000804,
  GUEST_DS_SELECTOR = 0x00000806,
  GUEST_FS_SELECTOR = 0x00000808,
  GUEST_GS_SELECTOR = 0x0000080a,
  GUEST_LDTR_SELECTOR = 0x0000080c,
  GUEST_TR_SELECTOR = 0x0000080e,
  GUEST_INTERRUPT_STATUS = 0x00000810,
  HOST_ES_SELECTOR = 0x00000c00,  // 16-Bit Host-State Fields
  HOST_CS_SELECTOR = 0x00000c02,
  HOST_SS_SELECTOR = 0x00000c04,
  HOST_DS_SELECTOR = 0x00000c06,
  HOST_FS_SELECTOR = 0x00000c08,
  HOST_GS_SELECTOR = 0x00000c0a,
  HOST_TR_SELECTOR = 0x00000c0c,
  IO_BITMAP_A = 0x00002000,  // 64-Bit Control Fields
  IO_BITMAP_A_HIGH = 0x00002001,
  IO_BITMAP_B = 0x00002002,
  IO_BITMAP_B_HIGH = 0x00002003,
  MSR_BITMAP = 0x00002004,
  MSR_BITMAP_HIGH = 0x00002005,
  VM_EXIT_MSR_STORE_ADDR = 0x00002006,
  VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
  VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
  VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
  VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
  VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
  EXECUTIVE_VMCS_POINTER = 0x0000200c,
  EXECUTIVE_VMCS_POINTER_HIGH = 0x0000200d,
  TSC_OFFSET = 0x00002010,
  TSC_OFFSET_HIGH = 0x00002011,
  VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
  VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
  APIC_ACCESS_ADDR = 0x00002014,
  APIC_ACCESS_ADDR_HIGH = 0x00002015,
  EPT_POINTER = 0x0000201a,
  EPT_POINTER_HIGH = 0x0000201b,
  EOI_EXIT_BITMAP_0 = 0x0000201c,
  EOI_EXIT_BITMAP_0_HIGH = 0x0000201d,
  EOI_EXIT_BITMAP_1 = 0x0000201e,
  EOI_EXIT_BITMAP_1_HIGH = 0x0000201f,
  EOI_EXIT_BITMAP_2 = 0x00002020,
  EOI_EXIT_BITMAP_2_HIGH = 0x00002021,
  EOI_EXIT_BITMAP_3 = 0x00002022,
  EOI_EXIT_BITMAP_3_HIGH = 0x00002023,
  EPTP_LIST_ADDRESS = 0x00002024,
  EPTP_LIST_ADDRESS_HIGH = 0x00002025,
  VMREAD_BITMAP_ADDRESS = 0x00002026,
  VMREAD_BITMAP_ADDRESS_HIGH = 0x00002027,
  VMWRITE_BITMAP_ADDRESS = 0x00002028,
  VMWRITE_BITMAP_ADDRESS_HIGH = 0x00002029,
  VIRTUALIZATION_EXCEPTION_INFO_ADDDRESS = 0x0000202a,
  VIRTUALIZATION_EXCEPTION_INFO_ADDDRESS_HIGH = 0x0000202b,
  XSS_EXITING_BITMAP = 0x0000202c,
  XSS_EXITING_BITMAP_HIGH = 0x0000202d,
  GUEST_PHYSICAL_ADDRESS = 0x00002400,  // 64-Bit Read-Only Data Field
  GUEST_PHYSICAL_ADDRESS_HIGH = 0x00002401,
  VMCS_LINK_POINTER = 0x00002800,  // 64-Bit Guest-State Fields
  VMCS_LINK_POINTER_HIGH = 0x00002801,
  GUEST_IA32_DEBUGCTL = 0x00002802,
  GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
  GUEST_IA32_PAT = 0x00002804,
  GUEST_IA32_PAT_HIGH = 0x00002805,
  GUEST_IA32_EFER = 0x00002806,
  GUEST_IA32_EFER_HIGH = 0x00002807,
  GUEST_IA32_PERF_GLOBAL_CTRL = 0x00002808,
  GUEST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002809,
  GUEST_PDPTR0 = 0x0000280a,
  GUEST_PDPTR0_HIGH = 0x0000280b,
  GUEST_PDPTR1 = 0x0000280c,
  GUEST_PDPTR1_HIGH = 0x0000280d,
  GUEST_PDPTR2 = 0x0000280e,
  GUEST_PDPTR2_HIGH = 0x0000280f,
  GUEST_PDPTR3 = 0x00002810,
  GUEST_PDPTR3_HIGH = 0x00002811,
  HOST_IA32_PAT = 0x00002c00,  // 64-Bit Host-State Fields
  HOST_IA32_PAT_HIGH = 0x00002c01,
  HOST_IA32_EFER = 0x00002c02,
  HOST_IA32_EFER_HIGH = 0x00002c03,
  HOST_IA32_PERF_GLOBAL_CTRL = 0x00002c04,
  HOST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002c05,
  PIN_BASED_VM_EXEC_CONTROL = 0x00004000,  // 32-Bit Control Fields
  CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
  EXCEPTION_BITMAP = 0x00004004,
  PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
  PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
  CR3_TARGET_COUNT = 0x0000400a,
  VM_EXIT_CONTROLS = 0x0000400c,
  VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
  VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
  VM_ENTRY_CONTROLS = 0x00004012,
  VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
  VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
  VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
  VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
  TPR_THRESHOLD = 0x0000401c,
  SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
  PLE_GAP = 0x00004020,
  PLE_WINDOW = 0x00004022,
  VM_INSTRUCTION_ERROR = 0x00004400,  // 32-Bit Read-Only Data Fields
  VM_EXIT_REASON = 0x00004402,
  VM_EXIT_INTR_INFO = 0x00004404,
  VM_EXIT_INTR_ERROR_CODE = 0x00004406,
  IDT_VECTORING_INFO_FIELD = 0x00004408,
  IDT_VECTORING_ERROR_CODE = 0x0000440a,
  VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
  VMX_INSTRUCTION_INFO = 0x0000440e,
  GUEST_ES_LIMIT = 0x00004800,  // 32-Bit Guest-State Fields
  GUEST_CS_LIMIT = 0x00004802,
  GUEST_SS_LIMIT = 0x00004804,
  GUEST_DS_LIMIT = 0x00004806,
  GUEST_FS_LIMIT = 0x00004808,
  GUEST_GS_LIMIT = 0x0000480a,
  GUEST_LDTR_LIMIT = 0x0000480c,
  GUEST_TR_LIMIT = 0x0000480e,
  GUEST_GDTR_LIMIT = 0x00004810,
  GUEST_IDTR_LIMIT = 0x00004812,
  GUEST_ES_AR_BYTES = 0x00004814,
  GUEST_CS_AR_BYTES = 0x00004816,
  GUEST_SS_AR_BYTES = 0x00004818,
  GUEST_DS_AR_BYTES = 0x0000481a,
  GUEST_FS_AR_BYTES = 0x0000481c,
  GUEST_GS_AR_BYTES = 0x0000481e,
  GUEST_LDTR_AR_BYTES = 0x00004820,
  GUEST_TR_AR_BYTES = 0x00004822,
  GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
  GUEST_ACTIVITY_STATE = 0x00004826,
  GUEST_SMBASE = 0x00004828,
  GUEST_SYSENTER_CS = 0x0000482a,
  VMX_PREEMPTION_TIMER_VALUE = 0x0000482e,
  HOST_IA32_SYSENTER_CS = 0x00004c00,  // 32-Bit Host-State Field
  CR0_GUEST_HOST_MASK = 0x00006000,    // Natural-Width Control Fields
  CR4_GUEST_HOST_MASK = 0x00006002,
  CR0_READ_SHADOW = 0x00006004,
  CR4_READ_SHADOW = 0x00006006,
  CR3_TARGET_VALUE0 = 0x00006008,
  CR3_TARGET_VALUE1 = 0x0000600a,
  CR3_TARGET_VALUE2 = 0x0000600c,
  CR3_TARGET_VALUE3 = 0x0000600e,
  EXIT_QUALIFICATION = 0x00006400,  // Natural-Width Read-Only Data Fields
  IO_RCX = 0x00006402,
  IO_RSI = 0x00006404,
  IO_RDI = 0x00006406,
  IO_RIP = 0x00006408,
  GUEST_LINEAR_ADDRESS = 0x0000640a,
  GUEST_CR0 = 0x00006800,  // Natural-Width Guest-State Fields
  GUEST_CR3 = 0x00006802,
  GUEST_CR4 = 0x00006804,
  GUEST_ES_BASE = 0x00006806,
  GUEST_CS_BASE = 0x00006808,
  GUEST_SS_BASE = 0x0000680a,
  GUEST_DS_BASE = 0x0000680c,
  GUEST_FS_BASE = 0x0000680e,
  GUEST_GS_BASE = 0x00006810,
  GUEST_LDTR_BASE = 0x00006812,
  GUEST_TR_BASE = 0x00006814,
  GUEST_GDTR_BASE = 0x00006816,
  GUEST_IDTR_BASE = 0x00006818,
  GUEST_DR7 = 0x0000681a,
  GUEST_RSP = 0x0000681c,
  GUEST_RIP = 0x0000681e,
  GUEST_RFLAGS = 0x00006820,
  GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
  GUEST_SYSENTER_ESP = 0x00006824,
  GUEST_SYSENTER_EIP = 0x00006826,
  HOST_CR0 = 0x00006c00,  // Natural-Width Host-State Fields
  HOST_CR3 = 0x00006c02,
  HOST_CR4 = 0x00006c04,
  HOST_FS_BASE = 0x00006c06,
  HOST_GS_BASE = 0x00006c08,
  HOST_TR_BASE = 0x00006c0a,
  HOST_GDTR_BASE = 0x00006c0c,
  HOST_IDTR_BASE = 0x00006c0e,
  HOST_IA32_SYSENTER_ESP = 0x00006c10,
  HOST_IA32_SYSENTER_EIP = 0x00006c12,
  HOST_RSP = 0x00006c14,
  HOST_RIP = 0x00006c16
};

// VMX BASIC EXIT REASONS
enum VMX_EXIT_REASON : UINT16 {
  EXIT_REASON_EXCEPTION_NMI = 0,
  EXIT_REASON_EXTERNAL_INTERRUPT = 1,
  EXIT_REASON_TRIPLE_FAULT = 2,
  EXIT_REASON_INIT = 3,
  EXIT_REASON_SIPI = 4,
  EXIT_REASON_IO_SMI = 5,
  EXIT_REASON_OTHER_SMI = 6,
  EXIT_REASON_PENDING_INTERRUPT = 7,
  EXIT_REASON_NMI_WINDOW = 8,
  EXIT_REASON_TASK_SWITCH = 9,
  EXIT_REASON_CPUID = 10,
  EXIT_REASON_GETSEC = 11,
  EXIT_REASON_HLT = 12,
  EXIT_REASON_INVD = 13,
  EXIT_REASON_INVLPG = 14,
  EXIT_REASON_RDPMC = 15,
  EXIT_REASON_RDTSC = 16,
  EXIT_REASON_RSM = 17,
  EXIT_REASON_VMCALL = 18,
  EXIT_REASON_VMCLEAR = 19,
  EXIT_REASON_VMLAUNCH = 20,
  EXIT_REASON_VMPTRLD = 21,
  EXIT_REASON_VMPTRST = 22,
  EXIT_REASON_VMREAD = 23,
  EXIT_REASON_VMRESUME = 24,
  EXIT_REASON_VMWRITE = 25,
  EXIT_REASON_VMOFF = 26,
  EXIT_REASON_VMON = 27,
  EXIT_REASON_CR_ACCESS = 28,
  EXIT_REASON_DR_ACCESS = 29,
  EXIT_REASON_IO_INSTRUCTION = 30,
  EXIT_REASON_MSR_READ = 31,
  EXIT_REASON_MSR_WRITE = 32,
  EXIT_REASON_INVALID_GUEST_STATE = 33,
  EXIT_REASON_MSR_LOADING = 34,
  EXIT_REASON_UNDEFINED_35 = 35,
  EXIT_REASON_MWAIT_INSTRUCTION = 36,
  EXIT_REASON_MONITOR_TRAP_FLAG = 37,
  EXIT_REASON_UNDEFINED_38 = 38,
  EXIT_REASON_MONITOR_INSTRUCTION = 39,
  EXIT_REASON_PAUSE_INSTRUCTION = 40,
  EXIT_REASON_MACHINE_CHECK = 41,
  EXIT_REASON_UNDEFINED_42 = 42,
  EXIT_REASON_TPR_BELOW_THRESHOLD = 43,
  EXIT_REASON_APIC_ACCESS = 44,
  EXIT_REASON_VIRTUALIZED_EOI = 45,
  EXIT_REASON_GDTR_OR_IDTR_ACCESS = 46,
  EXIT_REASON_LDTR_OR_TR_ACCESS = 47,
  EXIT_REASON_EPT_VIOLATION = 48,
  EXIT_REASON_EPT_MISCONFIG = 49,
  EXIT_REASON_INVEPT = 50,
  EXIT_REASON_RDTSCP = 51,
  EXIT_REASON_VMX_PREEMPTION_TIME = 52,
  EXIT_REASON_INVVPID = 53,
  EXIT_REASON_WBINVD = 54,
  EXIT_REASON_XSETBV = 55,
  EXIT_REASON_APIC_WRITE = 56,
  EXIT_REASON_RDRAND = 57,
  EXIT_REASON_INVPCID = 58,
  EXIT_REASON_VMFUNC = 59,
  EXIT_REASON_UNDEFINED_60 = 60,
  EXIT_REASON_RDSEED = 61,
  EXIT_REASON_UNDEFINED_62 = 62,
  EXIT_REASON_XSAVES = 63,
  EXIT_REASON_XRSTORS = 64,
};
static_assert(sizeof(VMX_EXIT_REASON) == 2, "Size check");

// VM-instruction error numbers
enum VMX_ERROR_NUMBERS {
  VMXERR_VMCALL_IN_VMX_ROOT_OPERATION = 1,
  VMXERR_VMCLEAR_INVALID_ADDRESS = 2,
  VMXERR_VMCLEAR_VMXON_POINTER = 3,
  VMXERR_VMLAUNCH_NONCLEAR_VMCS = 4,
  VMXERR_VMRESUME_NONLAUNCHED_VMCS = 5,
  VMXERR_VMRESUME_AFTER_VMXOFF = 6,
  VMXERR_ENTRY_INVALID_CONTROL_FIELD = 7,
  VMXERR_ENTRY_INVALID_HOST_STATE_FIELD = 8,
  VMXERR_VMPTRLD_INVALID_ADDRESS = 9,
  VMXERR_VMPTRLD_VMXON_POINTER = 10,
  VMXERR_VMPTRLD_INCORRECT_VMCS_REVISION_ID = 11,
  VMXERR_UNSUPPORTED_VMCS_COMPONENT = 12,
  VMXERR_VMWRITE_READ_ONLY_VMCS_COMPONENT = 13,
  VMXERR_VMXON_IN_VMX_ROOT_OPERATION = 15,
  VMXERR_ENTRY_INVALID_EXECUTIVE_VMCS_POINTER = 16,
  VMXERR_ENTRY_NONLAUNCHED_EXECUTIVE_VMCS = 17,
  VMXERR_ENTRY_EXECUTIVE_VMCS_POINTER_NOT_VMXON_POINTER = 18,
  VMXERR_VMCALL_NONCLEAR_VMCS = 19,
  VMXERR_VMCALL_INVALID_VM_EXIT_CONTROL_FIELDS = 20,
  VMXERR_VMCALL_INCORRECT_MSEG_REVISION_ID = 22,
  VMXERR_VMXOFF_UNDER_DUAL_MONITOR_TREATMENT_OF_SMIS_AND_SMM = 23,
  VMXERR_VMCALL_INVALID_SMM_MONITOR_FEATURES = 24,
  VMXERR_ENTRY_INVALID_VM_EXECUTION_CONTROL_FIELDS_IN_EXECUTIVE_VMCS = 25,
  VMXERR_ENTRY_EVENTS_BLOCKED_BY_MOV_SS = 26,
  VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID = 28,
};

////////////////////////////////////////////////////////////////////////////////
//
// types
//

//
// Virtual-Machine Control Structures
// FORMAT OF THE VMCS REGION
//
struct VMCS {
  ULONG RevisionIdentifier;
  ULONG VmxAbortIndicator;
  ULONG Data[1];  // implementation-specific format.
};

//
// Pin-Based VM-Execution Controls
//
union VMX_PIN_BASED_CONTROLS {
  unsigned int All;
  struct {
    unsigned ExternalInterruptExiting : 1;    // [0]
    unsigned Reserved1 : 2;                   // [1-2]
    unsigned NMIExiting : 1;                  // [3]
    unsigned Reserved2 : 1;                   // [4]
    unsigned VirtualNMIs : 1;                 // [5]
    unsigned ActivateVMXPreemptionTimer : 1;  // [6]
    unsigned ProcessPostedInterrupts : 1;     // [7]
  } Fields;
};
static_assert(sizeof(VMX_PIN_BASED_CONTROLS) == 4, "Size check");

union VMX_CPU_BASED_CONTROLS {
  unsigned int All;
  struct {
    unsigned Reserved1 : 2;                 // [0-1]
    unsigned InterruptWindowExiting : 1;    // [2]
    unsigned UseTSCOffseting : 1;           // [3]
    unsigned Reserved2 : 3;                 // [4-6]
    unsigned HLTExiting : 1;                // [7]
    unsigned Reserved3 : 1;                 // [8]
    unsigned INVLPGExiting : 1;             // [9]
    unsigned MWAITExiting : 1;              // [10]
    unsigned RDPMCExiting : 1;              // [11]
    unsigned RDTSCExiting : 1;              // [12]
    unsigned Reserved4 : 2;                 // [13-14]
    unsigned CR3LoadExiting : 1;            // [15]
    unsigned CR3StoreExiting : 1;           // [16]
    unsigned Reserved5 : 2;                 // [17-18]
    unsigned CR8LoadExiting : 1;            // [19]
    unsigned CR8StoreExiting : 1;           // [20]
    unsigned UseTPRShadowExiting : 1;       // [21]
    unsigned NMIWindowExiting : 1;          // [22]
    unsigned MovDRExiting : 1;              // [23]
    unsigned UnconditionalIOExiting : 1;    // [24]
    unsigned UseIOBitmaps : 1;              // [25]
    unsigned Reserved6 : 1;                 // [26]
    unsigned MonitorTrapFlag : 1;           // [27]
    unsigned UseMSRBitmaps : 1;             // [28]
    unsigned MONITORExiting : 1;            // [29]
    unsigned PAUSEExiting : 1;              // [30]
    unsigned ActivateSecondaryControl : 1;  // [31]
  } Fields;
};
static_assert(sizeof(VMX_CPU_BASED_CONTROLS) == 4, "Size check");

union VMX_SECONDARY_CPU_BASED_CONTROLS {
  unsigned int All;
  struct {
    unsigned VirtualizeAPICAccesses : 1;      // [0]
    unsigned EnableEPT : 1;                   // [1]
    unsigned DescriptorTableExiting : 1;      // [2]
    unsigned EnableRDTSCP : 1;                // [3]
    unsigned VirtualizeX2APICMode : 1;        // [4]
    unsigned EnableVPID : 1;                  // [5]
    unsigned WBINVDExiting : 1;               // [6]
    unsigned UnrestrictedGuest : 1;           // [7]
    unsigned APICRegisterVirtualization : 1;  // [8]
    unsigned VirtualInterruptDelivery : 1;    // [9]
    unsigned PAUSELoopExiting : 1;            // [10]
    unsigned RDRANDExiting : 1;               // [11]
    unsigned EnableINVPCID : 1;               // [12]
    unsigned EnableVMFunctions : 1;           // [13]
    unsigned VMCSShadowing : 1;               // [14]
    unsigned Reserved1 : 1;                   // [15]
    unsigned RDSEEDExiting : 1;               // [16]
    unsigned Reserved2 : 1;                   // [17]
    unsigned EPTViolation : 1;                // [18]
    unsigned Reserved3 : 1;                   // [19]
    unsigned EnableXSAVESXSTORS : 1;          // [20]
  } Fields;
};
static_assert(sizeof(VMX_SECONDARY_CPU_BASED_CONTROLS) == 4, "Size check");

union VMX_VM_EXIT_CONTROLS {
  unsigned int All;
  struct {
    unsigned Reserved1 : 2;                    // [0-1]
    unsigned SaveDebugControls : 1;            // [2]
    unsigned Reserved2 : 6;                    // [3-8]
    unsigned HostAddressSpaceSize : 1;         // [9]
    unsigned Reserved3 : 2;                    // [10-11]
    unsigned LoadIA32_PERF_GLOBAL_CTRL : 1;    // [12]
    unsigned Reserved4 : 2;                    // [13-14]
    unsigned AcknowledgeInterruptOnExit : 1;   // [15]
    unsigned Reserved5 : 2;                    // [16-17]
    unsigned SaveIA32_PAT : 1;                 // [18]
    unsigned LoadIA32_PAT : 1;                 // [19]
    unsigned SaveIA32_EFER : 1;                // [20]
    unsigned LoadIA32_EFER : 1;                // [21]
    unsigned SaveVMXPreemptionTimerValue : 1;  // [22]
  } Fields;
};
static_assert(sizeof(VMX_VM_EXIT_CONTROLS) == 4, "Size check");

union VMX_VM_ENTER_CONTROLS {
  unsigned int All;
  struct {
    unsigned Reserved1 : 2;                       // [0-1]
    unsigned LoadDebugControls : 1;               // [2]
    unsigned Reserved2 : 6;                       // [3-8]
    unsigned IA32eModeGuest : 1;                  // [9]
    unsigned EntryToSMM : 1;                      // [10]
    unsigned DeactivateDualMonitorTreatment : 1;  // [11]
    unsigned Reserved3 : 1;                       // [12]
    unsigned LoadIA32_PERF_GLOBAL_CTRL : 1;       // [13]
    unsigned LoadIA32_PAT : 1;                    // [14]
    unsigned LoadIA32_EFER : 1;                   // [15]
  } Fields;
};
static_assert(sizeof(VMX_VM_EXIT_CONTROLS) == 4, "Size check");

//
// Guest Register State
//
union VMX_SEG_DESCRIPTOR_ACCESS_RIGHT {
  unsigned int All;
  struct {
    unsigned Type : 4;
    unsigned System : 1;
    unsigned DPL : 2;
    unsigned Present : 1;
    unsigned Reserved1 : 4;
    unsigned AVL : 1;
    unsigned L : 1;  // Reserved (except for CS) 64-bit mode active (for CS)
    unsigned DB : 1;
    unsigned Gran : 1;
    unsigned Unusable : 1;  // Segment unusable (0 = usable; 1 = unusable)
    unsigned Reserved2 : 15;
  } Fields;
};
static_assert(sizeof(VMX_SEG_DESCRIPTOR_ACCESS_RIGHT) == 4, "Size check");

//
// IA32_FEATURE_CONTROL_MSR
// ARCHITECTURAL MSRS
//
union IA32_FEATURE_CONTROL_MSR {
  unsigned __int64 All;
  struct {
    unsigned Lock : 1;                // [0]
    unsigned EnableSMX : 1;           // [1]
    unsigned EnableVmxon : 1;         // [2]
    unsigned Reserved2 : 5;           // [3-7]
    unsigned EnableLocalSENTER : 7;   // [8-14]
    unsigned EnableGlobalSENTER : 1;  // [15]
    unsigned Reserved3a : 16;         //
    unsigned Reserved3b : 32;         // [16-63]
  } Fields;
};
static_assert(sizeof(IA32_FEATURE_CONTROL_MSR) == 8, "Size check");

//
// IA32_VMX_BASIC_MSR
// BASIC VMX INFORMATION
//
union IA32_VMX_BASIC_MSR {
  unsigned __int64 All;
  struct {
    unsigned RevisionIdentifier : 31;   // [0-30]
    unsigned Reserved1 : 1;             // [31]
    unsigned RegionSize : 12;           // [32-43]
    unsigned RegionClear : 1;           // [44]
    unsigned Reserved2 : 3;             // [45-47]
    unsigned SupportedIA64 : 1;         // [48]
    unsigned SupportedDualMoniter : 1;  // [49]
    unsigned MemoryType : 4;            // [50-53]
    unsigned VmExitReport : 1;          // [54]
    unsigned VmxCapabilityHint : 1;     // [55]
    unsigned Reserved3 : 8;             // [56-63]
  } Fields;
};
static_assert(sizeof(IA32_VMX_BASIC_MSR) == 8, "Size check");

//
// IA32_VMX_MISC_MSR
// MISCELLANEOUS DATA
//
union IA32_VMX_MISC_MSR {
  unsigned __int64 All;
  struct {
    unsigned TimeStamp : 5;                            // [0-4]
    unsigned Reserved1 : 1;                            // [5]
    unsigned SupportedActivityStateHLT : 1;            // [6]
    unsigned SupportedActivityStateShutdown : 1;       // [7]
    unsigned SupportedActivityStateWaitForSIPI : 1;    // [8]
    unsigned Reserved2 : 6;                            // [9-14]
    unsigned SupportedReadIA32_SMBASE_MSR : 1;         // [15]
    unsigned SupportedCR3TargetValueNumber : 8;        // [16-23]
    unsigned SupportedCR3TargetValueNumberClear : 1;   // [24]
    unsigned MaximumMSRsNumber : 3;                    // [25-27]
    unsigned SuppoetedChangeIA32_SMM_MONITOR_CTL : 1;  // [28]
    unsigned SuppoetedVmWriteVmExitInformation : 1;    // [29]
    unsigned Reserved3 : 2;                            // [30-31]
    unsigned RevisionIdentifier : 32;                  // [32-63]
  } Fields;
};
static_assert(sizeof(IA32_VMX_MISC_MSR) == 8, "Size check");

//
// IA32_VMX_VMCS_ENUM_MSR
// VMCS ENUMERATION
//
union IA32_VMX_VMCS_ENUM_MSR {
  unsigned __int64 All;
  struct {
    unsigned Reserved1 : 1;                     // [0]
    unsigned SupportedHighestVMCSEncoding : 9;  // [1-9]
    unsigned Reserved2a : 22;                   //
    unsigned Reserved2b : 32;                   // [10-63]
  } Fields;
};
static_assert(sizeof(IA32_VMX_VMCS_ENUM_MSR) == 8, "Size check");

//
// IA32_VMX_EPT_VPID_CAP_MSR
// VPID AND EPT CAPABILITIES
//
union IA32_VMX_EPT_VPID_CAP_MSR {
  unsigned __int64 All;
  struct {
    unsigned SupportedEPT : 1;                                   // [0]
    unsigned Reserved1 : 5;                                      // [1-5]
    unsigned SupportedPageWalkLength4 : 1;                       // [6]
    unsigned Reserved2 : 1;                                      // [7]
    unsigned SupportedUncachebleMemoryType : 1;                  // [8]
    unsigned Reserved3 : 5;                                      // [9-13]
    unsigned SupportedWriteBackMemoryType : 1;                   // [14]
    unsigned Reserved4 : 1;                                      // [15]
    unsigned SupportedPDE2MBPage : 1;                            // [16]
    unsigned Reserved5 : 3;                                      // [17-19]
    unsigned SupportedINVEPT : 1;                                // [20]
    unsigned Reserved6 : 4;                                      // [21-24]
    unsigned SupportedSingleContextINVEPT : 1;                   // [25]
    unsigned SupportedAllContextINVEPT : 1;                      // [26]
    unsigned Reserved7 : 5;                                      // [27-31]
    unsigned SupportedINVVPID : 1;                               // [32]
    unsigned Reserved8 : 7;                                      // [33-39]
    unsigned SupportedIndividualAddressINVVPID : 1;              // [40]
    unsigned SupportedSingleContextINVVPID : 1;                  // [41]
    unsigned SupportedAllContextINVVPID : 1;                     // [42]
    unsigned SupportedSingleContextRetainingGlobalsINVVPID : 1;  // [43]
    unsigned Reserved9 : 20;                                     // [44-63]
  } Fields;
};
static_assert(sizeof(IA32_VMX_EPT_VPID_CAP_MSR) == 8, "Size check");

// VM-ENTRY FAILURES DURING OR AFTER LOADING GUEST STATE
union VM_EXIT_INFORMATION {
  ULONG32 All;
  struct {
    VMX_EXIT_REASON Reason;             // [0:15]
    unsigned short Reserved : 15;       // [16:30]
    unsigned short VMEntryFailure : 1;  // [31]
  } Fields;
};
static_assert(sizeof(VM_EXIT_INFORMATION) == 4, "Size check");

// Format of the VM-Exit Instruction-Information Field as Used for
// LIDT, LGDT, SIDT, or SGDT
enum GDTR_OR_IDTR_SCALING {
  NO_SCALING = 0,
  SCALE_BY_2,
  SCALE_BY_4,
  SCALE_BY_8,
};

enum GDTR_OR_IDTR_ADDRESS_SIZE {
  BIT_16 = 0,
  BIT_32,
  BIT_64,
};

enum GDTR_OR_IDTR_SEGMENT_REGISTERS {
  ES = 0,
  CS,
  SS,
  DS,
  FS,
  GS,
};

enum GDTR_OR_IDTR_INSTRUCTION_IDENTITY {
  SGDT = 0,
  SIDT,
  LGDT,
  LIDT,
};

union GDTR_OR_IDTR_ACCESS_QUALIFICATION {
  ULONG32 All;
  struct {
    unsigned Scalling : 2;
    unsigned Reserved1 : 5;
    unsigned AddressSize : 3;
    unsigned Reserved2 : 1;
    unsigned OperandSize : 1;
    unsigned Reserved3 : 3;
    unsigned SegmentRegister : 3;
    unsigned IndexRegister : 4;
    unsigned IndexRegisterInvalid : 1;
    unsigned BaseRegister : 4;
    unsigned BaseRegisterInvalid : 1;
    unsigned InstructionIdentity : 2;
    unsigned Reserved4 : 2;
  } Fields;
};
static_assert(sizeof(GDTR_OR_IDTR_ACCESS_QUALIFICATION) == 4, "Size check");

// Format of the VM-Exit Instruction-Information Field as Used for
// LLDT, LTR, SLDT, and STR
enum LDTR_OR_TR_INSTRUCTION_IDENTITY {
  SLDT = 0,
  STR,
  LLDT,
  LTR,
};

union LDTR_OR_TR_ACCESS_QUALIFICATION {
  ULONG32 All;
  struct {
    unsigned Scalling : 2;
    unsigned Reserved1 : 1;
    unsigned Register1 : 4;
    unsigned AddressSize : 3;
    unsigned RegisterAccess : 1;
    unsigned Reserved2 : 4;
    unsigned SegmentRegister : 3;
    unsigned IndexRegister : 4;
    unsigned IndexRegisterInvalid : 1;
    unsigned BaseRegister : 4;
    unsigned BaseRegisterInvalid : 1;
    unsigned InstructionIdentity : 2;
    unsigned Reserved4 : 2;
  } Fields;
};
static_assert(sizeof(LDTR_OR_TR_ACCESS_QUALIFICATION) == 4, "Size check");

// Exit Qualification for MOV DR
enum MOV_DR_DIRECTION {
  MOVE_TO_DR = 0,
  MOVE_FROM_DR,
};

union MOV_DR_QUALIFICATION {
  ULONG_PTR All;
  struct {
    unsigned DebuglRegister : 3;
    unsigned Reserved1 : 1;
    unsigned Direction : 1;
    unsigned Reserved2 : 3;
    unsigned Register : 4;
    unsigned Reserved3 : 20;
    // unsigned Reserved4 : 32;
  } Fields;
};
static_assert(sizeof(MOV_DR_QUALIFICATION) == 8, "Size check");

// Exit Qualification for Control-Register Accesses
enum MOV_CR_ACCESS_TYPE {
  MOVE_TO_CR = 0,
  MOVE_FROM_CR,
  CLTS,
  LMSW,
};

union MOV_CR_QUALIFICATION {
  ULONG_PTR All;
  struct {
    unsigned ControlRegister : 4;
    unsigned AccessType : 2;
    unsigned LMSWOperandType : 1;
    unsigned Reserved1 : 1;
    unsigned Register : 4;
    unsigned Reserved2 : 4;
    unsigned LMSWSourceData : 16;
    // unsigned Reserved3 : 32;
  } Fields;
};
static_assert(sizeof(MOV_CR_QUALIFICATION) == 8, "Size check");

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//
