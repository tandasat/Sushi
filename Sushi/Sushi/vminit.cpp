// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module defines VMM initialization functions.
//
#include "stdafx.h"
#include "vminit.h"
#include "misc.h"
#include "ia32_type.h"
#include "vmx_type.h"
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

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C static bool VminitpIsVmxAvailable();

EXTERN_C static void VminitpInitializeVM(
    _In_ ULONG_PTR GuestStackPointer, _In_ ULONG_PTR GuestInstructionPointer);

EXTERN_C static bool VminitpEnterVmxMode(
    _Inout_ PER_PROCESSOR_DATA *ProcessorData);

EXTERN_C static bool VminitpInitializeVMCS(
    _Inout_ PER_PROCESSOR_DATA *ProcessorData);

EXTERN_C static bool VminitpSetupVMCS(
    _In_ const PER_PROCESSOR_DATA *ProcessorData,
    _In_ ULONG_PTR GuestStackPointer, _In_ ULONG_PTR GuestInstructionPointer,
    _In_ ULONG_PTR VmmStackPointer);

EXTERN_C static void VminitpLaunchVM();

EXTERN_C static ULONG VminitpGetSegmentAccessRight(_In_ USHORT SegmentSelector);

EXTERN_C static SEG_DESCRIPTOR *VminitpGetSegmentDescriptor(
    _In_ ULONG_PTR DescriptorTableBase, _In_ USHORT SegmentSelector);

EXTERN_C static ULONG_PTR VminitpGetSegmentBaseByDescriptor(
    _In_ const SEG_DESCRIPTOR *SegmentDescriptor);

EXTERN_C static ULONG_PTR VminitpGetSegmentBase(_In_ ULONG_PTR GdtBase,
                                                _In_ USHORT SegmentSelector);

EXTERN_C static ULONG VminitpAdjustByRdmsr(_In_ ULONG MsrNumber,
                                           _In_ ULONG RequestedValue);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

ALLOC_TEXT(INIT, VminitStartVM)
_Use_decl_annotations_ EXTERN_C NTSTATUS VminitStartVM(void *Context) {
  UNREFERENCED_PARAMETER(Context);

  LOG_INFO("Initializing VMX for the processor %d.",
            KeGetCurrentProcessorNumber());

  if (!VminitpIsVmxAvailable()) {
    return STATUS_UNSUCCESSFUL;
  }

  if (!AsmInitialieVM(VminitpInitializeVM)) {
    return STATUS_UNSUCCESSFUL;
  }
  LOG_INFO("Initialized successfully.");
  return STATUS_SUCCESS;
}

ALLOC_TEXT(INIT, VminitpIsVmxAvailable)
_Use_decl_annotations_ EXTERN_C static bool VminitpIsVmxAvailable() {
  // DISCOVERING SUPPORT FOR VMX
  // If CPUID.1:ECX.VMX[bit 5]=1, then VMX operation is supported.
  int cpuInfo[4] = {};
  __cpuid(cpuInfo, 1);
  CPU_FEATURES_ECX cpuFeatures = {static_cast<ULONG_PTR>(cpuInfo[2])};
  if (!cpuFeatures.Fields.VMX) {
    LOG_ERROR("VMX features are not supported.");
    return false;
  }

  // BASIC VMX INFORMATION
  // The first processors to support VMX operation use the write-back type.
  IA32_VMX_BASIC_MSR vmxBasicMsr = {__readmsr(IA32_VMX_BASIC)};
  if (vmxBasicMsr.Fields.MemoryType != 6)  // Write Back (WB)
  {
    LOG_ERROR("Write-back cache type is not supported.");
    return false;
  }

  // ENABLING AND ENTERING VMX OPERATION
  IA32_FEATURE_CONTROL_MSR vmxFeatureControl = {
      __readmsr(IA32_FEATURE_CONTROL)};
  if (!vmxFeatureControl.Fields.Lock || !vmxFeatureControl.Fields.EnableVmxon) {
    LOG_ERROR("VMX features are not enabled.");
    return false;
  }

  return true;
}

ALLOC_TEXT(INIT, VminitpInitializeVM)
_Use_decl_annotations_ EXTERN_C static void VminitpInitializeVM(
    ULONG_PTR GuestStackPointer, ULONG_PTR GuestInstructionPointer) {
  auto ProcessorData =
      reinterpret_cast<PER_PROCESSOR_DATA *>(ExAllocatePoolWithTag(
          NonPagedPoolNx, sizeof(PER_PROCESSOR_DATA), SUSHI_POOL_TAG_NAME));
  auto VmmStackTop = MiscAllocateContiguousMemory(KERNEL_STACK_SIZE);
  auto VmcsRegion =
      reinterpret_cast<VMCS *>(MiscAllocateContiguousMemory(MAXIMUM_VMCS_SIZE));
  auto VmxonRegion =
      reinterpret_cast<VMCS *>(MiscAllocateContiguousMemory(MAXIMUM_VMCS_SIZE));
  auto msrBitmap = MiscAllocateContiguousMemory(PAGE_SIZE);
  if (!ProcessorData || !VmmStackTop || !VmcsRegion || !VmxonRegion ||
      !msrBitmap) {
    goto ReturnFalse;
  }
  RtlZeroMemory(ProcessorData, sizeof(PER_PROCESSOR_DATA));
  RtlZeroMemory(VmmStackTop, KERNEL_STACK_SIZE);
  RtlZeroMemory(VmcsRegion, MAXIMUM_VMCS_SIZE);
  RtlZeroMemory(VmxonRegion, MAXIMUM_VMCS_SIZE);
  RtlZeroMemory(msrBitmap, PAGE_SIZE);
  /*
  (High)
  +------------------+
  | ProcessorData    |  <- VmmStackData
  +------------------+
  | ffffffffffffffff |  <- VmmStackBase
  +------------------+    v
  |                  |    v
  |   VmmStack       |    v (grow)
  |                  |    v
  +------------------+  <- VmmStackTop
  (Low)
  */
  const auto VmmStackBottom =
      reinterpret_cast<ULONG_PTR>(VmmStackTop) + KERNEL_STACK_SIZE;
  const auto VmmStackData = VmmStackBottom - sizeof(void *);
  const auto VmmStackBase = VmmStackData - sizeof(void *);
  LOG_DEBUG("VmmStackTop=       %p", VmmStackTop);
  LOG_DEBUG("VmmStackBottom=    %p", VmmStackBottom);
  LOG_DEBUG("VmmStackData=      %p", VmmStackData);
  LOG_DEBUG("ProcessorData=     %p stored at %p", ProcessorData, VmmStackData);
  LOG_DEBUG("VmmStackBase=      %p", VmmStackBase);
  LOG_DEBUG("GuestStackPointer= %p", GuestStackPointer);
  *reinterpret_cast<ULONG_PTR *>(VmmStackBase) = 0xffffffffffffffff;
  *reinterpret_cast<PER_PROCESSOR_DATA **>(VmmStackData) = ProcessorData;
  ProcessorData->VmmStackTop = VmmStackTop;
  ProcessorData->VmcsRegion = VmcsRegion;
  ProcessorData->VmxonRegion = VmxonRegion;
  ProcessorData->MsrBitmap = msrBitmap;
  if (!VminitpEnterVmxMode(ProcessorData)) {
    goto ReturnFalse;
  }
  if (!VminitpInitializeVMCS(ProcessorData)) {
    goto ReturnFalseWithVmxOff;
  }
  if (!VminitpSetupVMCS(ProcessorData, GuestStackPointer,
                        GuestInstructionPointer, VmmStackBase)) {
    goto ReturnFalseWithVmxOff;
  }

  VminitpLaunchVM();

ReturnFalseWithVmxOff:;
  __vmx_off();

ReturnFalse:;
  if (ProcessorData) {
    ExFreePoolWithTag(ProcessorData, SUSHI_POOL_TAG_NAME);
  }
  if (VmmStackTop) {
    MiscFreeContiguousMemory(VmmStackTop);
  }
  if (VmcsRegion) {
    MiscFreeContiguousMemory(VmcsRegion);
  }
  if (VmxonRegion) {
    MiscFreeContiguousMemory(VmxonRegion);
  }
  if (msrBitmap) {
    MiscFreeContiguousMemory(msrBitmap);
  }
}

// VMM SETUP & TEAR DOWN
ALLOC_TEXT(INIT, VminitpEnterVmxMode)
_Use_decl_annotations_ EXTERN_C static bool VminitpEnterVmxMode(
    PER_PROCESSOR_DATA *ProcessorData) {
  // apply FIXED bits
  const CR0_REG cr0Fixed0 = {__readmsr(IA32_VMX_CR0_FIXED0)};
  const CR0_REG cr0Fixed1 = {__readmsr(IA32_VMX_CR0_FIXED1)};
  CR0_REG cr0 = {__readcr0()};
  cr0.All &= cr0Fixed1.All;
  cr0.All |= cr0Fixed0.All;
  __writecr0(cr0.All);

  const CR4_REG cr4Fixed0 = {__readmsr(IA32_VMX_CR4_FIXED0)};
  const CR4_REG cr4Fixed1 = {__readmsr(IA32_VMX_CR4_FIXED1)};
  CR4_REG cr4 = {__readcr4()};
  cr4.All &= cr4Fixed1.All;
  cr4.All |= cr4Fixed0.All;
  __writecr4(cr4.All);

  // Write a VMCS revision identifier
  IA32_VMX_BASIC_MSR vmxBasicMsr = {__readmsr(IA32_VMX_BASIC)};
  ProcessorData->VmxonRegion->RevisionIdentifier =
      vmxBasicMsr.Fields.RevisionIdentifier;

  auto vmxonRegionPA = MmGetPhysicalAddress(ProcessorData->VmxonRegion);
  if (__vmx_on(
          reinterpret_cast<unsigned long long *>(&vmxonRegionPA.QuadPart))) {
    return false;
  }
  return true;
}

// VMM SETUP & TEAR DOWN
ALLOC_TEXT(INIT, VminitpInitializeVMCS)
_Use_decl_annotations_ EXTERN_C static bool VminitpInitializeVMCS(
    PER_PROCESSOR_DATA *ProcessorData) {
  // write a VMCS revision identifier
  IA32_VMX_BASIC_MSR vmxBasicMsr = {__readmsr(IA32_VMX_BASIC)};
  ProcessorData->VmcsRegion->RevisionIdentifier =
      vmxBasicMsr.Fields.RevisionIdentifier;

  auto vmcsRegionPA = MmGetPhysicalAddress(ProcessorData->VmcsRegion);

  // It stores the value FFFFFFFF_FFFFFFFFH if there is no current VMCS
  if (__vmx_vmclear(
          reinterpret_cast<unsigned long long *>(&vmcsRegionPA.QuadPart))) {
    return false;
  }

  // Software makes a VMCS current by executing VMPTRLD with the address
  // of the VMCS; that address is loaded into the current-VMCS pointer .
  if (__vmx_vmptrld(
          reinterpret_cast<unsigned long long *>(&vmcsRegionPA.QuadPart))) {
    return false;
  }

  // the launch state of current VMCS is "clear"
  return true;
}

// PREPARATION AND LAUNCHING A VIRTUAL MACHINE
ALLOC_TEXT(INIT, VminitpSetupVMCS)
_Use_decl_annotations_ EXTERN_C static bool VminitpSetupVMCS(
    const PER_PROCESSOR_DATA *ProcessorData, ULONG_PTR GuestStackPointer,
    ULONG_PTR GuestInstructionPointer, ULONG_PTR VmmStackPointer) {
  unsigned char error = 0;

  GDTR gdtr = {};
  __sgdt(&gdtr);

  IDTR idtr = {};
  __sidt(&idtr);

  VMX_VM_ENTER_CONTROLS vmEnterCtlRequested = {};
  vmEnterCtlRequested.Fields.IA32eModeGuest = true;
  VMX_VM_ENTER_CONTROLS vmEnterCtl = {
      VminitpAdjustByRdmsr(IA32_VMX_ENTRY_CTLS, vmEnterCtlRequested.All)};

  VMX_VM_EXIT_CONTROLS vmExitCtlRequested = {};
  vmExitCtlRequested.Fields.AcknowledgeInterruptOnExit = true;
  vmExitCtlRequested.Fields.HostAddressSpaceSize = true;
  VMX_VM_EXIT_CONTROLS vmExitCtl = {
      VminitpAdjustByRdmsr(IA32_VMX_EXIT_CTLS, vmExitCtlRequested.All)};

  VMX_PIN_BASED_CONTROLS vmPinCtlRequested = {};
  VMX_PIN_BASED_CONTROLS vmPinCtl = {
      VminitpAdjustByRdmsr(IA32_VMX_PINBASED_CTLS, vmPinCtlRequested.All)};

  VMX_CPU_BASED_CONTROLS vmCpuCtlRequested = {};
  vmCpuCtlRequested.Fields.RDTSCExiting = true;
  vmCpuCtlRequested.Fields.CR3LoadExiting = true;
  vmCpuCtlRequested.Fields.CR3StoreExiting = false;  // No MOV from CR3
  vmCpuCtlRequested.Fields.CR8LoadExiting = true;
  vmCpuCtlRequested.Fields.CR8StoreExiting = false;  // No MOV from CR8
  vmCpuCtlRequested.Fields.MovDRExiting = true;
  vmCpuCtlRequested.Fields.UseMSRBitmaps = true;
  vmCpuCtlRequested.Fields.ActivateSecondaryControl = true;
  VMX_CPU_BASED_CONTROLS vmCpuCtl = {
      VminitpAdjustByRdmsr(IA32_VMX_PROCBASED_CTLS, vmCpuCtlRequested.All)};

  VMX_SECONDARY_CPU_BASED_CONTROLS vmCpuCtl2Requested = {};
  vmCpuCtl2Requested.Fields.EnableRDTSCP = true;
  vmCpuCtl2Requested.Fields.DescriptorTableExiting = true;
  VMX_CPU_BASED_CONTROLS vmCpuCtl2 = {
      VminitpAdjustByRdmsr(IA32_VMX_PROCBASED_CTLS2, vmCpuCtl2Requested.All)};

  // Activate all RDMSR VM exits except for ones against below MSRs
  const auto bitMapReadLow =
      reinterpret_cast<UCHAR *>(ProcessorData->MsrBitmap);
  const auto bitMapReadHigh = bitMapReadLow + 1024;
  RtlFillMemory(bitMapReadLow, 1024, 0xff);   // read        0 -     1fff
  RtlFillMemory(bitMapReadHigh, 1024, 0xff);  // read c0000000 - c0001fff

  // Ignore IA32_MPERF (000000e7) and IA32_APERF (000000e8)
  RTL_BITMAP bitMapReadLowHeader = {};
  RtlInitializeBitMap(&bitMapReadLowHeader,
                      reinterpret_cast<PULONG>(bitMapReadLow), 1024 * 8);
  RtlClearBits(&bitMapReadLowHeader, 0xe7, 2);

  // Ignore IA32_GS_BASE (c0000101) and IA32_KERNEL_GS_BASE (c0000102)
  RTL_BITMAP bitMapReadHighHeader = {};
  RtlInitializeBitMap(&bitMapReadHighHeader,
                      reinterpret_cast<PULONG>(bitMapReadHigh), 1024 * 8);
  RtlClearBits(&bitMapReadHighHeader, 0x101, 2);

  //// Activate all WRMSR VM exits
  // const auto bitMapWriteLow = bitMapReadHigh + 1024;
  // const auto bitMapWriteHigh = bitMapWriteLow + 1024;
  // RtlFillMemory(bitMapWriteLow, 1024, 0xff);   // write        0 -     1fff
  // RtlFillMemory(bitMapWriteHigh, 1024, 0xff);  // write c0000000 - c0001fff

  const auto msrBitmapPA = MmGetPhysicalAddress(ProcessorData->MsrBitmap);

  // clang-format off
  /* 16-Bit Control Field */

  /* 16-Bit Guest-State Fields */
  error |= __vmx_vmwrite(GUEST_ES_SELECTOR, AsmReadES());
  error |= __vmx_vmwrite(GUEST_CS_SELECTOR, AsmReadCS());
  error |= __vmx_vmwrite(GUEST_SS_SELECTOR, AsmReadSS());
  error |= __vmx_vmwrite(GUEST_DS_SELECTOR, AsmReadDS());
  error |= __vmx_vmwrite(GUEST_FS_SELECTOR, AsmReadFS());
  error |= __vmx_vmwrite(GUEST_GS_SELECTOR, AsmReadGS());
  error |= __vmx_vmwrite(GUEST_LDTR_SELECTOR, AsmReadLDTR());
  error |= __vmx_vmwrite(GUEST_TR_SELECTOR, AsmReadTR());

  /* 16-Bit Host-State Fields */
  error |= __vmx_vmwrite(HOST_ES_SELECTOR, AsmReadES() & 0xf8);
  error |= __vmx_vmwrite(HOST_CS_SELECTOR, AsmReadCS() & 0xf8);
  error |= __vmx_vmwrite(HOST_SS_SELECTOR, AsmReadSS() & 0xf8);
  error |= __vmx_vmwrite(HOST_DS_SELECTOR, AsmReadDS() & 0xf8);
  error |= __vmx_vmwrite(HOST_FS_SELECTOR, AsmReadFS() & 0xf8);
  error |= __vmx_vmwrite(HOST_GS_SELECTOR, AsmReadGS() & 0xf8);
  error |= __vmx_vmwrite(HOST_TR_SELECTOR, AsmReadTR() & 0xf8);

  /* 64-Bit Control Fields */

  error |= __vmx_vmwrite(IO_BITMAP_A, 0);
  error |= __vmx_vmwrite(IO_BITMAP_B, 0);
  error |= __vmx_vmwrite(MSR_BITMAP, msrBitmapPA.QuadPart);
  error |= __vmx_vmwrite(TSC_OFFSET, 0);

  /* 64-Bit Guest-State Fields */
  error |= __vmx_vmwrite(VMCS_LINK_POINTER, 0xffffffffffffffff);
  error |= __vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(IA32_DEBUGCTL));

  /* 32-Bit Control Fields */
  error |= __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, vmPinCtl.All);
  error |= __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, vmCpuCtl.All);
  error |= __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, vmCpuCtl2.All);
  error |= __vmx_vmwrite(EXCEPTION_BITMAP, 0);
  error |= __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
  error |= __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);
  error |= __vmx_vmwrite(CR3_TARGET_COUNT, 0);
  error |= __vmx_vmwrite(VM_EXIT_CONTROLS, vmExitCtl.All);
  error |= __vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
  error |= __vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
  error |= __vmx_vmwrite(VM_ENTRY_CONTROLS, vmEnterCtl.All);
  error |= __vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
  error |= __vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

  /* 32-Bit Guest-State Fields */
  error |= __vmx_vmwrite(GUEST_ES_LIMIT, GetSegmentLimit(AsmReadES()));
  error |= __vmx_vmwrite(GUEST_CS_LIMIT, GetSegmentLimit(AsmReadCS()));
  error |= __vmx_vmwrite(GUEST_SS_LIMIT, GetSegmentLimit(AsmReadSS()));
  error |= __vmx_vmwrite(GUEST_DS_LIMIT, GetSegmentLimit(AsmReadDS()));
  error |= __vmx_vmwrite(GUEST_FS_LIMIT, GetSegmentLimit(AsmReadFS()));
  error |= __vmx_vmwrite(GUEST_GS_LIMIT, GetSegmentLimit(AsmReadGS()));
  error |= __vmx_vmwrite(GUEST_LDTR_LIMIT, GetSegmentLimit(AsmReadLDTR()));
  error |= __vmx_vmwrite(GUEST_TR_LIMIT, GetSegmentLimit(AsmReadTR()));
  error |= __vmx_vmwrite(GUEST_GDTR_LIMIT, gdtr.Limit);
  error |= __vmx_vmwrite(GUEST_IDTR_LIMIT, idtr.Limit);
  error |= __vmx_vmwrite(GUEST_ES_AR_BYTES, VminitpGetSegmentAccessRight(AsmReadES()));
  error |= __vmx_vmwrite(GUEST_CS_AR_BYTES, VminitpGetSegmentAccessRight(AsmReadCS()));
  error |= __vmx_vmwrite(GUEST_SS_AR_BYTES, VminitpGetSegmentAccessRight(AsmReadSS()));
  error |= __vmx_vmwrite(GUEST_DS_AR_BYTES, VminitpGetSegmentAccessRight(AsmReadDS()));
  error |= __vmx_vmwrite(GUEST_FS_AR_BYTES, VminitpGetSegmentAccessRight(AsmReadFS()));
  error |= __vmx_vmwrite(GUEST_GS_AR_BYTES, VminitpGetSegmentAccessRight(AsmReadGS()));
  error |= __vmx_vmwrite(GUEST_LDTR_AR_BYTES, VminitpGetSegmentAccessRight(AsmReadLDTR()));
  error |= __vmx_vmwrite(GUEST_TR_AR_BYTES, VminitpGetSegmentAccessRight(AsmReadTR()));
  error |= __vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
  error |= __vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);
  error |= __vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));

  /* 32-Bit Host-State Field */
  error |= __vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));

  /* Natural-Width Control Fields */
  // Where a bit is     masked, the shadow bit appears
  // Where a bit is not masked, the actual bit appears
  CR0_REG cr0mask = {};
  cr0mask.Fields.WP = true;
  CR4_REG cr4mask = {};
  cr4mask.Fields.PGE = true;
  error |= __vmx_vmwrite(CR0_GUEST_HOST_MASK, cr0mask.All);
  error |= __vmx_vmwrite(CR4_GUEST_HOST_MASK, cr4mask.All);
  error |= __vmx_vmwrite(CR0_READ_SHADOW, __readcr0());
  error |= __vmx_vmwrite(CR4_READ_SHADOW, __readcr4());
  error |= __vmx_vmwrite(CR3_TARGET_VALUE0, 0);
  error |= __vmx_vmwrite(CR3_TARGET_VALUE1, 0);
  error |= __vmx_vmwrite(CR3_TARGET_VALUE2, 0);
  error |= __vmx_vmwrite(CR3_TARGET_VALUE3, 0);

  /* Natural-Width Guest-State Fields */
  error |= __vmx_vmwrite(GUEST_CR0, __readcr0());
  error |= __vmx_vmwrite(GUEST_CR3, __readcr3());
  error |= __vmx_vmwrite(GUEST_CR4, __readcr4());
  error |= __vmx_vmwrite(GUEST_ES_BASE, 0);
  error |= __vmx_vmwrite(GUEST_CS_BASE, 0);
  error |= __vmx_vmwrite(GUEST_SS_BASE, 0);
  error |= __vmx_vmwrite(GUEST_DS_BASE, 0);
  error |= __vmx_vmwrite(GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
  error |= __vmx_vmwrite(GUEST_GS_BASE, __readmsr(IA32_GS_BASE));
  error |= __vmx_vmwrite(GUEST_LDTR_BASE, VminitpGetSegmentBase(gdtr.Address, AsmReadLDTR()));
  error |= __vmx_vmwrite(GUEST_TR_BASE, VminitpGetSegmentBase(gdtr.Address, AsmReadTR()));
  error |= __vmx_vmwrite(GUEST_GDTR_BASE, gdtr.Address);
  error |= __vmx_vmwrite(GUEST_IDTR_BASE, idtr.Address);
  error |= __vmx_vmwrite(GUEST_DR7, __readdr(7));
  error |= __vmx_vmwrite(GUEST_RSP, GuestStackPointer);
  error |= __vmx_vmwrite(GUEST_RIP, GuestInstructionPointer);
  error |= __vmx_vmwrite(GUEST_RFLAGS, __readeflags());
  error |= __vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
  error |= __vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));

  /* Natural-Width Host-State Fields */
  error |= __vmx_vmwrite(HOST_CR0, __readcr0());
  error |= __vmx_vmwrite(HOST_CR3, __readcr3());
  error |= __vmx_vmwrite(HOST_CR4, __readcr4());
  error |= __vmx_vmwrite(HOST_FS_BASE, __readmsr(IA32_FS_BASE));
  error |= __vmx_vmwrite(HOST_GS_BASE, __readmsr(IA32_GS_BASE));
  error |= __vmx_vmwrite(HOST_TR_BASE, VminitpGetSegmentBase(gdtr.Address, AsmReadTR()));
  error |= __vmx_vmwrite(HOST_GDTR_BASE, gdtr.Address);
  error |= __vmx_vmwrite(HOST_IDTR_BASE, idtr.Address);
  error |= __vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
  error |= __vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
  error |= __vmx_vmwrite(HOST_RSP, VmmStackPointer);
  error |= __vmx_vmwrite(HOST_RIP, reinterpret_cast<size_t>(AsmVmmEntryPoint));
  // clang-format on

  const auto vmxStatus = static_cast<VMX_STATUS>(error);
  return vmxStatus == VMX_OK;
}

ALLOC_TEXT(INIT, VminitpLaunchVM)
_Use_decl_annotations_ EXTERN_C static void VminitpLaunchVM() {
  size_t errorCode = 0;
  auto vmxStatus =
      static_cast<VMX_STATUS>(__vmx_vmread(VM_INSTRUCTION_ERROR, &errorCode));
  if (vmxStatus != VMX_OK) {
    LOG_WARN("VM_INSTRUCTION_ERROR = %p %d", errorCode, vmxStatus);
  }
  DBG_BREAK();
  vmxStatus = static_cast<VMX_STATUS>(__vmx_vmlaunch());
  if (vmxStatus == VMX_ERROR_WITH_STATUS) {
    vmxStatus =
        static_cast<VMX_STATUS>(__vmx_vmread(VM_INSTRUCTION_ERROR, &errorCode));
    LOG_ERROR("VM_INSTRUCTION_ERROR = %p %d", errorCode, vmxStatus);
  }
  DBG_BREAK();
}

ALLOC_TEXT(INIT, VminitpGetSegmentAccessRight)
_Use_decl_annotations_ EXTERN_C static ULONG VminitpGetSegmentAccessRight(
    USHORT SegmentSelector) {
  VMX_SEG_DESCRIPTOR_ACCESS_RIGHT accessRight = {};
  SEG_SELECTOR ss = {SegmentSelector};
  if (SegmentSelector) {
    auto nativeAccessRight = AsmLoadAccessRightsByte(ss.All);
    nativeAccessRight >>= 8;
    accessRight.All = static_cast<ULONG>(nativeAccessRight);
    accessRight.Fields.Reserved1 = 0;
    accessRight.Fields.Reserved2 = 0;
    accessRight.Fields.Unusable = false;
  } else {
    accessRight.Fields.Unusable = true;
  }
  return accessRight.All;
}

ALLOC_TEXT(INIT, VminitpGetSegmentBase)
_Use_decl_annotations_ EXTERN_C static ULONG_PTR VminitpGetSegmentBase(
    ULONG_PTR GdtBase, USHORT SegmentSelector) {
  const SEG_SELECTOR ss = {SegmentSelector};
  if (!ss.All) {
    return 0;
  }

  if (ss.Fields.TI) {
    const auto localSegmentDescriptor =
        VminitpGetSegmentDescriptor(GdtBase, AsmReadLDTR());
    const auto LdtBase =
        VminitpGetSegmentBaseByDescriptor(localSegmentDescriptor);
    const auto SegmentDescriptor =
        VminitpGetSegmentDescriptor(LdtBase, SegmentSelector);
    return VminitpGetSegmentBaseByDescriptor(SegmentDescriptor);
  } else {
    const auto segmentDescriptor =
        VminitpGetSegmentDescriptor(GdtBase, SegmentSelector);
    return VminitpGetSegmentBaseByDescriptor(segmentDescriptor);
  }
}

ALLOC_TEXT(INIT, VminitpGetSegmentDescriptor)
_Use_decl_annotations_ EXTERN_C static SEG_DESCRIPTOR *
VminitpGetSegmentDescriptor(ULONG_PTR DescriptorTableBase,
                            USHORT SegmentSelector) {
  SEG_SELECTOR ss = {SegmentSelector};
  return reinterpret_cast<SEG_DESCRIPTOR *>(
      DescriptorTableBase + ss.Fields.Index * sizeof(SEG_DESCRIPTOR));
}

ALLOC_TEXT(INIT, VminitpGetSegmentBaseByDescriptor)
_Use_decl_annotations_ EXTERN_C static ULONG_PTR
VminitpGetSegmentBaseByDescriptor(const SEG_DESCRIPTOR *SegmentDescriptor) {
  ULONG_PTR baseHi = SegmentDescriptor->Fields.BaseHi;
  baseHi = baseHi << (6 * 4);
  ULONG_PTR baseMid = SegmentDescriptor->Fields.BaseMid;
  baseMid = baseMid << (4 * 4);
  ULONG_PTR baseLow = SegmentDescriptor->Fields.BaseLow;
  ULONG_PTR base = (baseHi | baseMid | baseLow) & 0xffffffff;
  if (!SegmentDescriptor->Fields.System) {
    auto desc64 = reinterpret_cast<const SEG_DESCRIPTOR64 *>(SegmentDescriptor);
    ULONG_PTR baseUpper32 = desc64->BaseUpper32;
    base |= (baseUpper32 << 32);
  }
  return base;
}

ALLOC_TEXT(INIT, VminitpAdjustByRdmsr)
_Use_decl_annotations_ EXTERN_C static ULONG VminitpAdjustByRdmsr(
    ULONG MsrNumber, ULONG RequestedValue) {
  LARGE_INTEGER msrValue = {};
  msrValue.QuadPart = __readmsr(MsrNumber);
  auto adjustedValue = RequestedValue;
  adjustedValue &= msrValue.HighPart;  // bit == 0 in high word ==> must be zero
  adjustedValue |= msrValue.LowPart;   // bit == 1 in low word  ==> must be one
  return adjustedValue;
}
