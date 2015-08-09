// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

extern "C" {
#pragma warning(push, 0)
#include <fltKernel.h>
#include <Wdmsec.h>
#include <windef.h>
#include <ntimage.h>
#include <stdarg.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <intrin.h>
#include <Aux_klib.h>
#pragma warning(pop)
}

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

// Specifies where the code should be located
#ifdef ALLOC_PRAGMA
#define ALLOC_TEXT(Section, Name) __pragma(alloc_text(Section, Name))
#else
#define ALLOC_TEXT(Section, Name)
#endif

// Break point that works only when a debugger is enabled
#ifndef DBG_BREAK
#define DBG_BREAK()              \
  if (KD_DEBUGGER_NOT_PRESENT) { \
  } else {                       \
    __debugbreak();              \
  }                              \
  reinterpret_cast<void*>(0)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

static const ULONG SUSHI_POOL_TAG_NAME = 'hsus';
static const auto SUSHI_BACKDOOR_CODE = 0x11519;

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct VMCS;

struct PER_PROCESSOR_DATA {
  void* VmmStackTop;
  VMCS* VmxonRegion;
  VMCS* VmcsRegion;
  void* MsrBitmap;
};

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
