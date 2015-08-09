// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module declares interfaces to logging functions.
//
#include "stdafx.h"


////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

static const auto SUSHI_BACKDOOR_CODE = 0x11519;

////////////////////////////////////////////////////////////////////////////////
//
// types
//

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

int _tmain(int argc, TCHAR *argv[]) {
  if (argc == 2) {
    const auto affinity = (1 << std::stoul(argv[1]));
    if (!::SetThreadAffinityMask(::GetCurrentThread(), affinity)) {
      std::cout << "SetThreadAffinityMask() failed." << std::endl;
      return EXIT_FAILURE;
    }
  }

  for (; /*ever*/;) {
    int cpuInfo[4] = {};
    __cpuidex(cpuInfo, 0, SUSHI_BACKDOOR_CODE);
    char vendorID[13] = {};
    memcpy(&vendorID[0], &cpuInfo[1], 4);  // ebx
    memcpy(&vendorID[4], &cpuInfo[3], 4);  // edx
    memcpy(&vendorID[8], &cpuInfo[2], 4);  // ecx
    printf("Vendor ID: %s\n", vendorID);

    unsigned int tscAux = 0;
    const auto tsc1 = __rdtscp(&tscAux);
    printf("Rdtscp   : %016Ix, %08x\n", tsc1, tscAux);

    const auto tsc2 = __rdtsc();
    printf("Rdtsc    : %016Ix\n", tsc2);

    ::Sleep(1000);
  }
}
