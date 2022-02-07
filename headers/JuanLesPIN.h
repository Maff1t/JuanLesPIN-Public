#pragma once

#include <iostream>
#include <fstream>
#include <set>

#include "pin.H"

#include "ProcessInfo.h"
#include "Utils.h"
#include "HooksHandler.h"
#include "SyscallHooks.h"
#include "Report.h"
#include "fpu.h"
#include "md5.h"

namespace W {
#include "Windows.h"
#include "winternl.h"
#include "minwindef.h"
}

using std::cerr;
using std::string;
using std::endl;
using std::set;

std::ostream* out = &cerr;
ProcessInfo* procInfo = NULL;
HooksHandler* hooksHandler = NULL;
Report* reportHandler = NULL;
extern W::ULONGLONG numberOfExecutedInstructionsProgram;
W::ULONGLONG numberOfExecutedInstructionsLibraries = 0;
W::HANDLE gDoneEvent = NULL;
VOID __stdcall forceProgramExit(W::PVOID lpParam, W::BOOLEAN TimerOrWaitFired);


const std::string JLP_DLL_PATH = "C:\\pin\\source\\tools\\JuanLesPIN-Public\\Release\\JuanLesPIN.dll";