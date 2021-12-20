#pragma once
#include "pin.H"

#include "Utils.h"

#define FPUIPOFFSET 0xc

VOID FPU_Init();
VOID FPU_InstrumentINS(INS ins);
VOID PIN_FAST_ANALYSIS_CALL FPU_UpdateFPUStatus(ADDRINT regValue, ADDRINT op);
ADDRINT PIN_FAST_ANALYSIS_CALL FPU_UpdateLastFpuIns(ADDRINT addr);
