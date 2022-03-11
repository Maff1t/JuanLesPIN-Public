#include "JuanLesPIN.h"

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "report", "", "specify file name for JLP output");

KNOB<bool> KnobProcessInjection(KNOB_MODE_WRITEONCE, "pintool",
    "procInj", "1", "enable/disable process injection handling (default 1-enabled)");

KNOB<bool> KnobInsAddrTracing(KNOB_MODE_WRITEONCE, "pintool",
    "insAddrTrace", "0", "enable/disable instruction addresses logging (default 0-disabled)");

KNOB<int> KnobDump(KNOB_MODE_WRITEONCE, "pintool",
    "dump", "0", "select dump type: 0 disabled, 1 whole process, 2 Red Zone binary format");

KNOB<int> KnobTimer(KNOB_MODE_WRITEONCE, "pintool",
    "timer", "300", "Specify the time (in seconds) of the execution duration (default 300)");

KNOB<W::BOOL> honeypotProcess(KNOB_MODE_WRITEONCE, "pintool", "honeypot", "0", "FOR INTERNAL USE");

KNOB<string> KnobPipeName(KNOB_MODE_WRITEONCE, "pintool", "pipeName", "", "FOR INTERNAL USE");

VOID memReadCheckerBefore( ADDRINT readAddres)
{
    hooksHandler->readHooksHandler(readAddres);
}

VOID memWriteCheckerBefore(ADDRINT writtenAddress, ADDRINT writtenByte) {
    hooksHandler->writeHooksHandler(writtenAddress, writtenByte);
}

VOID memWriteCheckerAfter(ADDRINT writtenAddress, unsigned char * oldByte) {
    /*  
        We want to be sure (to avoid false positives)
        that the address has been overwritten the PE Header with a different value! 
    */
    if (writtenAddress < procInfo->baseAddress + 0x1000 && writtenAddress >= procInfo->baseAddress) {
        unsigned char byte[1];
        PIN_SafeCopy(byte, (VOID*)writtenAddress, sizeof(unsigned char));
        if (*byte != *oldByte) {
            EVASION("ANTIDUMP", "", "ErasePEHeaderFromMemory", "The process is modifying the Pe Header");
            MYINFO("WRITEONPEHEADEROFFSET", "%d", writtenAddress - procInfo->baseAddress);
        }
    }
}

EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo, PHYSICAL_CONTEXT* pPhysCtxt, VOID* v)
{
    EXCEPTION_CODE c = PIN_GetExceptionCode(pExceptInfo);
    EXCEPTION_CLASS cl = PIN_GetExceptionClass(c);
    std::cerr << "Exception occurred class " << cl << " : " << PIN_ExceptionToString(pExceptInfo) << std::endl;
    return EHR_UNHANDLED;
}


VOID traceInstrumentation(TRACE trace, VOID* v) {
    if (!hooksHandler) return; // It means that the malware module isn't still in memory

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {

        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {

            /* Get instruction pointer */
            ADDRINT ip = INS_Address(ins);

            /* If it is in a GUARD_PAGE, raise exception -> antidebugging technique */
            if (procInfo->isInsideGuardPage(ip)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)pageGuardException, IARG_CONTEXT, IARG_THREAD_ID, IARG_INST_PTR, IARG_END);
            }

            /*  This must be done before checking instruction pointer 
                If there is a memory write, I want to be sure that the written
                address CHANGE his content. I don't care about the write operation
                if it doesn't change.
                */
            if (INS_IsMemoryWrite(ins)) {
                UINT32 memOperands = INS_MemoryOperandCount(ins);

                for (UINT32 memOp = 0; memOp < memOperands; memOp++)
                {
                    if (INS_MemoryOperandIsWritten(ins, memOp))
                    {
                        unsigned char *oldByte = (unsigned char *)malloc (sizeof(unsigned char)*4);
                        INS_InsertPredicatedCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)memWriteCheckerBefore,
                            IARG_MEMORYOP_EA, memOp,
                            IARG_ADDRINT, oldByte,
                            IARG_END);
                        if (INS_IsValidForIpointAfter(ins))
                            INS_InsertPredicatedCall(
                                ins, IPOINT_AFTER, (AFUNPTR)memWriteCheckerAfter,
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYOP_EA, memOp,
                                IARG_ADDRINT, oldByte,
                                IARG_END);
                        else 
                            INS_InsertPredicatedCall(
                                ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)memWriteCheckerAfter,
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYOP_EA, memOp,
                                IARG_ADDRINT, oldByte,
                                IARG_END);
                        free(oldByte);
                    }
                }
            }

            /* If i'm the honeypot process, I check if the instruction is in the "injected" memory space*/
            if (honeypotProcess) {
                /* Check for new Injected pieces of memory */
                fetchMessageFromPipe();

                /* Check if this address is in a injected piece of memory*/
                if (!isInsideRedZoneHoneypot(ip)) return;
            }
            else if (!procInfo->isInsideRedZone(ip)) {
                numberOfExecutedInstructionsLibraries++;
                return;
            }
            numberOfExecutedInstructionsProgram++;

            /* Check memory read*/
            if (INS_IsMemoryRead(ins))
            {
                UINT32 memOperands = INS_MemoryOperandCount(ins);

                for (UINT32 memOp = 0; memOp < memOperands; memOp++)
                {
                    if (INS_MemoryOperandIsRead(ins, memOp))
                    {
                        INS_InsertPredicatedCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)memReadCheckerBefore,
                            IARG_MEMORYOP_EA, memOp,
                            IARG_END);
                    }
                }
            }

            /* Check for FPU leaks */
            FPU_InstrumentINS(ins);

            /* Check if this instruction is one of the instrumented ones */
            hooksHandler->instructionHooksHandler(ins);
        }       
    }
        
}



VOID onImageLoad(IMG img, VOID* v) {
    PIN_LockClient();

	if (IMG_IsMainExecutable(img)) {

        procInfo = new ProcessInfo(img);
        W::HANDLE hprocess = W::GetCurrentProcess();
        
        /* Get process name*/
        if (!honeypotProcess) {
            W::TCHAR szFileName[MAX_PATH];
            W::GetModuleFileName(NULL, szFileName, MAX_PATH);
            MYINFO("PROCESS NAME", "%s", szFileName);
            MYINFO("BASEADDRESS", "%p", IMG_StartAddress(img));

        }
        /* Get PEB structure*/
        procInfo->set_peb(FindPEBAddress(hprocess));

        /* Initialize hooks*/
        hooksHandler = new HooksHandler(procInfo);
        
        /* Get SizeOfImage Address via PEB (I need it for some evasion techniques) */
        W::PLIST_ENTRY InLoadOrderModuleList = (W::PLIST_ENTRY)procInfo->get_peb()->Ldr->Reserved2[1];
        PLDR_DATA_TABLE_ENTRY tableEntry = CONTAINING_RECORD(InLoadOrderModuleList, LDR_DATA_TABLE_ENTRY, Reserved1[0] /*InLoadOrderLinks*/);
        W::PULONG pEntrySizeOfImage = (W::PULONG)&tableEntry->Reserved3[1]; // &tableEntry->SizeOfImage
        sizeOfImageAddress = pEntrySizeOfImage;
    } else {
        ADDRINT begin = IMG_LowAddress(img);
        ADDRINT end = IMG_HighAddress(img);
        string name = IMG_Name(img);
        procInfo->insertSection(Section (begin, end, name));

        /* If I'm the honeypot, check if this module is Injected by another process!*/
        if (honeypotProcess && isInInjectedDLL(name)) {
            addToHoneypotRedZone(begin, (size_t)(end - begin));
        }

        /* If this dll has a strange path, I insert his code in the red zone*/
        if (name.find("C:\\Windows\\") == string::npos) {
            MYINFO("SUSPECT DLL", "%s", name.c_str());
            if (honeypotProcess)
                addToHoneypotRedZone(begin, (size_t)(end - begin));
            else
                procInfo->insertSuspectedDll((W::LPVOID)begin, (size_t)(end - begin));
        }

        /* Hook library calls in this module */
        hooksHandler->hookApiInThisLibrary(img);
    }
    PIN_UnlockClient();
}

VOID onFinish(INT32 exitCode, VOID* v) {
    
    std::stringstream ss;
    MYINFO("EXITCODE", "%d", exitCode);
    terminateHoneypotProcess();
    if (rdtscCounter != 0) {
        ss << "Rdtsc has been called" << rdtscCounter << " times";
        EVASION("TIMING ATTACK", NULL, "RDTSC", ss.str().c_str());
        ss.clear();
    }

    if (getTickCountCounter != 0) {
        ss << "The process called GetTickCount() " << getTickCountCounter << " times";
        EVASION("ANTIDEBUG", NULL, "GetTickCount", ss.str().c_str());
        ss.clear();
    }
    
    if (sleepCounter > TIMING_ATTACK_THRESHOLD) {
        ss << sleepTime;
        EVASION("TIMING ATTACK", NULL, "time_stalling", ss.str().c_str());
        ss.clear();
    }

    if (process32NextCounter > 0) {
        ss << process32NextCounter;
        EVASION("ENVIRONMENT PROFILING", NULL, "process_enum", ss.str().c_str());
        ss.clear();
    }

    MYINFO("PROGRAM INSTRUCTIONS", "%lu", numberOfExecutedInstructionsProgram);
    MYINFO("LIBRARY INSTRUCTIONS", "%lu", numberOfExecutedInstructionsLibraries);

    if (!honeypotProcess) {
        std::stringstream dumpName;
        dumpName << KnobOutputFile.Value() << "-" << W::GetCurrentProcessId();
        if (KnobDump.Value() == 1) { /* Use procDump */
            procDump(dumpName.str());
        }
        else if (KnobDump.Value() == 2) { /* Manual dump of red zone pieces of memory*/
            procInfo->dumpRedZoneMemory(dumpName.str());
        }
    }
        

    delete reportHandler;
}

BOOL followChild (CHILD_PROCESS childProcess, VOID* val) {

    int argc = 0;
    const CHAR* const* argv = NULL;
    CHILD_PROCESS_GetCommandLine(childProcess, &argc, &argv);
    OS_PROCESS_ID childPid = CHILD_PROCESS_GetId(childProcess);
    std::stringstream ss;
    for (int i = 0; i < argc; i++)
        ss << argv[i] << " ";

    BEHAVIOURREPORT("PROCESS", "ChildProcess");
    MYINFO("CHILDPROCESS CMD", "%s", ss.str().c_str());
    MYINFO("CHILDPROCESS PID", "%d", childPid);
    
    return TRUE; // To say that I want to follow the child process!
}

static VOID timerThread(VOID* arg)
{
    PIN_Sleep(KnobTimer.Value() * 1000);
    MYINFO("TIMEOUT", "The program exited for timeout -> Elapsed %d seconds", KnobTimer.Value());
    PIN_ExitApplication(2);
}

VOID PIN_FAST_ANALYSIS_CALL LogInstructionAddr(ADDRINT instructionAddress)
{
    if (procInfo->isInsideRedZone(instructionAddress)) reportHandler->bblReport(instructionAddress);
}

VOID InsAddrTracing(INS ins, VOID* v)
{
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)LogInstructionAddr, IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_END);
}

int main(int argc, char *argv[])
{
    if (!file_exists(JLP_DLL_PATH)) {
        std::cout <<"Wrong path of JLP dll. Can't continue.";
        return -1;
    }
    if (!file_exists(HON_DLL_PATH)) {
        std::cout << "Wrong path of Honeypot executable. Can't continue.";
        return -1;
    }
    W::HANDLE hTimer = NULL;
    W::HANDLE hTimerQueue = NULL;

    PIN_InitSymbols(); 

    if( PIN_Init(argc,argv) ) return Usage();
    
    std::stringstream reportFileName;
    reportFileName << KnobOutputFile.Value() << "-" << W::GetCurrentProcessId();
    reportHandler = new Report(reportFileName.str(), honeypotProcess, KnobInsAddrTracing.Value());

    MD5 md5;
    MYINFO("JLP MD5", "%s", md5.digestFile(JLP_DLL_PATH.c_str()));

    if (KnobDump.Value() == 1 && !file_exists(PROCDUMPBINARY)) {
        std::cout << "Wrong path of procdump executable. Can't continue.";
        return -1;
    }

    if (KnobInsAddrTracing.Value()) {
        INS_AddInstrumentFunction(InsAddrTracing, NULL);
    }
    
    // This will catch eventual exceptions inside pin or inside the tool
    PIN_AddInternalExceptionHandler(ExceptionHandler, NULL);

    // Register function to be called to instrument instructions
    TRACE_AddInstrumentFunction(traceInstrumentation, NULL);
        
    // Register function to be called to instrument Image loading
    IMG_AddInstrumentFunction(onImageLoad, NULL);

    // Register function to be called when the program exit
    PIN_AddFiniFunction(onFinish, NULL);

    PIN_AddFollowChildProcessFunction(followChild, NULL); // Follow child process!

    /* init the hooking system */
    SyscallHooks::initHooks();
    
    /* init FPU module*/
    FPU_Init();
    
    /* init injection handling system*/
    if (KnobProcessInjection.Value()) {
        if (!honeypotProcess) {         
            W::DWORD ppid = W::GetCurrentProcessId();
            initHoneypotProcess(KnobOutputFile.Value(), ppid);
            initNamedPipeServer(ppid);
        }
        else {
            initNamedPipeClient(KnobPipeName.Value());
        }
    }
    
    /* Initialize timer thread (exits program before snapshot restoring) */

    // Create an internal thread and wait for exit.
    if (KnobTimer.Value() != 0) {

        THREADID threadId = PIN_SpawnInternalThread(timerThread, NULL, 0, NULL);
        if (threadId == INVALID_THREADID)
        {
            MYERROR("PIN_SpawnInternalThread(timerThread) failed");
        }
    }

    /* Start the program*/
    PIN_StartProgram();
    
    return 0;
}
