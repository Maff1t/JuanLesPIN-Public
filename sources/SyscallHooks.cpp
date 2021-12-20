#include "SyscallHooks.h"
#include "Report.h"


/* Get syscall numbers of hooked syscalls */
void SyscallHooks::enumSyscalls(map<string, syscall_hook> syscallsHooks)
{
    set <string> missingSyscalls;
    for (const auto& pair : syscallsHooks) {
        missingSyscalls.insert(pair.first);
    }
    unsigned char* image = (unsigned char*)W::GetModuleHandle("ntdll");
    W::IMAGE_DOS_HEADER* dos_header = (W::IMAGE_DOS_HEADER*) image;
    W::IMAGE_NT_HEADERS* nt_headers = (W::IMAGE_NT_HEADERS*)(image + dos_header->e_lfanew);
    W::IMAGE_DATA_DIRECTORY* data_directory = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    W::IMAGE_EXPORT_DIRECTORY* export_directory = (W::IMAGE_EXPORT_DIRECTORY*)(image + data_directory->VirtualAddress);
    unsigned long* address_of_names = (unsigned long*)(image + export_directory->AddressOfNames);
    unsigned long* address_of_functions = (unsigned long*)(image + export_directory->AddressOfFunctions);
    unsigned short* address_of_name_ordinals = (unsigned short*)(image + export_directory->AddressOfNameOrdinals);
    unsigned long number_of_names = MIN(export_directory->NumberOfFunctions, export_directory->NumberOfNames);
    for (unsigned long i = 0; i < number_of_names; i++) {
        const char* name = (const char*)(image + address_of_names[i]);
        unsigned char* addr = image + address_of_functions[address_of_name_ordinals[i]];
        if (!memcmp(name, "Zw", 2) || !memcmp(name, "Nt", 2)) {
            // does the signature match?
            // either:   mov eax, syscall_number ; mov ecx, some_value
            // or:       mov eax, syscall_number ; xor ecx, ecx
            // or:       mov eax, syscall_number ; mov edx, 0x7ffe0300
            if (*addr == 0xb8 && (addr[5] == 0xb9 || addr[5] == 0x33 || addr[5] == 0xba)) {
                unsigned long syscall_number = *(unsigned long*)(addr + 1);
                string syscall_name = string(name);
                if (syscallsHooks.find(syscall_name + "_entry") != syscallsHooks.end()) {
                    syscallsMap.insert(std::pair<unsigned long, string>(syscall_number, syscall_name));
                    missingSyscalls.erase(syscall_name + "_entry");
                }
                if (syscallsHooks.find(syscall_name + "_exit") != syscallsHooks.end()) {
                    syscallsMap.insert(std::pair<unsigned long, string>(syscall_number, syscall_name));
                    missingSyscalls.erase(syscall_name + "_exit");
                }
            }
        }
    }
    
    for (auto it = missingSyscalls.begin(); it != missingSyscalls.end(); ++it) {
        ERROR("Unable to find syscall: %s", it->c_str());
    }
}

void SyscallHooks::initHooks() {

    //syscallsHooks.insert(std::pair<string, syscall_hook>("NtQueryInformationProcess_exit", &SyscallHooks::NtQueryInformationProcessHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtQuerySystemInformation_exit", &SyscallHooks::NtQuerySystemInformationHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtSetInformationThread_entry", &SyscallHooks::NtSetInformationThreadHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtQueryObject_exit", &SyscallHooks::NtQueryObjectHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtOpenKey_exit", &SyscallHooks::NtOpenKeyHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtOpenKeyEx_exit", &SyscallHooks::NtOpenKeyHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtQueryValueKey_exit", &SyscallHooks::NtQueryValueKeyHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtQueryAttributesFile_exit", &SyscallHooks::NtQueryAttributesFileHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtDelayExecution_entry", &SyscallHooks::NtDelayExecutionHook));

    // BEHAVIOUR - REGISTRY
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtCreateKey_exit", &SyscallHooks::NtCreateKeyHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtDeleteKey_entry", &SyscallHooks::NtDeleteKeyHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtDeleteValueKey_entry", &SyscallHooks::NtDeleteKeyHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtRenameKey_entry", &SyscallHooks::NtRenameKeyHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtSetValueKey_entry", &SyscallHooks::NtSetValueKeyHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtSaveKey_entry", &SyscallHooks::NtSaveKeyHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtSaveKeyEx_entry", &SyscallHooks::NtSaveKeyHook));

    // BEHAVIOUR - MUTEX
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtCreateMutant_entry", &SyscallHooks::NtCreateMutantHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtOpenMutant_entry", &SyscallHooks::NtOpenMutantHook));

    // BEHAVIOUR - FILESYSTEM
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtOpenFile_exit", &SyscallHooks::NtOpenFileHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtCreateFile_exit", &SyscallHooks::NtCreateFileHook));

    syscallsHooks.insert(std::pair<string, syscall_hook>("NtReadFile_entry", &SyscallHooks::NtReadFileHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtWriteFile_entry", &SyscallHooks::NtWriteFileHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtDeviceIoControlFile_entry", &SyscallHooks::NtDeviceIoControlFileHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtQueryInformationFile_entry", &SyscallHooks::NtQueryInformationFileHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtSetInformationFile_entry", &SyscallHooks::NtSetInformationFileHook));

    syscallsHooks.insert(std::pair<string, syscall_hook>("NtDeleteFile_entry", &SyscallHooks::NtDeleteFileHook));
    // NtQueryAttributesFile_exit see above


    // Process Injection Hooks
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtWriteVirtualMemory_entry", &SyscallHooks::NtWriteVirtualMemoryHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtCreateThreadEx_entry", &SyscallHooks::NtCreateThreadExHook));
    /*syscallsHooks.insert(std::pair<string, syscall_hook>("NtResumeThread_entry", &SyscallHooks::NtResumeThreadHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtMapViewOfSection_entry", &SyscallHooks::NtMapViewOfSectionHook));
    syscallsHooks.insert(std::pair<string, syscall_hook>("NtQueueApcThread_entry", &SyscallHooks::NtQueueApcThreadHook));*/

    enumSyscalls(syscallsHooks);

    /* RegKey Artifacts */
    regKeyArtifacts.insert(std::pair <wstring, const char *> (L"HARDWARE\\ACPI\\DSDT\\VBOX__", "VirtualBox"));
    regKeyArtifacts.insert(std::pair <wstring, const char *> (L"HARDWARE\\ACPI\\RSDT\\VBOX__", "VirtualBox"));
    regKeyArtifacts.insert(std::pair <wstring, const char *> (L"HARDWARE\\ACPI\\FADT\\VBOX__", "VirtualBox"));
    regKeyArtifacts.insert(std::pair <wstring, const char *> (L"SOFTWARE\\Oracle\\VirtualBox Guest Additions", "VirtualBox"));
    regKeyArtifacts.insert(std::pair <wstring, const char *> (L"SYSTEM\\ControlSet001\\Services\\VBoxGuest", "VirtualBox"));
    regKeyArtifacts.insert(std::pair <wstring, const char *> (L"SYSTEM\\ControlSet001\\Services\\VBoxMouse", "VirtualBox"));
    regKeyArtifacts.insert(std::pair <wstring, const char *> (L"SYSTEM\\ControlSet001\\Services\\VBoxService", "VirtualBox"));
    regKeyArtifacts.insert(std::pair <wstring, const char *> (L"SYSTEM\\ControlSet001\\Services\\VBoxSF", "VirtualBox"));
    regKeyArtifacts.insert(std::pair <wstring, const char *> (L"SYSTEM\\ControlSet001\\Services\\VBoxVideo", "VirtualBox"));
    regKeyArtifacts.insert(std::pair <wstring, const char *> (L"SOFTWARE\\VMware Inc.\\VMware Tools", "VMWare"));
    regKeyArtifacts.insert(std::pair <wstring, const char *> (L"SOFTWARE\\Wine", "Wine"));
    regKeyArtifacts.insert(std::pair <wstring, const char *> (L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters", "VirtualPC"));

    keyNameValueMap.insert(std::make_pair<std::string, std::string>("HARDWARE\\Description\\System", "SystemBiosVersion"));
    keyNameValueMap.insert(std::make_pair<std::string, std::string>("HARDWARE\\Description\\System", "SystemBiosVersion"));
    keyNameValueMap.insert(std::make_pair<std::string, std::string>("HARDWARE\\Description\\System", "VideoBiosVersion"));
    keyNameValueMap.insert(std::make_pair<std::string, std::string>("HARDWARE\\Description\\System", "SystemBiosDate"));
    keyNameValueMap.insert(std::make_pair<std::string, std::string>("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier"));
    keyNameValueMap.insert(std::make_pair<std::string, std::string>("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier"));
    keyNameValueMap.insert(std::make_pair<std::string, std::string>("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier"));
    keyNameValueMap.insert(std::make_pair<std::string, std::string>("SYSTEM\\ControlSet001\\Control\\SystemInformation", "SystemManufacturer"));
    keyNameValueMap.insert(std::make_pair<std::string, std::string>("SYSTEM\\ControlSet001\\Control\\SystemInformation", "SystemProductName"));
    
    /* FileSystem Artifacts */

    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\drivers\\VBoxMouse.sys", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\drivers\\VBoxGuest.sys", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\drivers\\VBoxSF.sys", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\drivers\\VBoxVideo.sys", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\vboxdisp.dll", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\vboxhook.dll", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\vboxmrxnp.dll", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\vboxogl.dll", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\vboxoglarrayspu.dll", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\vboxoglcrutil.dll", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\vboxoglerrorspu.dll", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\vboxoglfeedbackspu.dll", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\vboxoglpackspu.dll", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\vboxoglpassthroughspu.dll", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\vboxservice.exe", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\vboxtray.exe", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\VBoxControl.exe", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"oracle\\virtualbox guest additions\\", "VirtualBox"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\drivers\\vmmouse.sys", "VMWare"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\drivers\\vm3dmp.sys", "VMWare"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\drivers\\vmci.sys", "VMWare"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\drivers\\vmhgfs.sys", "VMWare"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\drivers\\vmmemctl.sys", "VMWare"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\drivers\\vmrawdsk.sys", "VMWare"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\drivers\\vmusbmouse.sys", "VMWare"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\drivers\\vmkdb.sys", "VMWare"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\drivers\\vmnetuserif.sys", "VMWare"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"System32\\drivers\\vmnetadapter.sys", "VMWare"));
    fileSystemArtifacts.push_back(std::pair <wstring, const char *> (L"VMWare\\", "VMware"));

    // allocate syscall information struct
    static syscall_t sc[256] = { 0 };
    PIN_AddSyscallEntryFunction(&SyscallHooks::syscallEntry, &sc);
    PIN_AddSyscallExitFunction(&SyscallHooks::syscallExit, &sc);

}

void SyscallHooks::syscallEntry(THREADID thread_id, CONTEXT* ctx, SYSCALL_STANDARD std, void* v) {
    //get the syscall number
    unsigned long syscall_number = PIN_GetSyscallNumber(ctx, std);
    //if (syscall_number == 0) return;

    syscall_t* sc = &((syscall_t*)v)[thread_id];
    sc->syscall_number = syscall_number;
    SyscallHooks::syscallGetArguments(ctx, std, 8, 0, &sc->arg0, 1, &sc->arg1, 2, &sc->arg2, 3, &sc->arg3, 4, &sc->arg4, 5, &sc->arg5, 6, &sc->arg6, 7, &sc->arg7);
    
    // Search if there is a hook on the entry of this syscall!
    auto it = syscallsMap.find(sc->syscall_number);
    if (it != syscallsMap.end()) {
        auto syscallHookItem = syscallsHooks.find(it->second + "_entry");
        if (syscallHookItem != syscallsHooks.end()) {
            syscallHookItem->second(sc, ctx, std);
        }
    }
}

void SyscallHooks::syscallExit(THREADID thread_id, CONTEXT* ctx, SYSCALL_STANDARD std, void* v) {
    //get the structure with the informations on the systemcall
    syscall_t* sc = &((syscall_t*)v)[thread_id];
    
    //search for an hook on exit
    auto it = syscallsMap.find(sc->syscall_number);
    if (it != syscallsMap.end()) {
        //serch if we have an hook for the syscall
        auto syscallHookItem = syscallsHooks.find(it->second + "_exit");
        if (syscallHookItem != syscallsHooks.end()) {
            //if so call the hook
            syscallHookItem->second(sc, ctx, std);
        }
    }
}

void SyscallHooks::syscallGetArguments(CONTEXT* ctx, SYSCALL_STANDARD std, int count, ...)
{
    va_list args;
    va_start(args, count);
    for (int i = 0; i < count; i++) {
        int index = va_arg(args, int);
        ADDRINT* ptr = va_arg(args, ADDRINT*);
        *ptr = PIN_GetSyscallArgument(ctx, std, index);
    }
    va_end(args);
}

void SyscallHooks::NtQueryInformationProcessHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {

    Complete_PROCESS_BASIC_INFORMATION* pbi = (Complete_PROCESS_BASIC_INFORMATION*)sc->arg2;
    W::PROCESSINFOCLASS ProcessInformationClass = (W::PROCESSINFOCLASS) sc->arg1;
    if (ProcessInformationClass == PROCESSDEBUGPORT) {
        EVASION("ANTIDEBUG", NULL, "NtQueryInformationProcess_ProcessDebugPort", "");
        W::PDWORD32 IsRemotePresent = (W::PDWORD32)sc->arg2; // if it is different from 0 it means there is a debugger attached
        memset(IsRemotePresent, 0x00000000, sizeof(W::DWORD32)); 
    }
    else if (ProcessInformationClass == PROCESSDEBUGFLAGS) {
        EVASION("ANTIDEBUG", NULL, "NtQueryInformationProcess_ProcessDebugFlag", "");
        W::PDWORD32 NoDebugInherit = (W::PDWORD32)sc->arg2; // if it is equal to 0 it means there is a debugger attached
        memset(NoDebugInherit, 0x00000001, sizeof(W::DWORD32)); 
    }
    else if (ProcessInformationClass == PROCESSDEBUGOBJECT) {
        EVASION("ANTIDEBUG", NULL, "NtQueryInformationProcess_ProcessDebugObject", "");
    }
    else if (ProcessInformationClass == PROCESSBASICINFORMATION) {
        /* Change parent process ID */
        W::ULONG_PTR pid = GetProcessIdFromName("explorer.exe");
        PIN_SafeCopy((VOID*)&pbi->ParentProcessId, (const VOID*)&pid, sizeof(W::ULONG_PTR));
    }

}

void SyscallHooks::NtQuerySystemInformationHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
    W::SYSTEM_INFORMATION_CLASS SystemInformationClass = (W::SYSTEM_INFORMATION_CLASS) sc->arg0;
    PSYSTEM_PROCESS_INFO spi = (PSYSTEM_PROCESS_INFO)sc->arg1;
    
    if (SystemInformationClass == SYSTEM_PROCESS_INFORMATION_TYPE) {
        
        //iterate through all processes 
        while (spi->NextEntryOffset) {
            //if the process is pin change it's name in cmd.exe in order to avoid evasion
            if (spi->ImageName.Buffer && ((wcscmp(spi->ImageName.Buffer, L"pin.exe") == 0))) {
                wcscpy(spi->ImageName.Buffer, L"cmd.exe");
            }
            spi = (PSYSTEM_PROCESS_INFO)((W::LPBYTE)spi + spi->NextEntryOffset); // Calculate the address of the next entry.
        }
    }
    
    /* I do it in API hooks
    else if (SystemInformationClass == SYSTEM_KERNEL_DEBUGGER_INFORMATION) {
        EVASION("ANTIDEBUG", NULL, "NtQuerySystemInformation_SystemKernelDebuggerInformation", "Program tried to get kernel debugging information to detect attached debugger");
    }*/
}

void SyscallHooks::NtSetInformationThreadHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
    int ThreadInformationClass = (int)sc->arg1;

    if (ThreadInformationClass == THREADHIDEFROMDEBUGGER) {
        EVASION("ANTIDEBUG", NULL, "NtSetInformationThread_ThreadHideFromDebugger", "The process called NtSetInformationThread with ThreadHideFromDebugger");
    }
}

void SyscallHooks::NtQueryObjectHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std)
{
    W::HANDLE Handle = (W::HANDLE)sc->arg0;
    Complete_OBJECT_INFORMATION_CLASS ObjectInformationClass = (Complete_OBJECT_INFORMATION_CLASS) sc->arg1;

    if (ObjectInformationClass == Complete_OBJECT_INFORMATION_CLASS::ObjectAllInformation && Handle == (W::HANDLE)-1) {
        /* The process may check if there is a "debug object" in the list of objects!*/
        EVASION("ANTIDEBUG", NULL, "NtQueryObject_ObjectAllTypesInformation", "Probably the process is trying to check for 'debug objects'");
    }
    else if (ObjectInformationClass == Complete_OBJECT_INFORMATION_CLASS::ObjectTypeInformation){
        W::__PUBLIC_OBJECT_TYPE_INFORMATION* ObjectInformation = (W::__PUBLIC_OBJECT_TYPE_INFORMATION*) sc->arg2;
        wchar_t myBuf[12];
        PIN_SafeCopy((VOID*)myBuf, (const VOID*)ObjectInformation->TypeName.Buffer, sizeof(wchar_t) * 12);
        if (wcscmp(L"DebugObject", myBuf) == 0)
            EVASION("ANTIDEBUG", NULL, "NtQueryObject_ObjectTypeInformation", "Probably the process is trying to check for 'debug objects'");
        /* We can mitigate this changing the returned object type if it is a debug object */
    }
}


void SyscallHooks::NtDelayExecutionHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std)
{
    W::PLARGE_INTEGER DelayInterval = (W::PLARGE_INTEGER) sc->arg1;
    W::LARGE_INTEGER delay;

    PIN_SafeCopy(&delay, DelayInterval, sizeof(W::LARGE_INTEGER));

    uint32_t delayInMs = (-delay.QuadPart) / 10000LL;
    if (delayInMs > DELAY_MINIMUM_VALUE && delayInMs < 1000000000) {
        //std::stringstream ss;
        //ss << "NtDelayExecution syscall called with " << delayInMs << "ms";
        //EVASION("TIMING ATTACK", NULL, "NtDelayExecution", ss.str().c_str());
        if (delay.QuadPart < 0) {
            sleepTime += delayInMs;
        }

        // Mitigation
        delay.HighPart = 0;
        delay.LowPart = 0;
        delay.QuadPart = 0;
        delay.u.HighPart = 0;
        delay.u.LowPart = 0;
        PIN_SafeCopy(DelayInterval, &delay, sizeof(W::LARGE_INTEGER));
    }
}

/* Registry Key monitor */

void SyscallHooks::NtOpenKeyHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std)
{
    PIN_LockClient();
    W::PHANDLE pKeyHandle = (W::PHANDLE)sc->arg0;
    W::HANDLE kh;
    PIN_SafeCopy((VOID*)&kh, (VOID*)pKeyHandle, sizeof(W::HANDLE));
    W::HKEY keyHandle = (W::HKEY)kh;

    W::POBJECT_ATTRIBUTES ObjectAttributes = (W::POBJECT_ATTRIBUTES)sc->arg2;
    wchar_t* buf = getWStrFromObjectAttribute(ObjectAttributes);
    wstring ws(buf);
    PIN_UnlockClient();
   
    string name(ws.begin(), ws.end());
    auto it = regKeyArtifacts.find(ws);
    if (it != regKeyArtifacts.end()) {
        std::stringstream ss;
        ss << "The process checked the following registry key: " << name;
        EVASION("GENERIC SANDBOX CHECK", it->second, "reg_keys", ss.str().c_str());
    }
    else {
        BEHAVIOURREPORREGKEYHANDLE("NtOpenKeyHook", keyHandle);
    }
    keyHandleStringMap[kh] = name;
    free(buf);
}

void SyscallHooks::NtCreateKeyHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std)
{
    
    PIN_LockClient();
    W::PHANDLE pKeyHandle = (W::PHANDLE)sc->arg0;
    W::HANDLE kh;
    PIN_SafeCopy((VOID*)&kh, (VOID*)pKeyHandle, sizeof(W::HANDLE));
    W::HKEY keyHandle = (W::HKEY)kh;
    PIN_UnlockClient();
    BEHAVIOURREPORREGKEYHANDLE("NtCreateKey", keyHandle);
    
    /*
    W::POBJECT_ATTRIBUTES ObjectAttributes = (W::POBJECT_ATTRIBUTES)sc->arg2;
    wchar_t* buf = getWStrFromObjectAttribute(ObjectAttributes);
    wstring ws(buf);
    string name(ws.begin(), ws.end());
    BEHAVIOURREPORTARG("REGISTRY", "NtCreateKey", name.c_str());
    free(buf);
    */
}

void SyscallHooks::NtDeleteKeyHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
    PIN_LockClient();
    W::HKEY argKeyHandle = (W::HKEY)sc->arg0;
    W::HKEY pKeyHandle;
    PIN_SafeCopy((VOID*)&pKeyHandle, (VOID*)&argKeyHandle, sizeof(W::HANDLE));
    PIN_UnlockClient();
    BEHAVIOURREPORREGKEYHANDLE("NtDeleteKey", pKeyHandle);
}

void SyscallHooks::NtRenameKeyHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
    PIN_LockClient();
    W::HKEY argKeyHandle = (W::HKEY)sc->arg0;
    W::HKEY pKeyHandle;
    PIN_SafeCopy((VOID*)&pKeyHandle, (VOID*)&argKeyHandle, sizeof(W::HANDLE));
    PIN_UnlockClient();
    BEHAVIOURREPORREGKEYHANDLE("NtRenameKey", pKeyHandle);
}

void SyscallHooks::NtSetValueKeyHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
    PIN_LockClient();
    W::HKEY argKeyHandle = (W::HKEY)sc->arg0;
    W::HKEY pKeyHandle;
    PIN_SafeCopy((VOID*)&pKeyHandle, (VOID*)&argKeyHandle, sizeof(W::HANDLE));
    PIN_UnlockClient();
    BEHAVIOURREPORREGKEYHANDLE("NtSetValueKey", pKeyHandle);
}

void SyscallHooks::NtSaveKeyHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
    PIN_LockClient();
    W::HKEY argKeyHandle = (W::HKEY)sc->arg0;
    W::HKEY pKeyHandle;
    PIN_SafeCopy((VOID*)&pKeyHandle, (VOID*)&argKeyHandle, sizeof(W::HANDLE));
    PIN_UnlockClient();
    BEHAVIOURREPORREGKEYHANDLE("NtSaveKey", pKeyHandle);
}


/*
void SyscallHooks::NtOpenKeyExHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std)
{
    W::PHANDLE pKeyHandle = (W::PHANDLE) sc->arg0;
    W::POBJECT_ATTRIBUTES ObjectAttributes = (W::POBJECT_ATTRIBUTES) sc->arg2;
    W::HANDLE keyHandle;
    PIN_SafeCopy((VOID*)&keyHandle, (VOID*)pKeyHandle, sizeof(W::HANDLE));

    wchar_t* buf = getWStrFromObjectAttribute(ObjectAttributes);
    wstring ws(buf);
    string name(ws.begin(), ws.end());
    auto it = regKeyArtifacts.find(ws);
    if (it != regKeyArtifacts.end()) {
        std::stringstream ss;
        ss << "The process checked the following registry key: " << name;
        EVASION("GENERIC SANDBOX CHECK", it->second, "reg_keys", ss.str().c_str());
    }
    keyHandleStringMap[keyHandle] = name;

    free(buf);
}
*/
void SyscallHooks::NtQueryValueKeyHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
    PIN_LockClient();
    W::HKEY akh = (W::HKEY)sc->arg0;
    W::HKEY kh;
    PIN_SafeCopy((VOID*)&kh, (VOID*)&akh, sizeof(W::HANDLE));
    BEHAVIOURREPORREGKEYHANDLE("NtQueryValueKey", kh);

    W::HANDLE keyHandle = (W::HANDLE)sc->arg0;
    W::PUNICODE_STRING ValueName = (W::PUNICODE_STRING) sc->arg1;
    char* value = (char*)sc->arg3;
    PIN_UnlockClient();

    /* Find the key name from the handle received */
    auto it = keyHandleStringMap.find(keyHandle);
    if (it == keyHandleStringMap.end()) return;
    /* Then search if this key is one of the artifacts! */
    string keyname(it->second);
    wchar_t* keyValue = getWStrFromPUnicodeString(ValueName);
    wstring ws(keyValue);
    string keyVal(ws.begin(), ws.end());

    auto it2 = keyNameValueMap.equal_range(keyname); // This iterator goes from the first value with key k to the last value with key k
    for (auto it3 = it2.first; it3 != it2.second; it3++) {
        if (it3->second == keyVal) {
            /* Mitigation -> in proxMox the value "BOCHS" is in this key*/
            if (keyVal == "SystemBiosVersion") {
                char* fakeValue = "ZenHack";
                PIN_SafeCopy(value, fakeValue, strlen(fakeValue));
            }
            std::stringstream ss;
            ss << "The process queried the value " << it3->second << " of the following registry key: " << keyname;
            EVASION("GENERIC SANDBOX CHECK", NULL, "reg_key_value", ss.str().c_str());
        }
    }

    free(keyValue);
}

/* Mutex */
void SyscallHooks::NtCreateMutantHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std)
{
    PIN_LockClient();
    W::POBJECT_ATTRIBUTES ObjectAttributes = (W::POBJECT_ATTRIBUTES)sc->arg2;
    wchar_t* buf = getWStrFromObjectAttribute(ObjectAttributes);
    PIN_UnlockClient();

    if (buf == NULL) {
        BEHAVIOURREPORT("MUTEX", "NtCreateMutant");
    }
    else {
        wstring ws(buf);
        string s(ws.begin(), ws.end());
        BEHAVIOURREPORTARG("MUTEX", "NtCreateMutant", s.c_str());
    }
}
void SyscallHooks::NtOpenMutantHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std)
{
    PIN_LockClient();
    W::POBJECT_ATTRIBUTES ObjectAttributes = (W::POBJECT_ATTRIBUTES)sc->arg2;
    wchar_t* buf = getWStrFromObjectAttribute(ObjectAttributes);
    PIN_UnlockClient();

    if (buf == NULL) {
        BEHAVIOURREPORT("MUTEX", "NtOpenMutant");
    }
    else {
        wstring ws(buf);
        string s(ws.begin(), ws.end());
        BEHAVIOURREPORTARG("MUTEX", "NtOpenMutant", s.c_str());
    }
}



/* FileSystem Monitor */
void SyscallHooks::NtOpenFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std)
{
    PIN_LockClient();
    W::PHANDLE FileHandleArg = (W::PHANDLE)sc->arg0;
    W::HANDLE FileHandle;
    PIN_SafeCopy((VOID*)&FileHandle, (VOID*)FileHandleArg, sizeof(W::HANDLE));
    PIN_UnlockClient();
    BEHAVIOURREPORTFILEHANDLE("NtOpenFile", FileHandle);
}

void SyscallHooks::NtCreateFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std)
{
    PIN_LockClient();
    W::PHANDLE FileHandleArg = (W::PHANDLE)sc->arg0;
    W::HANDLE FileHandle;
    PIN_SafeCopy((VOID*)&FileHandle, (VOID*)FileHandleArg, sizeof(W::HANDLE));
    PIN_UnlockClient();
    BEHAVIOURREPORTFILEHANDLE("NtCreateFile", FileHandle);
}

void SyscallHooks::NtReadFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std)
{
    PIN_LockClient();
    W::HANDLE FileHandleArg = (W::HANDLE)sc->arg0;
    W::HANDLE FileHandle;
    PIN_SafeCopy((VOID*)&FileHandle, (VOID*)&FileHandleArg, sizeof(W::HANDLE));
    PIN_UnlockClient();
    BEHAVIOURREPORTFILEHANDLE("NtReadFile", FileHandle);
}

void SyscallHooks::NtWriteFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std)
{
    PIN_LockClient();
    W::HANDLE FileHandleArg = (W::HANDLE)sc->arg0;
    W::HANDLE FileHandle;
    PIN_SafeCopy((VOID*)&FileHandle, (VOID*)&FileHandleArg, sizeof(W::HANDLE));
    PIN_UnlockClient();
    BEHAVIOURREPORTFILEHANDLE("NtWriteFile", FileHandle);
}

void SyscallHooks::NtDeviceIoControlFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std)
{
    PIN_LockClient();
    W::HANDLE FileHandleArg = (W::HANDLE)sc->arg0;
    W::HANDLE FileHandle;
    PIN_SafeCopy((VOID*)&FileHandle, (VOID*)&FileHandleArg, sizeof(W::HANDLE));
    PIN_UnlockClient();
    BEHAVIOURREPORTFILEHANDLE("NtDeviceIoControlFile", FileHandle);
}

void SyscallHooks::NtQueryInformationFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std)
{
    PIN_LockClient();
    W::HANDLE FileHandleArg = (W::HANDLE)sc->arg0;
    W::HANDLE FileHandle;
    PIN_SafeCopy((VOID*)&FileHandle, (VOID*)&FileHandleArg, sizeof(W::HANDLE));
    PIN_UnlockClient();
    BEHAVIOURREPORTFILEHANDLE("NtQueryInformationFile", FileHandle);
}

void SyscallHooks::NtSetInformationFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std)
{
    PIN_LockClient();
    W::HANDLE FileHandleArg = (W::HANDLE)sc->arg0;
    W::HANDLE FileHandle;
    PIN_SafeCopy((VOID*)&FileHandle, (VOID*)&FileHandleArg, sizeof(W::HANDLE));
    PIN_UnlockClient();
    BEHAVIOURREPORTFILEHANDLE("NtSetInformationFile", FileHandle);
}


void SyscallHooks::NtQueryAttributesFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std)
{
    W::POBJECT_ATTRIBUTES ObjectAttributes = (W::POBJECT_ATTRIBUTES) sc->arg0;

    wchar_t* buf = getWStrFromObjectAttribute(ObjectAttributes);
    wstring ws(buf);
    string s(ws.begin(), ws.end());

    for (auto it = fileSystemArtifacts.begin(); it != fileSystemArtifacts.end(); it++) {
        if (ws.find(it->first) != std::wstring::npos) {
            std::stringstream ss;
            ss << "The process accessed this filesystem artifact: " << s;
            EVASION("ANTIVM", it->second, "filesystem_artifacts", ss.str().c_str());
        }
    }
    BEHAVIOURREPORTARG("FILESYSTEM", "NtQueryAttributesFile", s.c_str());

    free(buf);
}

void SyscallHooks::NtDeleteFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std)
{
    PIN_LockClient();
    W::POBJECT_ATTRIBUTES ObjectAttributes = (W::POBJECT_ATTRIBUTES)sc->arg0;
    wchar_t* buf = getWStrFromObjectAttribute(ObjectAttributes);
    wstring ws(buf);
    string s(ws.begin(), ws.end());
    PIN_UnlockClient();
    BEHAVIOURREPORTARG("FILESYSTEM", "NtDeleteFile", s.c_str());
    free(buf);
}

/* Process Injection Hooks */

/*NtWriteVirtualMemory(
  IN HANDLE               ProcessHandle,
  IN PVOID                BaseAddress,
  IN PVOID                Buffer,
  IN ULONG                NumberOfBytesToWrite,
  OUT PULONG              NumberOfBytesWritten OPTIONAL );
 */
void SyscallHooks::NtWriteVirtualMemoryHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {

    W::HANDLE processHandle = (W::HANDLE)sc->arg0;
    W::PVOID BaseAddress = (W::PVOID)sc->arg1;
    W::PVOID pBuffer = (W::PVOID) sc->arg2;
    W::ULONG NumberOfBytesToWrite = (W::ULONG)sc->arg3;
    W::DWORD injectedPid = W::GetProcessId(processHandle);
    
    if (injectedPid != honeypotPID && injectedPid != W::GetCurrentProcessId()) {
        // Process is writing memory of another process 
        MYINFO("WRITE PROCESS MEMORY", "%s", ProcessIdToName(injectedPid).c_str());
        return;
    }
    wchar_t* myBuf = (wchar_t*)malloc(NumberOfBytesToWrite);
    wmemcpy(myBuf, (wchar_t*)pBuffer, NumberOfBytesToWrite);

    remoteWrittenAddresses.insert(BaseAddress);
    std::stringstream ss;
    ss << BaseAddress << " " << NumberOfBytesToWrite;
    sendMessageToPipe("[CODE]", ss.str());
    
    // Number of written bytes!
    MYINFO("INJECTION", "%d", NumberOfBytesToWrite);
}

/*NtCreateThreadEx(
    OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress, // Usually this address is the one of LoadLibrary
	IN PVOID lpParameter,   // This address is instead the baseAddress of the DLL to load! (passed as argument to LoadLibrary)
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);*/
void SyscallHooks::NtCreateThreadExHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
    W::HANDLE hProcess = (W::HANDLE) sc->arg3;
    W::PVOID lpStartAddress = (W::LPVOID) sc->arg4;
    W::PVOID lpParameter = (W::LPVOID) sc->arg5;
    W::DWORD injectedPid = W::GetProcessId(hProcess);
    std::stringstream ss;

    if (injectedPid != honeypotPID && injectedPid != W::GetCurrentProcessId()) {
        MYERROR("(NtCreateThreadExHook) Process is executing code in another unknown process....WTF?");
        return;
    }
    /*  When there is a DLL Injection, usually CreateRemoteThread is executed on LoadLibrary with the Dll name as parameter.
        I send to the honeypot process both addresses and it checks if the first address is LoadLibrary and the second contains
        a DLL name. If those conditions are true, detect a DLL Injection and manage it
    */
    if (remoteWrittenAddresses.find(lpParameter) != remoteWrittenAddresses.end()) {
        ss << lpStartAddress << " " << lpParameter;
        sendMessageToPipe("[DLL]", ss.str());
        remoteWrittenAddresses.erase(lpParameter);
    } 
    if (remoteWrittenAddresses.find(lpStartAddress) != remoteWrittenAddresses.end()) {

        EVASION("CODE INJECTION", NULL, "Shellcode_injected", "The program injected shellcode into another process and executed it");
        remoteWrittenAddresses.erase(lpStartAddress);
    }
}