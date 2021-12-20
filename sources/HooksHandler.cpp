#include "HooksHandler.h"
#include "Utils.h"
#include <string>
#include <sstream>


HooksHandler * HooksHandler::instance = NULL;
uint64_t lastRdtsc = 0;
W::ULONGLONG lastRdtscInstr = 0;
W::ULONGLONG numberOfExecutedInstructionsProgram = 0;
uint32_t rdtscCounter = 0;
uint32_t getTickCountCounter = 0;
uint32_t process32NextCounter = 0;

HooksHandler* HooksHandler::getInstance()
{
	return instance;
}

HooksHandler::~HooksHandler()
{
}

HooksHandler::HooksHandler(ProcessInfo* procInfo)
{
	this->procInfo = procInfo;
	
	/* Library Hooks */
	this->libraryHooks.insert(pair <string, libraryHooksId>("GetDiskFreeSpaceExW", GETDISKFREESPACEEX));
	this->libraryHooks.insert(pair <string, libraryHooksId>("GetDiskFreeSpaceExA", GETDISKFREESPACEEX));
	this->libraryHooks.insert(pair <string, libraryHooksId>("GetDiskFreeSpaceEx", GETDISKFREESPACEEX));
	this->libraryHooks.insert(pair <string, libraryHooksId>("GlobalMemoryStatusEx", GLOBALMEMORYSTATUSEX));
	this->libraryHooks.insert(pair <string, libraryHooksId>("GetCursorPos", GETCURSORPOS));
	this->libraryHooks.insert(pair <string, libraryHooksId>("SetupDiGetDeviceRegistryPropertyW", SETUPDIGETDEVICEREGISTRYPROPERTYW));
	this->libraryHooks.insert(pair <string, libraryHooksId>("DeviceIoControl", DEVICEIOCONTROL));
	this->libraryHooks.insert(pair <string, libraryHooksId>("GetAdaptersInfo", GETADAPTERSINFO));
	this->libraryHooks.insert(pair <string, libraryHooksId>("EnumServicesStatusExW", ENUMSERVICESSTATUSEXW));
	this->libraryHooks.insert(pair <string, libraryHooksId>("GetSystemInfo", GETSYSTEMINFO));
	this->libraryHooks.insert(pair <string, libraryHooksId>("OpenProcess", OPENPROCESS));
	this->libraryHooks.insert(pair <string, libraryHooksId>("GetModuleHandleW", GETMODULEHANDLE));
	this->libraryHooks.insert(pair <string, libraryHooksId>("IsDebuggerPresent", ISDEBUGGERPRESENT));
	this->libraryHooks.insert(pair <string, libraryHooksId>("CheckRemoteDebuggerPresent", CHECKREMOTEDEBUGGERPRESENT));
	this->libraryHooks.insert(pair <string, libraryHooksId>("GetThreadContext", GETTHREADCONTEXT));
	this->libraryHooks.insert(pair <string, libraryHooksId>("VirtualAlloc", VIRTUALALLOC));
	this->libraryHooks.insert(pair <string, libraryHooksId>("VirtualProtect", VIRTUALPROTECT));
	this->libraryHooks.insert(pair <string, libraryHooksId>("VirtualQuery", VIRTUALQUERY));
	this->libraryHooks.insert(pair <string, libraryHooksId>("CreateFileW", CREATEFILE));
	this->libraryHooks.insert(pair <string, libraryHooksId>("GetSystemFirmwareTable", GETSYSTEMFIRMWARETABLE));
	this->libraryHooks.insert(pair <string, libraryHooksId>("GetTickCount", GETTICKCOUNT));
	this->libraryHooks.insert(pair <string, libraryHooksId>("TimeSetEvent", TIMESETEVENT));
	this->libraryHooks.insert(pair <string, libraryHooksId>("WaitForSingleObject", WAITFORSINGLEOBJECT));
	this->libraryHooks.insert(pair <string, libraryHooksId>("Process32Next", PROCESS32NEXT));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtQueryInformationProcess", NTQUERYINFOPROCESS));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtQuerySystemInformation", NTQUERYSYSINFO));
	this->libraryHooks.insert(pair <string, libraryHooksId>("?Get@CWbemObject@@UAGJPBGJPAUtagVARIANT@@PAJ2@Z", WMI));
	
	/* Network API behaviour hooks*/
	this->libraryHooks.insert(pair <string, libraryHooksId>("DnsQuery_A", NETWORKBEHAVIOUR));
	this->set_in_pcstr.insert("DnsQuery_A");
	this->libraryHooks.insert(pair <string, libraryHooksId>("DnsQuery_W", NETWORKBEHAVIOUR));
	this->set_in_pcwstr.insert("DnsQuery_W");
	this->libraryHooks.insert(pair <string, libraryHooksId>("DnsQuery_UTF8", NETWORKBEHAVIOUR));
	this->set_in_pcstr.insert("DnsQuery_UTF8");
	this->libraryHooks.insert(pair <string, libraryHooksId>("URLDownloadToFileA", NETWORKBEHAVIOUR));
	this->set_in_pcstr.insert("URLDownloadToFileA");
	this->libraryHooks.insert(pair <string, libraryHooksId>("URLDownloadToFileW", NETWORKBEHAVIOUR));
	this->set_in_pcwstr.insert("URLDownloadToFileW");
	this->libraryHooks.insert(pair <string, libraryHooksId>("InternetOpenA", NETWORKBEHAVIOUR));
	this->set_in_pcstr.insert("InternetOpenA");
	this->libraryHooks.insert(pair <string, libraryHooksId>("InternetOpenW", NETWORKBEHAVIOUR));
	this->set_in_pcwstr.insert("InternetOpenW");
	this->libraryHooks.insert(pair <string, libraryHooksId>("InternetConnectA", NETWORKBEHAVIOUR));
	this->set_in_pcstr.insert("InternetConnectA");
	this->libraryHooks.insert(pair <string, libraryHooksId>("InternetConnectW", NETWORKBEHAVIOUR));
	this->set_in_pcwstr.insert("InternetConnectW");
	this->libraryHooks.insert(pair <string, libraryHooksId>("InternetOpenUrlA", NETWORKBEHAVIOUR));
	this->set_in_pcstr.insert("InternetOpenUrlA");
	this->libraryHooks.insert(pair <string, libraryHooksId>("InternetOpenUrlW", NETWORKBEHAVIOUR));
	this->set_in_pcwstr.insert("InternetOpenUrlW");

	this->libraryHooks.insert(pair <string, libraryHooksId>("HttpSendRequestA", NETWORKBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("HttpSendRequestW", NETWORKBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("InternetReadFile", NETWORKBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("InternetWriteFile", NETWORKBEHAVIOUR));

	this->libraryHooks.insert(pair <string, libraryHooksId>("connect", NETWORKBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("inet_addr", NETWORKBEHAVIOUR));
	this->set_in_pcstr.insert("inet_addr");

	
	/* Process API behaviour hooks*/
	this->set_process_out_first.insert("NtCreateProcess");
	this->set_process_out_first.insert("NtCreateProcessEx");
	this->set_process_out_first.insert("NtCreateUserProcess");
	this->set_process_out_first.insert("NtOpenProcess");
	this->set_process_out_first.insert("NtOpenSection");

	this->libraryHooks.insert(pair <string, libraryHooksId>("NtCreateProcess", PROCESSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtCreateProcessEx", PROCESSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtCreateUserProcess", PROCESSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("RtlCreateUserProcess", PROCESSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtOpenProcess", PROCESSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtTerminateProcess", PROCESSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtCreateSection", PROCESSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtMakeTemporaryObject", PROCESSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtMakePermanentObject", PROCESSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtOpenSection", PROCESSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtUnmapViewOfSection", PROCESSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtAllocateVirtualMemory", PROCESSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtReadVirtualMemory", PROCESSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtWriteVirtualMemory", PROCESSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtProtectVirtualMemory", PROCESSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtFreeVirtualMemory", PROCESSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtMapViewOfSection", PROCESSBEHAVIOUR));

	/* Thread APIs behaviour hooks */
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtCreateThread", THREADBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtCreateThreadEx", THREADBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtOpenThread", THREADBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtGetContextThread", THREADBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtSetContextThread", THREADBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtSuspendThread", THREADBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtResumeThread", THREADBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtTerminateThread", THREADBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("RtlCreateUserThread", THREADBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtQueueApcThread", THREADBEHAVIOUR));

	/* FileSystem API behaviour hooks */ 
	/*  SEE SYSHOOKS
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtCreateFile", FSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtDeleteFile", FSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtOpenFile", FSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtReadFile", FSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtWriteFile", FSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtDeviceIoControlFile", FSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtQueryDirectoryFile", FSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtQueryInformationFile", FSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtSetInformationFile", FSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtOpenDirectoryObject", FSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtCreateDirectoryObject", FSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtQueryAttributesFile", FSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtQueryFullAttributesFile", FSBEHAVIOUR));
	*/
	this->libraryHooks.insert(pair <string, libraryHooksId>("CreateFileA", FSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("DeleteFileA", FSBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("DeleteFileW", FSBEHAVIOUR));


	/* Registry API behaviour hooks */
	
	/* commented out because we are checking the syscalls
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtCreateKey", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtOpenKey", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtOpenKeyEx", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtRenameKey", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtReplaceKey", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtEnumerateKey", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtEnumerateValueKey", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtSetValueKey", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtQueryValueKey", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtQueryMultipleValueKey", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtDeleteKey", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtDeleteValueKey", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtLoadKey", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtLoadKey2", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtLoadKeyEx", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtQueryKey", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtSaveKey", REGISTRYBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtSaveKeyEx", REGISTRYBEHAVIOUR));
	*/

	/* Service API behaviour hooks */
	this->libraryHooks.insert(pair <string, libraryHooksId>("OpenServiceW", SERVICEBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("OpenServiceA", SERVICEBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("CreateServiceA", SERVICEBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("CreateServiceW", SERVICEBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("OpenSCManagerA", SERVICEBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("OpenSCManagerW", SERVICEBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("DeleteService", SERVICEBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("StartServiceA", SERVICEBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("StartServiceW", SERVICEBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("ControlService", SERVICEBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("EnumServicesStatusA", SERVICEBEHAVIOUR));
	this->libraryHooks.insert(pair <string, libraryHooksId>("EnumServicesStatusW", SERVICEBEHAVIOUR));

	/* Read Hooks */
	this->readHooks.insert(pair <ADDRINT, readHooksId>((ADDRINT)&procInfo->get_peb()->NumberOfProcessors, NUMBEROFPROCESSORS));
	this->readHooks.insert(pair <ADDRINT, readHooksId>((ADDRINT)&procInfo->get_peb()->BeingDebugged, BEINGDEBUGGED));
	this->readHooks.insert(pair <ADDRINT, readHooksId>((ADDRINT)&procInfo->get_peb()->NtGlobalFlag, NTGLOBALFLAG));
	this->readHooks.insert(pair <ADDRINT, readHooksId>((ADDRINT)procInfo->get_peb()->ProcessHeap + 0x40, HEAPFLAGS));
	this->readHooks.insert(pair <ADDRINT, readHooksId>((ADDRINT)procInfo->get_peb()->ProcessHeap + 0x44, HEAPFORCEFLAGS));
	this->readHooks.insert(pair <ADDRINT, readHooksId>((ADDRINT)(KUSER_SHARED_DATA + KERNEL_DEBUGGER_OFFSET), SHAREDUSERDATAKERNELDBG));


	/* Instruction Hooks*/
	this->instructionHooks.insert(pair <string, int>("rdtsc", RDTSC));
	this->instructionHooks.insert(pair <string, int>("cpuid", CPUID));
	this->instructionHooks.insert(pair <string, int>("sidt", SIDT));
	this->instructionHooks.insert(pair <string, int>("sgdt", SGDT));
	this->instructionHooks.insert(pair <string, int>("sldt", SLDT));
	this->instructionHooks.insert(pair <string, int>("str", STR));
	this->instructionHooks.insert(pair <string, int>("int", INTERRUPT));
	this->instructionHooks.insert(pair <string, int>("int3", BREAKPOINT));

	/* Initialize Device Artifacts */
	// VBox
	deviceArtifacts.insert(std::pair <wstring, const char *> (L"\\\\.\\VBoxMiniRdrDN", "VirtualBox"));
	deviceArtifacts.insert(std::pair <wstring, const char *> (L"\\\\.\\VBoxGuest", "VirtualBox"));
	deviceArtifacts.insert(std::pair <wstring, const char *> (L"\\\\.\\pipe\\VBoxMiniRdDN", "VirtualBox"));
	deviceArtifacts.insert(std::pair <wstring, const char *> (L"\\\\.\\VBoxTrayIPC", "VirtualBox"));
	deviceArtifacts.insert(std::pair <wstring, const char *> (L"\\\\.\\pipe\\VBoxTrayIPC", "VirtualBox"));
	deviceArtifacts.insert(std::pair <wstring, const char *> (L"\\\\.\\HGFS", "VWare"));
	deviceArtifacts.insert(std::pair <wstring, const char *> (L"\\\\.\\vmci", "VWare"));

	W::HMODULE ntdll = W::GetModuleHandle("ntdll.dll");
	/* To detect CsrGetProcessId technique */
	_CsrGetProcessId CsrGetProcessId = (_CsrGetProcessId)GetProcAddress(ntdll, "CsrGetProcessId");
	csrssId = CsrGetProcessId();
	isCsrss = false;
	if (!instance)
		instance = this;
	return;
}

void HooksHandler::readHooksHandler(ADDRINT readAddress)
{
	auto hook = readHooks.find(readAddress);
	if (hook != readHooks.end())
	{
		switch (hook->second)
		{
		case NUMBEROFPROCESSORS:
			W::DWORD fakeProcessorNumber;
			EVASION("GENERIC SANDBOX CHECK", NULL, "NumberOfProcessors", "Process read PEB->NumberOfProcessor");

			/* Modifying the number of processors */
			if (NUMBEROFPROCESSOR_MITIGATION) {
				fakeProcessorNumber = static_cast<W::DWORD>(4);
				PIN_SafeCopy((VOID*)readAddress, static_cast<void*>(&fakeProcessorNumber), sizeof(W::DWORD));
			}
			break;
		case GETADAPTERSINFOMACADDRESS:
			EVASION("GENERIC SANDBOX CHECK", "VirtualBox", "vbox_check_mac", "The process tries to get MAC Address of the system");
			break;
		case GLOBALMEMORYSTATUSEXRAMCHECK:
			EVASION("GENERIC SANDBOX CHECK", NULL, "memory_space ", "The process tries to detect ram size through GlobalMemoryStatusEx()");
			break;
		case GETSYSTEMINFOPROCESSORCHECK:
			EVASION("GENERIC SANDBOX CHECK", NULL, "NumberOfProcessors", "Process read number of processors through GetSystemInfo()");
			break;
		case BEINGDEBUGGED:
			EVASION("ANTIDEBUG", NULL, "IsDebuggerPresentPEB", "Process read BeingDebugged flag");
			break;
		case NTGLOBALFLAG:
			EVASION("ANTIDEBUG", NULL, "NtGlobalFlag", "Process read NtGlobalFlag flag");
			break;
		case HEAPFLAGS:
			EVASION("ANTIDEBUG", NULL, "HeapFlags", "Process read Heap Flags");
			break;
		case HEAPFORCEFLAGS:
			EVASION("ANTIDEBUG", NULL, "HeapForceFlags", "Process read Heap Force Flags");
			break;
		case HARDWAREBREAKPOINTS:
			EVASION("ANTIDEBUG", NULL, "HardwareBreakpoints", "Process read registers Dr0-4 to check for hardware breakpoints");
			break;
		case SHAREDUSERDATAKERNELDBG:
			EVASION("ANTIDEBUG", NULL, "SharedUserData_KernelDebugger", "Process check the presence of a kernel debugger in the ShareUserData struct");
			break;
		default: ;
		}
	}
}

/* If a monitored address is overwritten, I can delete the read/write hooks. */
/* Monitor writes*/
void HooksHandler::writeHooksHandler(ADDRINT writtenAddress, ADDRINT oldByte) {
	if (this->writeHooks.count(writtenAddress)) {
		this->removeReadWriteHooks(writtenAddress);
	}

	if ((W::PULONG)writtenAddress == sizeOfImageAddress) {
		EVASION("ANTIDUMP", NULL, "SizeOfImage", "The process is overwriting SizeOfImage value");
	}

	/*	Check if the address is the baseAddress, to detect eventual
		Anti-dump technique	*/
	ADDRINT baseAddress = HooksHandler::getInstance()->procInfo->baseAddress;
	if (writtenAddress < baseAddress + 0x1000 && writtenAddress >= baseAddress)
		PIN_SafeCopy((VOID*)oldByte, (VOID*)writtenAddress, sizeof(unsigned char));
}

/*	I hook on read the address, and on write all the addresses of that field.
	If a writeHook is triggered, then the correspective read hook must be deleted
	(Because if an address is overwrote, the information is not present anymore there)	*/
VOID HooksHandler::addReadWriteHook(ADDRINT address, readHooksId caseNumber, size_t numberOfAddresses)
{
	this->readHooks.insert(pair <ADDRINT, readHooksId>(address, caseNumber));
	for (size_t i = 0; i < numberOfAddresses; i++) {
		this->writeHooks.insert(pair <ADDRINT, size_t>(address + i, i));
	}
}

/*	If an address hooked has been written in the middle. I have to remove the hook on read
	and all the hooks on write	*/
VOID HooksHandler::removeReadWriteHooks(ADDRINT address)
{
	auto it = this->writeHooks.find(address);
	if (it != this->writeHooks.end()) {
		size_t number = it->second;
		ADDRINT firstAddress = address - number;
		this->readHooks.erase(firstAddress);
		for (size_t i = 0; this->writeHooks.count(firstAddress + i); i++) {
			this->writeHooks.erase(firstAddress + i);
		}
	}
}


/* ------------------ API HOOK FUNCTIONS --------------------- */

void HooksHandler::hookApiInThisLibrary(IMG img)
{
	const std::string dllName = getDllName(IMG_Name(img));
	
	// Pin cannot find this routine used for WMI so we define it manually
	if (IMG_Name(img).find("fastprox") != string::npos) {
		RTN tmp = RTN_CreateAt(IMG_LowAddress(img) + WMIOFFSETEXEC, "GetQuery");
		RTN_Open(tmp);
		RTN_InsertCall(tmp, IPOINT_BEFORE, (AFUNPTR)WMIExecQueryHook, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2, IARG_END);
		RTN_Close(tmp);
	}

	for (auto iter = libraryHooks.begin(); iter != libraryHooks.end(); ++iter)
	{
		/* Trying to find the routine in the image */
		string funcName = iter->first;
		const CHAR* funcNameC_str = funcName.c_str();
		RTN rtn = RTN_FindByName(img, funcNameC_str);
		if (!RTN_Valid(rtn)) continue;
		REGSET regsIn;
		REGSET regsOut;
		/* Instrument the routine found */
		RTN_Open(rtn);
		switch (iter->second)
		{
		case GETDISKFREESPACEEX:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetDiskFreeSpaceExW_After, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_RETURN_IP, IARG_END);
			break;
		case GLOBALMEMORYSTATUSEX:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GlobalMemoryStatusEx_After, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
			break;
		case GETCURSORPOS:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetCursorPos_After, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
			break;
		case SETUPDIGETDEVICEREGISTRYPROPERTYW:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)SetupDiGetDeviceRegistryPropertyW_After, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_RETURN_IP, IARG_END);
			break;
		case DEVICEIOCONTROL:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)DeviceIoControl_After, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_RETURN_IP, IARG_END);
			break;
		case GETADAPTERSINFO:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetAdaptersInfo_After, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
			break;
		case ENUMSERVICESSTATUSEXW:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetAdaptersInfo_After, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_RETURN_IP, IARG_END);
			break;
		case GETSYSTEMINFO:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetSystemInfo_After, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
			break;
		case OPENPROCESS:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)OpenProcess_Before, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2, IARG_RETURN_IP, IARG_END);
			/* Mitigation for csrss.exe ....Modifying the pid sometimes not work*/
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)OpenProcess_After, IARG_FUNCRET_EXITPOINT_REFERENCE, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2, IARG_RETURN_IP, IARG_END);
			break;
		case GETMODULEHANDLE:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetModuleHandle_Before, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
			break;
		case ISDEBUGGERPRESENT:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)IsDebuggerPresent_After, IARG_RETURN_IP, IARG_END);
			break;
		case CHECKREMOTEDEBUGGERPRESENT:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CheckRemoteDebuggerPresent_After, IARG_RETURN_IP, IARG_END);
			break;
		case GETTHREADCONTEXT:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetThreadContext_After, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_RETURN_IP, IARG_END);
			break;
		case VIRTUALALLOC:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)VirtualAlloc_Before, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2, IARG_RETURN_IP, IARG_END);
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VirtualAlloc_After, IARG_FUNCRET_EXITPOINT_VALUE, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_RETURN_IP, IARG_END);
			break;
		case VIRTUALPROTECT:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VirtualProtect_After, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_RETURN_IP, IARG_END);
			break;
		case VIRTUALQUERY:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VirtualQuery_After, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_RETURN_IP, IARG_END);
			break;
		case CREATEFILE:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CreateFile_After, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
			break;
		case GETSYSTEMFIRMWARETABLE:
			REGSET_Clear(regsIn);
			REGSET_Clear(regsOut);
			REGSET_Insert(regsIn, REG_EAX);
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetSystemFirmwareTable_After, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_RETURN_IP, IARG_END);
			break;
		case GETTICKCOUNT:
			REGSET_Clear(regsIn);
			REGSET_Clear(regsOut);
			REGSET_Insert(regsIn, REG_EAX);
			REGSET_Insert(regsOut, REG_EAX);
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetTickCount_After, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut, IARG_RETURN_IP, IARG_END);
			break;
		case TIMESETEVENT:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TimeSetEvent_Before, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_RETURN_IP, IARG_END);
			break;
		case WAITFORSINGLEOBJECT:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)WaitForSingleObject_Before, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1, IARG_RETURN_IP, IARG_END);
			break;
		case PROCESS32NEXT:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Process32Next_Before, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_RETURN_IP, IARG_END);
			break;
		case NTQUERYINFOPROCESS:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)NtQueryInformationProcess_Before, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_RETURN_IP, IARG_END);
			break;
		case NTQUERYSYSINFO:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)NtQuerySystemInformation_Before, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
			break;
		case WMI:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)WMIQueryHookExit,
				IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
				IARG_FUNCARG_ENTRYPOINT_REFERENCE, 3,
				IARG_END);
			break;
		
		/* Behavioural hooks*/
		case NETWORKBEHAVIOUR:
			if (set_in_pcstr.find(funcName) != set_in_pcstr.end()) {
				if (funcName.compare("DnsQuery_A") == 0 || funcName.compare("InternetOpenA") == 0 || funcName.compare("inet_addr") == 0 || funcName.compare("getaddrinfo") == 0) {
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)in_first_pcstr, IARG_FAST_ANALYSIS_CALL, IARG_ADDRINT, NETWORKBEHAVIOUR, IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
				}
				else {
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)in_first_pcstr, IARG_FAST_ANALYSIS_CALL, IARG_ADDRINT, NETWORKBEHAVIOUR, IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
				}
			}
			else if (set_in_pcwstr.find(funcName) != set_in_pcwstr.end()) {
				if (funcName.compare("DnsQuery_W") == 0 || funcName.compare("InternetOpenW") == 0) {
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)in_first_pcwstr, IARG_FAST_ANALYSIS_CALL, IARG_ADDRINT, NETWORKBEHAVIOUR, IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
				}
				else {
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)in_first_pcwstr, IARG_FAST_ANALYSIS_CALL, IARG_ADDRINT, NETWORKBEHAVIOUR, IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
				}
			}
			else if (funcName.compare("connect") == 0) {
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)log_connect, IARG_FAST_ANALYSIS_CALL, IARG_ADDRINT, NETWORKBEHAVIOUR, IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
			}
			else {
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)networkApiReport, IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_END);
			}
			break;
		case PROCESSBEHAVIOUR:
			if (set_process_out_first.find(funcName) != set_process_out_first.end()) {
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)process_out_first, IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
			}
			//else {
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)processApiReport, IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_END);
			//}
			break;
		case THREADBEHAVIOUR:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)threadApiReport, IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_END);
			break;
		case FSBEHAVIOUR:
			if (funcName.compare("DeleteFileW") == 0) {
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)DeleteFileWHook,  IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
			}
			else if (funcName.compare("DeleteFileA") == 0) {
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)DeleteFileAHook, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
			}
			else if (funcName.compare("CreateFileA") == 0) {
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CreateFileAHook, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
			}
			else {
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fileSystemApiReport, IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_END);
			}
			break;
		case REGISTRYBEHAVIOUR:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)registryApiReport, IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_END);
			break;
		case SERVICEBEHAVIOUR:
			if (funcName.compare("OpenServiceW") == 0) {
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)OpenServiceWHook, IARG_FUNCRET_EXITPOINT_REFERENCE, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_RETURN_IP, IARG_END);
			}
			else if (funcName.compare("OpenServiceA") == 0) {
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)OpenServiceAHook, IARG_FUNCRET_EXITPOINT_REFERENCE, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_RETURN_IP, IARG_END);
			}
			else if (funcName.compare("CreateServiceA") == 0) {
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CreateServiceAHook, IARG_FUNCRET_EXITPOINT_REFERENCE, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_RETURN_IP, IARG_END);
			}
			else if (funcName.compare("CreateServiceW") == 0) {
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CreateServiceWHook, IARG_FUNCRET_EXITPOINT_REFERENCE, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_RETURN_IP, IARG_END);
			}
			else {
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)serviceApiReport, IARG_FAST_ANALYSIS_CALL, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_INST_PTR, IARG_END);
			}
			break;
		}
		RTN_Close(rtn);
	}
}

VOID GetDiskFreeSpaceExW_After(UINT64* lpTotalNumberOfBytes, ADDRINT ret) {
	
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;

	EVASION("GENERIC SANDBOX CHECK", NULL, "disk_size_getdiskfreespace", "The process tries to detect hard disk size through GetDiskFreeSpaceExW()");

	// Mitigation
	W::ULONGLONG fakeSize = (800ULL * (1024ULL * (1024ULL * (1024ULL)))); // 800 GB
	PIN_SafeCopy(static_cast<void*>(lpTotalNumberOfBytes), static_cast<void*>(&fakeSize), sizeof(UINT64));
}

VOID GlobalMemoryStatusEx_After(W::LPMEMORYSTATUSEX lpBuffer, ADDRINT ret)
{

	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;

	// Hook on read of RAM Memory
	HooksHandler::getInstance()->addReadWriteHook((ADDRINT)&lpBuffer->ullTotalPhys, GLOBALMEMORYSTATUSEXRAMCHECK, sizeof(W::DWORDLONG));
	// Mitigation
	W::DWORDLONG fakeRAM = (8LL * 1024LL * (1024LL * (1024LL))); // 8GB
	PIN_SafeCopy(static_cast<void*>(&lpBuffer->ullTotalPhys), static_cast<void*>(&fakeRAM), sizeof(W::DWORDLONG));
}

void GetCursorPos_After(W::LPPOINT lpPoint, ADDRINT ret)
{

	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;
	EVASION("GENERIC SANDBOX CHECK", NULL, "mouse_movement", "The process tries to detect mouse movement through GetCursorPos()");

	if (MOUSEMOVEMENT_MITIGATION) {
		// Mitigation
		srand(time(NULL));
		int fakex = rand() % 1920;
		int fakey = rand() % 1080;
		W::LPPOINT p = new W::POINT();
		p->x = fakex;
		p->y = fakey;
		PIN_SafeCopy(static_cast<void*>(lpPoint), static_cast<void*>(&p), sizeof(W::POINT));
	}
}

void SetupDiGetDeviceRegistryPropertyW_After(W::PBYTE buffer, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;

	if (buffer)
	{
		EVASION("GENERIC SANDBOX CHECK", NULL, "setupdi_diskdrive", "The process tries to detect devices in the system through SetupDiGetDeviceRegistryPropertyW ()");

		// Mitigation
		size_t size = sizeof(W::WCHAR) * 50;
		W::WCHAR* realBuffer = (W::WCHAR*)malloc(size);
		PIN_SafeCopy((VOID*)realBuffer, (VOID*)buffer, size);
		size_t realSize = wcslen(realBuffer);
		
		W::WCHAR* newBuffer = (W::WCHAR*)malloc(realSize);
		for (size_t i = 0; i < realSize; i++)
		{
			wcsncpy(newBuffer, L"c" , sizeof(W::WCHAR));
		}
		PIN_SafeCopy((VOID*)buffer, (VOID*)newBuffer, realSize);

		free(realBuffer);
		free(newBuffer);
	}
}

void DeviceIoControl_After(W::DWORD dwloControlCode, W::LPVOID lpOutBuffer, ADDRINT ret)
{

	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;

	if (dwloControlCode == IOCTL_DISK_GET_LENGTH_INFO)
	{
		
		EVASION("GENERIC SANDBOX CHECK", NULL, "dizk_size_deviceiocontrol", "The process tries to detect hard disk size through DeviceIOControl()");

		// Mitigation
		W::GET_LENGTH_INFORMATION fakeValue;
		PIN_SafeCopy((VOID*)&fakeValue, (VOID*)lpOutBuffer, sizeof(W::GET_LENGTH_INFORMATION));
		fakeValue.Length.QuadPart = (800LL * (1024LL * (1024LL * (1024LL)))); // 800 GB
		PIN_SafeCopy((VOID*)lpOutBuffer, (VOID*) &fakeValue, sizeof(W::GET_LENGTH_INFORMATION));
	}
}

void GetAdaptersInfo_After(W::PIP_ADAPTER_INFO AdapterInfo, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;
	// Now I will check if the malware read the MAC ADDRESS
	HooksHandler::getInstance()->addReadWriteHook((ADDRINT)&AdapterInfo->Address, GETADAPTERSINFOMACADDRESS, sizeof(W::BYTE));
}

void EnumServicesStatusExW_After(int InfoLevel, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;
	if (InfoLevel == 0)
	{
		// related to 13 techniques in al-khaser
		EVASION("GENERIC SANDBOX CHECK", NULL, "VMDriverServices", "The process tries to detect services in the system through EnumServicesStatusExW()");
	}
}

VOID GetSystemInfo_After(W::LPSYSTEM_INFO lpSystemInfo, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;
	/* Mitigation */
	W::DWORD fakeNumberOfProcessors = 4;
	PIN_SafeCopy((VOID*)&lpSystemInfo->dwNumberOfProcessors, (VOID*)&fakeNumberOfProcessors, sizeof(W::DWORD));

	// Add read/write hook
	HooksHandler::getInstance()->addReadWriteHook((ADDRINT)&lpSystemInfo->dwNumberOfProcessors, GETSYSTEMINFOPROCESSORCHECK, sizeof(W::DWORD));
}

VOID OpenProcess_Before(W::PDWORD dwProcessId, ADDRINT ret) {
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;
	W::DWORD pid = 0;
	PIN_SafeCopy((VOID*)&pid, dwProcessId, sizeof(W::DWORD));
	if (pid != csrssId) {
		hookedPID.insert(pid);
		if (!honeypotPID && !findHoneypotProcess()) {
			return;
		}

		if (pid != W::GetCurrentProcessId() && pid != honeypotPID) {
			//MYINFO("Modified PID from %d to honeypotPID : %d", pid, honeypotPID);
			PIN_SafeCopy((VOID*)dwProcessId, &honeypotPID, sizeof(W::DWORD));
		}
	}
	else {
		isCsrss = true;
		EVASION("ANTIDEBUG", NULL, "CanOpenCsrss", "The process is trying to access to csrss.exe -> SeDebugPrivilege check");
	}
}

VOID OpenProcess_After(W::PHANDLE returnValue, W::PDWORD pid, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;
	/* Mitigation for CsrGetProcessId */
	if (isCsrss) {
		isCsrss = false;
		W::HANDLE newHandle = NULL;
		PIN_SafeCopy(returnValue, &newHandle, sizeof(W::HANDLE));
	}
}

VOID GetModuleHandle_Before(W::LPCWSTR lpModuleName, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;
	wchar_t* szDlls[] = {
		L"avghookx.dll",		// AVG
		L"avghooka.dll",		// AVG
		L"snxhk.dll",		// Avast
		L"sbiedll.dll",		// Sandboxie
		L"dbghelp.dll",		// WindBG
		L"api_log.dll",		// iDefense Lab
		L"dir_watch.dll",	// iDefense Lab
		L"pstorec.dll",		// SunBelt Sandbox
		L"vmcheck.dll",		// Virtual PC
		L"wpespy.dll",		// WPE Pro
		L"cmdvrt64.dll",		// Comodo Container
		L"cmdvrt32.dll",		// Comodo Container
	};
	int dwlength = sizeof(szDlls) / sizeof(szDlls[0]);
	size_t bufsize = sizeof(wchar_t) * 1024;
	wchar_t* name = (wchar_t*)malloc(bufsize);
	PIN_SafeCopy((void*)name, (void*)lpModuleName, bufsize);

	for (int i = 0; i < dwlength; i++)
	{
		if (!wcscmp(name, szDlls[i])) {
			wstring ws(szDlls[i]);
			string dll(ws.begin(), ws.end());
			string message("Process tried to load common AV Dll: " + dll);
			EVASION("GENERIC SANDBOX CHECK", NULL, "loaded_dlls", message.c_str());

			/* Mitigation (is not important to overwrite all the real argument)*/
			wchar_t* fakeDLL = L"deadbeef.dll";
			PIN_SafeCopy((void*)lpModuleName, (void*)fakeDLL, wcslen(fakeDLL));
			return;
		}

	}
	free(name);
}

VOID IsDebuggerPresent_After(ADDRINT ret) {
	
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;
	EVASION("ANTIDEBUG", NULL, "IsDebuggerPresentAPI", "The process called IsDebuggerPresent()");	
}

VOID CheckRemoteDebuggerPresent_After(ADDRINT ret) {
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;

	EVASION("ANTIDEBUG", NULL, "CheckRemoteDebuggerPresentAPI", "The process called CheckRemoteDebuggerPresent()");
}

VOID GetThreadContext_After(W::PCONTEXT pctx, ADDRINT ret) {
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;
	
	W::CONTEXT ctx;
	PIN_SafeCopy((void*)&ctx, (void*)pctx, sizeof(W::CONTEXT));

	// Add read/write hook on Hardware Breakpoint registers (Dr0, Dr1, Dr2, Dr3)!
	if (ctx.ContextFlags == CONTEXT_DEBUG_REGISTERS) {
		HooksHandler::getInstance()->addReadWriteHook((ADDRINT)&pctx->Dr0, HARDWAREBREAKPOINTS, sizeof(W::DWORD));
		HooksHandler::getInstance()->addReadWriteHook((ADDRINT)&pctx->Dr1, HARDWAREBREAKPOINTS, sizeof(W::DWORD));
		HooksHandler::getInstance()->addReadWriteHook((ADDRINT)&pctx->Dr2, HARDWAREBREAKPOINTS, sizeof(W::DWORD));
		HooksHandler::getInstance()->addReadWriteHook((ADDRINT)&pctx->Dr3, HARDWAREBREAKPOINTS, sizeof(W::DWORD));
	}
}

VOID VirtualAlloc_Before(W::PDWORD pflProtectionType, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;
	W::DWORD flProtectionType;

	PIN_SafeCopy(&flProtectionType, pflProtectionType, sizeof(W::DWORD));
	
	if (flProtectionType & MEM_WRITE_WATCH) {
		EVASION("ANTIDEBUG", NULL, "VirtualAlloc_WriteWatch_*", "The program allocated a page with MEM_WRITE_WATCH parameter");
		flProtectionType = flProtectionType & (!MEM_WRITE_WATCH & 0xFFFFFFFF) ;
		PIN_SafeCopy(pflProtectionType, &flProtectionType, sizeof(W::DWORD));
	}

}

VOID VirtualAlloc_After(W::LPVOID lpAddress, W::SIZE_T dwSize, W::DWORD flProtect, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;

	/* If VirtualAlloc Fails, return NULL*/
	if (!lpAddress)
		return;

	HooksHandler::getInstance()->procInfo->insertAllocatedMemory(lpAddress, dwSize);

	if (flProtect & PAGE_EXECUTE ||
		flProtect & PAGE_EXECUTE_READ ||
		flProtect & PAGE_EXECUTE_READWRITE ||
		flProtect & PAGE_EXECUTE_WRITECOPY)
		MYINFO("VIRTUAL ALLOC EXEC", "%p", lpAddress);

}

VOID VirtualProtect_After(W::LPVOID lpAddress, W::SIZE_T dwSize, W::DWORD flNewProtect, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;

	/* Check if the page is mapped as executable.*/
	if (flNewProtect & PAGE_EXECUTE ||
		flNewProtect & PAGE_EXECUTE_READ ||
		flNewProtect & PAGE_EXECUTE_READWRITE ||
		flNewProtect & PAGE_EXECUTE_WRITECOPY) {
		HooksHandler::getInstance()->procInfo->insertAllocatedMemory(lpAddress, dwSize);
		// The process set executable a preallocated piece of memory
		MYINFO("VIRTUAL PROTECT", " %p", lpAddress);
	}
	/* Check if the page is a Guard Page */
	if (flNewProtect & PAGE_GUARD) {
		HooksHandler::getInstance()->procInfo->insertGuardPage(lpAddress, dwSize);
		// Process changed permission to a page, to create a PAGE GUARD 
		MYINFO("PAGE GUARD", "%p", lpAddress);
	}

}

VOID VirtualQuery_After(W::LPVOID lpAddress, W::PMEMORY_BASIC_INFORMATION lpBuffer, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;
	/*	We have verify if the requested address could be 
		suspected for the program */
	W::MEMORY_BASIC_INFORMATION mbi;
	PIN_SafeCopy(&mbi, lpBuffer, sizeof(W::MEMORY_BASIC_INFORMATION));
	if (isSuspectedModule(lpAddress, mbi)) {
		W::DWORD newState = MEM_FREE;
		PIN_SafeCopy(&lpBuffer->State, &newState, sizeof(W::DWORD));
	}
}


VOID CreateFile_After(W::LPCWSTR lpFileName, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;

	wchar_t* filename = (wchar_t*)malloc(sizeof(wchar_t) * MAX_PATH);

	PIN_SafeCopy((VOID*)filename, (VOID*)lpFileName, sizeof(wchar_t) * MAX_PATH);
	wstring ws(filename);
	std::stringstream ss;
	string s(ws.begin(), ws.end());

	auto it = deviceArtifacts.find(ws);
	if (it != deviceArtifacts.end()) {
		ss << "The process tried to access to device: " << s;
		EVASION("ANTIVM", it->second, "Device Artifacts", ss.str().c_str());
	}
	else {
		BEHAVIOURREPORTARG("FILESYSTEM", "CreateFileW", s.c_str());
	}

	free(filename);
}

VOID GetSystemFirmwareTable_After(CONTEXT * ctxt, W::DWORD FirmwareTableProviderSignature, W::PVOID pFirmwareTableBuffer, W::DWORD bufferSize, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;
	if (FirmwareTableProviderSignature == (W::DWORD)'ACPI') {
		EVASION("ANTIVM", NULL, "Firmware ACPI", "The process asked the Firmware Table, it can detect some hypervisors");
		/* Mitigation -> I erase the buffer that contains the hypervisor name */
		size_t EAX = (size_t)PIN_GetContextReg(ctxt, REG_EAX);
		if (EAX != 0 && EAX <= bufferSize) {
			//std::cerr << "erasing " << EAX << " bytes" << std::endl;
			char* newBuffer = new char[EAX]();
			memset(newBuffer, 0x90, EAX);
			PIN_SafeCopy(pFirmwareTableBuffer, newBuffer, EAX);
			free(newBuffer);
		}
	}
	if (FirmwareTableProviderSignature == (W::DWORD)'RSMB') {
		EVASION("ANTIVM", NULL, "Firmware RSMB", "The process asked the Firmware Table, it can detect some hypervisors");
		/* Mitigation -> I erase the buffer that contains the hypervisor name */
		ADDRINT EAX = PIN_GetContextReg(ctxt, REG_EAX);
		if (EAX != 0 && EAX <= bufferSize) {
			//std::cerr << "erasing " << EAX << " bytes" << std::endl;
			char* newBuffer = new char[EAX]();
			memset(newBuffer, 0x90, EAX);
			PIN_SafeCopy(pFirmwareTableBuffer, newBuffer, EAX);
			free(newBuffer);
		}
	}
}

VOID GetTickCount_After(CONTEXT *ctxt, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;
	getTickCountCounter += 1;
	/*	In this way, if the process tries to detect time acceleration
		sleeping some time between two GetTickCount(), it doesn't
		see anything strange!
	*/
	if (GETTICKCOUNT_MITIGATION) {
		W::DWORD fakeResult = PIN_GetContextReg(ctxt, REG_EAX);
		fakeResult += sleepTime;
		PIN_SetContextReg(ctxt, REG_EAX, fakeResult);
	}	
}

VOID TimeSetEvent_Before(W::PUINT puDelay, W::UINT fuEvent, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;
	W::UINT delay;

	PIN_SafeCopy(&delay, puDelay, sizeof(W::UINT));

	/*  Modify delay time to be 1 ms only if type is TIME_ONESHOT 
		Otherwise I should trigger the event every 1 ms ...
		it could be a problem */
	if (fuEvent == TIME_ONESHOT && delay >= DELAY_MINIMUM_VALUE && delay <= DELAY_MINIMUM_VALUE * 10) {
		std::stringstream ss;
		ss << "The process is setting a timer with TimeSetEvent() for " << delay << "ms";
		EVASION("TIMING ATTACK", NULL, "timing_timeSetEvent", ss.str().c_str());
		sleepTime += delay;
		delay = 1;
		PIN_SafeCopy(puDelay, &delay, sizeof(W::UINT));
	}

}

VOID WaitForSingleObject_Before(W::PDWORD pDelayInMillis, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;
	W::DWORD delay;

	PIN_SafeCopy(&delay, pDelayInMillis, sizeof(W::DWORD));
	/*  Modify delay time to be 1000 ms only if the delay is valid! */
	if (delay >= DELAY_MINIMUM_VALUE && delay <= DELAY_MINIMUM_VALUE * 10) {
		std::stringstream ss;
		ss << "The process is delaying execution with WaitForSingleObject() for " << delay << "ms";
		EVASION("TIMING ATTACK", NULL, "timing_WaitForSingleObject", ss.str().c_str());
		sleepTime += delay - 1000;
		delay = 1000;
		PIN_SafeCopy(pDelayInMillis, &delay, sizeof(W::DWORD));
	}
}

/* Detect if the malware is enumerating processes! */
VOID Process32Next_Before(W::LPPROCESSENTRY32 lppe, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret)) return;
	W::PROCESSENTRY32 pe32;

	process32NextCounter++;
	PIN_SafeCopy(&pe32, lppe, sizeof(W::PROCESSENTRY32));

	/* Hide pin.exe from the list of processes! */
	if (W::StrCmpI(pe32.szExeFile, "pin.exe") == 0)
	{
		MYINFO("PROCESS ENUMERATION", "Potential detection of pin.exe through Process32Next");
		char* newName = "cmd.exe";
		PIN_SafeCopy(&lppe->szExeFile, newName, strlen(newName));
	}

}

VOID WMIQueryHookExit(W::LPCWSTR* query, W::VARIANT** var)
{
	// Get the data from the query
	if (*var == NULL) return;

	if ((*var)->n1.n2.vt != W::VT_NULL) {

		char value[MAX_QUERY_SIZE];
		GET_STR_TO_UPPER(*query, value, MAX_QUERY_SIZE);

		MYINFO("WMI-Get", "%s", value);
		
		if (strstr(value, "NUMBEROFCORES") != NULL) {
			EVASION("GENERIC SANDBOX CHECK", NULL, "number_cores_wmi", "The process ask for number of cores in the machine through WMI");
			(*var)->n1.n2.n3.uintVal = 8;
		}

		else if (strstr(value, "SERIALNUMBER") != NULL) {
			EVASION("GENERIC SANDBOX CHECK", NULL, "serial_number_bios_wmi", "The process ask serial number through WMI");
		}

		else if (strstr(value, "SIZE") != NULL) {
			EVASION("GENERIC SANDBOX CHECK", NULL, "disk_size_wmi", "The process ask for disk size through WMI");
		}
		
		else if (strstr(value, "MODEL") != NULL) {
			EVASION("GENERIC SANDBOX CHECK", NULL, "model_computer_system_wmi", "The process ask for model computer through WMI");
		}

		else if (strstr(value, "MANUFACTURER") != NULL) {
			EVASION("GENERIC SANDBOX CHECK", NULL, "manufacturer_computer_system_wmi", "The process ask for manufacturer computer through WMI");
		}

		else if (strstr(value, "CURRENTTEMPERATURE") != NULL) {
			EVASION("GENERIC SANDBOX CHECK", NULL, "current_temperature_acpi_wmi", "The process ask for current temperature through WMI");
		}

		else if (strstr(value, "PROCESSORID") != NULL) {
			EVASION("GENERIC SANDBOX CHECK", NULL, "process_id_processor_wmi", "The process ask for processor id through WMI");
		}

		else if (strstr(value, "DEVICEID") != NULL) {
			EVASION("ANTIVM", NULL, "vbox_pnpentity_pcideviceid_wmi", "The process ask for device id through WMI");
		}

		else if (strstr(value, "NAME") != NULL) {
			EVASION("ANTIVM", NULL, "vbox_wmi", "The process ask for names through WMI");
		}

		else if (strstr(value, "MACADDRESS") != NULL) {
			EVASION("ANTIVM", "VBOX", "vbox_mac_wmi", "The process ask mac address through WMI");
		}
	}
}

VOID NtQueryInformationProcess_Before(W::PROCESSINFOCLASS ProcessInformationClass, W::PVOID ProcessInformation, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret))
		return;
	Complete_PROCESS_BASIC_INFORMATION* pbi = (Complete_PROCESS_BASIC_INFORMATION*)ProcessInformation;
	if (ProcessInformationClass == PROCESSDEBUGPORT) {
		EVASION("ANTIDEBUG", NULL, "NtQueryInformationProcess_ProcessDebugPort", "");
	}
	else if (ProcessInformationClass == PROCESSDEBUGFLAGS) {
		EVASION("ANTIDEBUG", NULL, "NtQueryInformationProcess_ProcessDebugFlag", "");
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

VOID NtQuerySystemInformation_Before(W::SYSTEM_INFORMATION_CLASS SystemInformationClass, ADDRINT ret)
{
	if (!isAddressInsideRedZoneOrRedZoneHoneypot(ret))
		return;
	if (SystemInformationClass == SYSTEM_KERNEL_DEBUGGER_INFORMATION)
		EVASION("ANTIDEBUG", NULL, "NtQuerySystemInformation_SystemKernelDebuggerInformation", "Program tried to get kernel debugging information to detect attached debugger");
}

VOID DeleteFileAHook(W::LPCSTR lpFileName, ADDRINT ret)
{
	PIN_LockClient();
	char* buff = (char*)malloc(sizeof(char) * MAX_PATH);
	PIN_SafeCopy((VOID*)buff, (VOID*)lpFileName, MAX_PATH);
	PIN_UnlockClient();
	BEHAVIOURREPORTARG("FILESYSTEM", "DeleteFileA", buff);
	free(buff);
}

VOID CreateFileAHook(W::LPCSTR lpFileName, ADDRINT ret)
{
	PIN_LockClient();
	char* buff = (char*)malloc(sizeof(char) * MAX_PATH);
	PIN_SafeCopy((VOID*)buff, (VOID*)lpFileName, MAX_PATH);
	PIN_UnlockClient();
	BEHAVIOURREPORTARG("FILESYSTEM", "CreateFileA", buff);
	free(buff);
}

VOID DeleteFileWHook(W::LPCWSTR lpFileName, ADDRINT ret)
{
	PIN_LockClient();
	wchar_t* filename = (wchar_t*)malloc(sizeof(wchar_t) * MAX_PATH);
	PIN_SafeCopy((VOID*)filename, (VOID*)lpFileName, sizeof(wchar_t) * MAX_PATH);
	wstring ws(filename);
	string s(ws.begin(), ws.end());
	PIN_UnlockClient();
	BEHAVIOURREPORTARG("FILESYSTEM", "DeleteFileW", s.c_str());
	free(filename);
}


VOID CreateServiceAHook(W::LPSC_HANDLE pscHandle, W::LPCSTR lpServiceName, ADDRINT ret)
{
	PIN_LockClient();
	int sc_handle;
	PIN_SafeCopy((VOID*)&sc_handle, (VOID*)pscHandle, sizeof(int));
	char* buff = (char*)malloc(sizeof(char) * MAX_PATH);
	PIN_SafeCopy((VOID*)buff, (VOID*)lpServiceName, MAX_PATH);
	std::ostringstream ss;
	ss << "NAME=";
	ss << buff;
	ss << "HANDLE=";
	ss << sc_handle;
	PIN_UnlockClient();
	BEHAVIOURREPORTARG("SERVICE", "CreateServiceA", buff);
	free(buff);
}

VOID CreateServiceWHook(W::LPSC_HANDLE pscHandle, W::LPCWSTR lpServiceName, ADDRINT ret)
{
	PIN_LockClient();
	int sc_handle;
	PIN_SafeCopy((VOID*)&sc_handle, (VOID*)pscHandle, sizeof(int));
	wchar_t* filename = (wchar_t*)malloc(sizeof(wchar_t) * MAX_PATH);
	PIN_SafeCopy((VOID*)filename, (VOID*)lpServiceName, sizeof(wchar_t) * MAX_PATH);
	wstring ws(filename);
	string s(ws.begin(), ws.end());
	std::ostringstream ss;
	ss << "NAME=";
	ss << s;
	ss << "HANDLE=";
	ss << sc_handle;
	PIN_UnlockClient();
	BEHAVIOURREPORTARG("SERVICE", "CreateServiceW", ss.str().c_str());
	free(filename);
}

VOID OpenServiceAHook(W::LPSC_HANDLE pscHandle, W::LPCSTR lpServiceName, ADDRINT ret)
{
	PIN_LockClient();
	W::SC_HANDLE sc_handle;
	PIN_SafeCopy((VOID*)&sc_handle, (VOID*)pscHandle, sizeof(W::SC_HANDLE));
	char* buff = (char*)malloc(sizeof(char) * MAX_PATH);
	PIN_SafeCopy((VOID*)buff, (VOID*)lpServiceName, MAX_PATH);
	std::ostringstream ss;
	ss << "NAME=";
	ss << buff;
	ss << "HANDLE=";
	ss << sc_handle;
	PIN_UnlockClient();
	BEHAVIOURREPORTARG("SERVICE", "OpenServiceA", buff);
	free(buff);
}

VOID OpenServiceWHook(W::LPSC_HANDLE pscHandle, W::LPCWSTR lpServiceName, ADDRINT ret)
{
	PIN_LockClient();
	W::SC_HANDLE sc_handle;
	PIN_SafeCopy((VOID*)&sc_handle, (VOID*)pscHandle, sizeof(W::SC_HANDLE));
	wchar_t* filename = (wchar_t*)malloc(sizeof(wchar_t) * MAX_PATH);
	PIN_SafeCopy((VOID*)filename, (VOID*)lpServiceName, sizeof(wchar_t) * MAX_PATH);
	wstring ws(filename);
	string s(ws.begin(), ws.end());
	std::ostringstream ss;
	ss << "NAME=";
	ss << s;
	ss << "HANDLE=";
	ss << sc_handle;
	PIN_UnlockClient();
	BEHAVIOURREPORTARG("SERVICE", "OpenServiceW", ss.str().c_str());
	free(filename);
}

VOID PIN_FAST_ANALYSIS_CALL networkApiReport(ADDRINT ip)
{
	string name = RTN_FindNameByAddress(ip);
	BEHAVIOURREPORT("NETWORK", name.c_str());
}

VOID PIN_FAST_ANALYSIS_CALL processApiReport(ADDRINT ip)
{
	string name = RTN_FindNameByAddress(ip);
	BEHAVIOURREPORT("PROCESS", name.c_str());
}

VOID PIN_FAST_ANALYSIS_CALL in_first_pcstr(uint32_t hooksId, ADDRINT ip, W::PCSTR pszName)
{
	PIN_LockClient();
	string name = RTN_FindNameByAddress(ip);
	char* buff = (char*)malloc(sizeof(char)* MAX_PATH);
	PIN_SafeCopy((VOID*)buff, (VOID*)pszName, MAX_PATH);
	PIN_UnlockClient();

	BEHAVIOURREPORIDARG(hooksId, name.c_str(), buff);
	free(buff);
}

VOID PIN_FAST_ANALYSIS_CALL in_first_pcwstr(uint32_t hooksId, ADDRINT ip, W::PCWSTR pszName)
{
	PIN_LockClient();
	string name = RTN_FindNameByAddress(ip);
	std::wstring ws(pszName);
	std::string test(ws.begin(), ws.end());
	PIN_UnlockClient();

	BEHAVIOURREPORTARG("NETWORK", name.c_str(), test.c_str());
}


VOID PIN_FAST_ANALYSIS_CALL log_connect(uint32_t hooksId, ADDRINT ip, W::sockaddr_in* sockin) {
	PIN_LockClient();
	string name = RTN_FindNameByAddress(ip);
	W::sockaddr_in sockincpy;
	PIN_SafeCopy((VOID*)&sockincpy, (VOID*)sockin, sizeof(W::sockaddr_in));

	char buffer[50];
	uint16_t port = our_htons(sockincpy.sin_port);
	const char* ipstr = our_inet_ntoa(sockincpy.sin_addr);
	sprintf(buffer, "%s:%d", ipstr, port);
	PIN_UnlockClient();

	BEHAVIOURREPORIDARG(hooksId, name.c_str(), buffer);
}

VOID PIN_FAST_ANALYSIS_CALL process_out_first(ADDRINT ip, W::PHANDLE processHandle)
{
	string name = RTN_FindNameByAddress(ip);

	W::TCHAR buff[88];
	W::HANDLE newh;
	PIN_SafeCopy((VOID*)&newh, processHandle, sizeof(W::HANDLE));
	if (W::GetModuleFileNameExA(newh, NULL, buff, 88) != 0) {
		BEHAVIOURREPORTARG("PROCESS", name.c_str(), buff);
	}
	else {
		BEHAVIOURREPORT("PROCESS", name.c_str());
	}
}

VOID PIN_FAST_ANALYSIS_CALL threadApiReport(ADDRINT ip)
{
	string name = RTN_FindNameByAddress(ip);
	BEHAVIOURREPORT("THREAD", name.c_str());
}

VOID PIN_FAST_ANALYSIS_CALL fileSystemApiReport(ADDRINT ip)
{
	string name = RTN_FindNameByAddress(ip);
	BEHAVIOURREPORT("FILESYSTEM", name.c_str());
}

VOID PIN_FAST_ANALYSIS_CALL registryApiReport(ADDRINT ip)
{
	string name = RTN_FindNameByAddress(ip);
	BEHAVIOURREPORT("REGISTRY", name.c_str());
}
	
VOID PIN_FAST_ANALYSIS_CALL serviceApiReport(W::SC_HANDLE sc_handle_arg, ADDRINT ip)
{
	PIN_LockClient();
	string name = RTN_FindNameByAddress(ip);
	std::ostringstream ss;
	ss << "HANDLE=" << sc_handle_arg;
	PIN_UnlockClient();
	BEHAVIOURREPORTARG("SERVICE", name.c_str(), ss.str().c_str());
}

	

/* ------------------ INSTRUCTION HOOKS FUNCTIONS --------------------- */

void HooksHandler::instructionHooksHandler(INS ins)
{
	string disass_instr = INS_Disassemble(ins);
	string arg;
	int int_arg;
	string instruction = disass_instr.substr(0, disass_instr.find(' '));
	
	auto it = instructionHooks.find(instruction);
	if (it == instructionHooks.end()) return;
	REGSET regsIn;
	REGSET regsOut;
	int type = 0;
	switch (it->second)
	{
	case RDTSC:
		REGSET_Clear(regsIn);
		REGSET_Clear(regsOut);
		REGSET_Insert(regsOut, REG_EAX);
		REGSET_Insert(regsOut, REG_EDX);
		REGSET_Insert(regsIn, REG_EAX);
		REGSET_Insert(regsIn, REG_EDX);
		INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)rdtscHook, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut, IARG_END);
		break;
	case CPUID:
		REGSET_Clear(regsIn);
		REGSET_Clear(regsOut);
		REGSET_Insert(regsIn, REG_EAX);
		REGSET_Insert(regsIn, REG_EIP);
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)cpuidHookBefore, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut, IARG_ADDRINT, &type, IARG_END);
		REGSET_Insert(regsOut, REG_EBX);
		REGSET_Insert(regsOut, REG_ECX);
		REGSET_Insert(regsOut, REG_EDX);
		INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)cpuidHookAfter, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut, IARG_ADDRINT, &type, IARG_END);
		break;
	case SIDT:
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)sidtHook, IARG_END);
		break;
	case SGDT:
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)sgdtHook, IARG_END);
		break;
	case SLDT:
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)sldtHook, IARG_END);
		break;
	case STR:
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)strHook, IARG_END);
		break;
	case INTERRUPT:
		arg = disass_instr.substr(disass_instr.find(' '), disass_instr.length());
		int_arg = strtol(arg.c_str(), NULL, 16);
		if (int_arg == 0x2e) {
			REGSET_Clear(regsIn);
			REGSET_Clear(regsOut);
			REGSET_Insert(regsOut, REG_EDX);
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)int2e, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut, IARG_INST_PTR, IARG_END);
		}
		else if (int_arg == 3) {
			EVASION("ANTIDEBUG", NULL, "Interrupt_3", "Process uses INT 3 to trigger an exception");
		}
		else if (int_arg == 0x2d) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)int2d, IARG_CONTEXT, IARG_THREAD_ID, IARG_INST_PTR, IARG_END);
			
		}
		break;
	case BREAKPOINT:
		EVASION("ANTIDEBUG", NULL, "Interrupt_3", "Process uses int3 to trigger an exception");
		break;
	default:;
	}
}

/*	Patch RDTSC -> Modify value in EDX:EAX registers to be the old value + RDTSC_AVG_Value
	in this way two call to rdtsc will give as difference RDTSC_AVG_VALUE */
VOID rdtscHook(CONTEXT* ctxt) {
	uint32_t eax, edx;
	rdtscCounter++;
	// If it is the first time that the instruction is used, save the return value
	if (lastRdtsc == 0) {
		// pack those two registers into one 64bit variable!
		eax = PIN_GetContextReg(ctxt, REG_EAX);
		edx = PIN_GetContextReg(ctxt, REG_EDX);
		lastRdtsc = (uint64_t)(((uint64_t)edx << 32) + eax);
		lastRdtscInstr = numberOfExecutedInstructionsProgram;
		return;
	}
	//  If the distance between the 2 rdtsc is small ->
	if (numberOfExecutedInstructionsProgram - lastRdtscInstr < RDTSC_DISTANCE) {
		
		/*	This is to avoid the detection with rdtsc_diff_locky() and
			rdtsc_diff_vmexit() from al-khaser */
		if (rdtscCounter % 2)
			lastRdtsc += RDTSC_AVG_VALUE;
		else
			lastRdtsc += 10 * RDTSC_AVG_VALUE;

		eax = (uint32_t)(lastRdtsc & 0xFFFFFFFFLL) + sleepTime;
		edx = (uint32_t)((lastRdtsc & 0xFFFFFFFF00000000LL) >> 32);

		PIN_SetContextReg(ctxt, REG_EAX, eax);
		PIN_SetContextReg(ctxt, REG_EDX, edx);
	}

	lastRdtscInstr = numberOfExecutedInstructionsProgram;
}

VOID cpuidHookBefore(CONTEXT* ctxt, int* value)
{
	UINT32 eax_value = PIN_GetContextReg(ctxt, REG_EAX);
	UINT32 eip;
	unsigned char toCheckBytes[85];

	if (eax_value == 0x40000000)
	{
		EVASION("GENERIC SANDBOX CHECK", NULL, "cpuid_hypervisor_vendor", "The process tried to detect hypervisors using CPUID with EAX=0x40000000");
		int val = 1;
		PIN_SafeCopy((VOID*)value, (VOID*)&val, sizeof(int));
	} else if (eax_value == 1)
	{
		/* Check if it is a false positive */
		eip = PIN_GetContextReg(ctxt, REG_EIP);
		UINT32 copiedBytes = PIN_SafeCopy(toCheckBytes, (VOID*)(eip - 85), sizeof(char) * 85);

		// Check if it is a false positive
		if (copiedBytes && !isMsvcCpuid(toCheckBytes)) {
			EVASION("GENERIC SANDBOX CHECK", NULL, "cpuid_is_hypervisor", "The process tried to detect hypervisors using CPUID with EAX=1");
		}
		else {
			MYINFO("MSVC", "Found cpuid(0x1) that match MSVC compiler routine");
		}
		int val = 2;
		PIN_SafeCopy((VOID*)value, (VOID*)&val, sizeof(int));
	}
}

VOID cpuidHookAfter(CONTEXT* ctxt, int* value) {

	if (!*value) return;

	int val = 0;
	PIN_SafeCopy((VOID*)&val, (VOID*)value, sizeof(int));
	if (val == 1)
	{
		/* MITIGATE CPUID with eax = 0x40000000 */
		PIN_SetContextReg(ctxt, REG_EBX, 0xdeadbeef);
		PIN_SetContextReg(ctxt, REG_ECX, 0xdeadbeef);
		PIN_SetContextReg(ctxt, REG_EDX, 0xdeadbeef);
	} else if (val == 2 & CPUID_1_MITIGATION)
	{
		/* MITIGATE CPUID with eax = 0x1 */
		UINT32 ecx_value = PIN_GetContextReg(ctxt, REG_ECX);
		UINT32 new_ecx_value = (ecx_value >> 31) & 0; // Force the 31th bit of ECX (hypervisor bit) to be 0
		PIN_SetContextReg(ctxt, REG_ECX, new_ecx_value);
	}
}

void sidtHook()
{
	EVASION("GENERIC SANDBOX CHECK", NULL, "idt_trick", "The process tried to check the Interupt Descriptor Table location");
}

void sldtHook()
{
	EVASION("GENERIC SANDBOX CHECK", NULL, "ldt_trick", "The process tried to check the Local Descriptor Table location");
}

void sgdtHook()
{
	EVASION("GENERIC SANDBOX CHECK", NULL, "gdt_trick", "The process tried to check the Global Descriptor Table location");
}

void strHook()
{
	EVASION("GENERIC SANDBOX CHECK", NULL, "str_trick", "The process tried to check the Store task register");
}

VOID int2e(CONTEXT* ctxt, ADDRINT eip) {
	EVASION("ANTIDBI", NULL, "Check_EIP", "Process tried to get EIP through Int 0x2e");
	PIN_SetContextReg(ctxt, REG_EDX, eip);
}

/*	When int2d is executed, without a debugger attached, an exception is triggered 
	with EXCEPTION_BREAKPOINT code. After that the execution is resumed at eip+1 or eip+2 (depends on EAX).
	If pin is attached, the exception is not handled by the program, so I have to trigger it manually!
	Unfortunatly, when I trigger manually the exception, eip is not incremented, so I trigger infinite exceptions.
	So I manually set EIP to start exactly where it should start after the exception (eip + 3)*/
VOID int2d(CONTEXT* ctxt, THREADID tid, ADDRINT eip)
{
	EVASION("ANTIDEBUG", NULL, "Interrupt_0x2d", "Process uses INT 0x2d to trigger an exception");
	EXCEPTION_INFO exc;
	PIN_SetContextReg(ctxt, REG_EIP, eip + 3);
	PIN_InitExceptionInfo(&exc, EXCEPTCODE_DBG_BREAKPOINT_TRAP, eip + 1);
	PIN_RaiseException(ctxt, tid, &exc);
}

/* ------------------  Other stuff ------------------ */

BOOL isAddressInsideRedZoneOrRedZoneHoneypot(ADDRINT ret) {
	if (honeypotProcess)
		return isInsideRedZoneHoneypot(ret);
	else 
		return HooksHandler::getInstance()->procInfo->isInsideRedZone(ret);
}

VOID pageGuardException(CONTEXT* ctxt, THREADID tid, ADDRINT eip) {
	EVASION("ANTIDEBUG", NULL, "MemoryBreakpoints_PageGuard", "A page guard is accessed by the program.");
	EXCEPTION_INFO exc;
	PIN_InitExceptionInfo(&exc, EXCEPTCODE_ACCESS_WINDOWS_GUARD_PAGE, eip);
	PIN_RaiseException(ctxt, tid, &exc);
}

/*	This function match if the cpuid(0x1) instruction is executed
	inside one of the MSVC compilers initial routine functions
	to avoid false positives
*/
BOOL isMsvcCpuid(unsigned char * toCheckBytes)
{
	/*
	for (int i = 0; i < 85; ++i)
		std::cerr << std::setfill('0') << std::setw(2) << std::hex << (int)toCheckBytes[i] << " ";
	std::cerr << std::endl;
	*/
	std::vector<unsigned char*> *constraints = new std::vector<unsigned char*>();
	unsigned char const2[4] = { 0x69, 0x6E, 0x65, 0x49 };
	unsigned char const3[4] = { 0x47, 0x65, 0x6E, 0x75 };
	constraints->push_back(const2);
	constraints->push_back(const3);

	void* found = toCheckBytes;
	for (auto it = constraints->begin(); it != constraints->end(); it++) {
		found = memmem(found, 85 * sizeof(char), *it, sizeof(*it));
		if (found == NULL)
			return false;
	}
	return true;
}


VOID WMIExecQueryHook(W::TCHAR** Query) {

	char value[MAX_QUERY_SIZE] = { 0 };
	GET_STR_TO_UPPER((char*)*Query, value, MAX_QUERY_SIZE);
	MYINFO("WMI-Query", "%s", value);

}
