#pragma once
#include <map>
#include <set>

#include "ProcessInfo.h"
#include "ProcessInjection.h"
#include "Report.h"

namespace W
{
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include "winsock.h"
	#include "psapi.h"
	#include "winnt.h"
	#include "sysinfoapi.h"
	#include "windef.h"
	#include "winioctl.h"
	#include "IPTypes.h"
	#include <wbemcli.h>
	#include <OleAuto.h>
	#include "winsvc.h"
}


using std::map;
using std::set;
using std::pair;

extern KNOB<W::BOOL> honeypotProcess;

#define WMIOFFSETEXEC			0x1EBE0
VOID WMIExecQueryHook(W::TCHAR** Query);

/* Other stuffs */
#define TIME_ONESHOT 0x0000
#define RDTSC_DISTANCE 100
#define KUSER_SHARED_DATA 0x7FFE0000
#define KERNEL_DEBUGGER_OFFSET 0x2d4
#define RDTSC_AVG_VALUE 50 // Clock cycles between two different RDTSC instructions#define
#define MAX_QUERY_SIZE 0x300

#define myntohs16(x)							\
    (__uint16_t)(((__uint16_t)(x) & 0xff) << 8 | ((__uint16_t)(x) & 0xff00) >> 8)


/* Read Hooks */
enum readHooksId {
	NUMBEROFPROCESSORS,
	GETADAPTERSINFOMACADDRESS,
	GLOBALMEMORYSTATUSEXRAMCHECK,
	GETSYSTEMINFOPROCESSORCHECK,
	BEINGDEBUGGED,
	NTGLOBALFLAG,
	HEAPFLAGS,
	HEAPFORCEFLAGS,
	HARDWAREBREAKPOINTS,
	SHAREDUSERDATAKERNELDBG
};

/* Instruction Hooks */
enum instructioHooksId {
	RDTSC,
	CPUID,
	SIDT,
	SLDT,
	SGDT,
	STR,
	INTERRUPT,
	BREAKPOINT
};

/* Library Hooks */
VOID GetDiskFreeSpaceExW_After(UINT64* lpTotalNumberOfBytes, ADDRINT ret);
VOID GlobalMemoryStatusEx_After(W::LPMEMORYSTATUSEX lpBuffer, ADDRINT ret);
VOID GetCursorPos_After( W::LPPOINT lpPoint, ADDRINT ret);
VOID SetupDiGetDeviceRegistryPropertyW_After(W::PBYTE buffer, ADDRINT ret);
VOID DeviceIoControl_After(W::DWORD dwloControlCode, W::LPVOID lpOutBuffer, ADDRINT ret);
VOID GetAdaptersInfo_After(W::PIP_ADAPTER_INFO AdapterInfo, ADDRINT ret);
VOID EnumServicesStatusExW_After(int InfoLevel, ADDRINT ret);
VOID GetSystemInfo_After (W::LPSYSTEM_INFO lpSystemInfo, ADDRINT ret);
VOID OpenProcess_Before (W::PDWORD dwProcessId, ADDRINT ret);
VOID OpenProcess_After(W::PHANDLE returnValue, W::PDWORD pid, ADDRINT ret);
VOID GetModuleHandle_Before (W::LPCWSTR lpModuleName , ADDRINT ret);
VOID IsDebuggerPresent_After(ADDRINT ret);
VOID CheckRemoteDebuggerPresent_After(ADDRINT ret);
VOID GetThreadContext_After(W::PCONTEXT pctx, ADDRINT ret);
VOID VirtualAlloc_Before(W::PDWORD pflProtectionType, ADDRINT ret);
VOID VirtualAlloc_After(W::LPVOID lpAddress, W::SIZE_T dwSize, W::DWORD flProtect, ADDRINT ret);
VOID VirtualProtect_After(W::LPVOID lpAddress, W::SIZE_T dwSize, W::DWORD flNewProtect, ADDRINT ret);
VOID VirtualQuery_After(W::LPVOID lpAddress, W::PMEMORY_BASIC_INFORMATION lpBuffer, ADDRINT ret);
VOID CreateFile_After(W::LPCWSTR lpFileName, ADDRINT ret);
VOID GetSystemFirmwareTable_After(CONTEXT* ctxt, W::DWORD FirmwareTableProviderSignature, W::PVOID pFirmwareTableBuffer, W::DWORD bufferSize, ADDRINT ret);
VOID GetTickCount_After(CONTEXT * ctxt, ADDRINT ret);
VOID TimeSetEvent_Before(W::PUINT puDelay, W::UINT fuEvent, ADDRINT ret);
VOID WaitForSingleObject_Before(W::PDWORD pDelayInMillis, ADDRINT ret);
VOID Process32Next_Before(W::LPPROCESSENTRY32 lppe, ADDRINT ret);
VOID NtQueryInformationProcess_Before(W::PROCESSINFOCLASS ProcessInformationClass, W::PVOID ProcessInformation, ADDRINT ret);
VOID NtQuerySystemInformation_Before(W::SYSTEM_INFORMATION_CLASS SystemInformationClass, ADDRINT ret);
VOID WMIQueryHookExit(W::LPCWSTR* query, W::VARIANT** var);


/* Behavioural hooks */
VOID PIN_FAST_ANALYSIS_CALL in_first_pcstr(uint32_t hooksId, ADDRINT ip, W::PCSTR pszName);
VOID PIN_FAST_ANALYSIS_CALL in_first_pcwstr(uint32_t hooksId, ADDRINT ip, W::PCWSTR pszName);

VOID PIN_FAST_ANALYSIS_CALL log_connect(uint32_t hooksId, ADDRINT ip, W::sockaddr_in* sockin);

VOID PIN_FAST_ANALYSIS_CALL networkApiReport(ADDRINT ip);
VOID PIN_FAST_ANALYSIS_CALL processApiReport(ADDRINT ip);
VOID PIN_FAST_ANALYSIS_CALL process_out_first(ADDRINT ip, W::PHANDLE processHandle);
VOID PIN_FAST_ANALYSIS_CALL threadApiReport(ADDRINT ip);
VOID PIN_FAST_ANALYSIS_CALL fileSystemApiReport(ADDRINT ip);
VOID PIN_FAST_ANALYSIS_CALL registryApiReport(ADDRINT ip);
//VOID PIN_FAST_ANALYSIS_CALL serviceApiReport(ADDRINT ip);
VOID PIN_FAST_ANALYSIS_CALL serviceApiReport(W::SC_HANDLE sc_handle_arg, ADDRINT ip);


// FileSystem behaviour
VOID CreateFileAHook(W::LPCSTR lpFileName, ADDRINT ret);
VOID DeleteFileAHook(W::LPCSTR lpFileName, ADDRINT ret);
VOID DeleteFileWHook(W::LPCWSTR lpFileName, ADDRINT ret);

// Service behaviour
VOID OpenServiceAHook(W::LPSC_HANDLE, W::LPCSTR lpServiceName, ADDRINT ret);
VOID OpenServiceWHook(W::LPSC_HANDLE, W::LPCWSTR lpServiceName, ADDRINT ret);
VOID CreateServiceAHook(W::LPSC_HANDLE, W::LPCSTR lpServiceName, ADDRINT ret);
VOID CreateServiceWHook(W::LPSC_HANDLE, W::LPCWSTR lpServiceName, ADDRINT ret);


/* Instruction Hooks */
VOID rdtscHook(CONTEXT* ctxt);
VOID cpuidHookBefore(CONTEXT* ctxt, int* value);
VOID cpuidHookAfter(CONTEXT* ctxt, int * value);
VOID sidtHook();
VOID sldtHook();
VOID sgdtHook();
VOID strHook();
VOID int2e(CONTEXT *ctxt, ADDRINT eip);
VOID int2d(CONTEXT *ctxt, THREADID tid, ADDRINT eip);

BOOL isAddressInsideRedZoneOrRedZoneHoneypot(ADDRINT ret); // check if ret address is in a "monitored" piece of memory
VOID pageGuardException(CONTEXT* ctxt, THREADID tid, ADDRINT eip); // This throw STATUS_GUARD_PAGE_VIOLATION if a PAGE GUARD is accessed
BOOL isMsvcCpuid(unsigned char * toCheckBytes); // Check if cpuid(0x1) is a false positive

typedef W::DWORD (*_CsrGetProcessId)();

static map <wstring, const char *> deviceArtifacts;
static W::DWORD csrssId;
static bool isCsrss;
extern uint64_t lastRdtsc;
extern W::ULONGLONG lastRdtscInstr;
extern W::ULONGLONG numberOfExecutedInstructionsProgram;
extern uint32_t process32NextCounter;
extern W::PULONG sizeOfImageAddress;

/*	Counters: Some evasive logs are too much verbose if logged each time.
	I prefer to log the number of times that is triggered
	at the end of the malware execution
*/
extern uint32_t rdtscCounter;
extern uint32_t getTickCountCounter;

class HooksHandler
{
public:
	static HooksHandler* getInstance();
	HooksHandler(ProcessInfo * procInfo);
	~HooksHandler();
	VOID readHooksHandler(ADDRINT read_address); // Called each time an instruction read the memory
	VOID writeHooksHandler(ADDRINT read_address, ADDRINT oldByte); // Called each time an instruction write in memory
	VOID addReadWriteHook(ADDRINT address, readHooksId caseNumber, size_t numberOfAddresses);
	VOID removeReadWriteHooks(ADDRINT address);
	VOID hookApiInThisLibrary(IMG img); // Called each time a new IMG is loaded
	VOID instructionHooksHandler(INS ins); // Called each time an instruction read in memory

	ProcessInfo* procInfo;

private:
	static HooksHandler* instance;
	map <string, libraryHooksId> libraryHooks;
	map <ADDRINT, readHooksId> readHooks;
	map <ADDRINT, size_t> writeHooks;
	map <string, int> instructionHooks;
	// Arg logging
	set<string> set_process_out_first;
	set<string> set_in_pcstr;
	set<string> set_in_pcwstr;
};

/*
class WAPIfunction
{
	public:
		libraryHooksId category;
		string dll;
		string name;
		int nOfArgs;

		WAPIfunction(libraryHooksId c, string d, string n, int nOf) {
			category = c;
			dll = d;
			name = n;
			nOfArgs = nOf;
		};

};
*/