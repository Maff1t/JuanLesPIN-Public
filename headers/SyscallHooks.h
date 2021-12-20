#pragma once
#include "pin.H"

#include <map>
#include <set>
#include <list>
#include <fstream>
#include <string> 
#include <sstream>

namespace W {
	#include <Windows.h>
	#include "WinBase.h"
	#include "minwindef.h"
	#include "libloaderapi.h"
	#include "processthreadsapi.h"
}
#include "Utils.h"
#include "ProcessInjection.h"

#define MAXPATH 100

#define SYSTEM_PROCESS_INFORMATION_TYPE 5
#define THREADHIDEFROMDEBUGGER 17

using std::string;
using std::map;
using std::multimap;
using std::set;
using std::pair;
using std::list;

//information on the syscall
typedef struct _syscall_t {
	ADDRINT syscall_number;
	union {
		ADDRINT args[16];
		struct {
			ADDRINT arg0, arg1, arg2, arg3;
			ADDRINT arg4, arg5, arg6, arg7;
		};
	};
} syscall_t;

typedef void (*syscall_hook)(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);

typedef int(NTAPI* pfnNtCreateThreadEx)
(
	OUT W::PHANDLE hThread,
	IN W::ACCESS_MASK DesiredAccess,
	IN W::PVOID ObjectAttributes,
	IN W::HANDLE ProcessHandle,
	IN W::PVOID lpStartAddress,
	IN W::PVOID lpParameter,
	IN W::ULONG Flags,
	IN W::SIZE_T StackZeroBits,
	IN W::SIZE_T SizeOfStackCommit,
	IN W::SIZE_T SizeOfStackReserve,
	OUT W::PVOID lpBytesBuffer
);

typedef struct _SYSTEM_PROCESS_INFO
{
	W::ULONG                   NextEntryOffset;
	W::ULONG                   NumberOfThreads;
	W::LARGE_INTEGER           Reserved[3];
	W::LARGE_INTEGER           CreateTime;
	W::LARGE_INTEGER           UserTime;
	W::LARGE_INTEGER           KernelTime;
	W::UNICODE_STRING          ImageName;
	W::ULONG                   BasePriority;
	W::HANDLE                  ProcessId;
	W::HANDLE                  InheritedFromProcessId;
} SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;




static map<wstring, const char *>regKeyArtifacts;
static multimap<string, string>keyNameValueMap;
static map<W::HANDLE, string> keyHandleStringMap;

static list<pair <wstring, const char *>>fileSystemArtifacts;

static map<string, syscall_hook> syscallsHooks;
static map<unsigned long, string> syscallsMap;

class SyscallHooks
{
public:
	static void enumSyscalls(map<string, syscall_hook> syscallsHooks); // Fill syscallMap with ("syscallName":syscallNumber)
	static void initHooks();	// Hook all interesting syscalls!

private:

	// Helper fuctions
	static void syscallEntry(THREADID thread_id, CONTEXT* ctx, SYSCALL_STANDARD std, void* v);
	static void syscallExit(THREADID thread_id, CONTEXT* ctx, SYSCALL_STANDARD std, void* v);
	static void syscallGetArguments(CONTEXT* ctx, SYSCALL_STANDARD std, int count, ...);

	/* General Hooks */
	static void NtQueryInformationProcessHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtQuerySystemInformationHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtSetInformationThreadHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtQueryObjectHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtDelayExecutionHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);


	/* Registry Key Monitor */
	static void NtOpenKeyHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtOpenKeyExHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtQueryValueKeyHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtCreateKeyHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtDeleteKeyHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtRenameKeyHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtSetValueKeyHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtSaveKeyHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);

	/* Mutex */
	static void NtCreateMutantHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtOpenMutantHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);

	
	/* FileSystem Monitor */
	static void NtOpenFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtCreateFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtReadFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtWriteFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtDeviceIoControlFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtQueryInformationFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtSetInformationFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtQueryAttributesFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtDeleteFileHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);

	/* Process Injection hooks */
	static void NtWriteVirtualMemoryHook (syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtCreateThreadExHook (syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtMapViewOfSectionHook(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtResumeThreadHook (syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	static void NtQueueApcThreadHook (syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
};