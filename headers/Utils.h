#pragma once
#include "pin.H"
#include "ProcessInfo.h"
#include "Report.h"
#include <iostream>
#include <ctime>
#include <vector>
#include "TCHAR.h"
#include <sstream>
#include <sys/stat.h>

namespace W {
#include "Wincrypt.h"
#include <windows.h>
}

const std::string DLL_FOLDER = "C:\\pin\\source\\tools\\JuanLesPIN-Public\\Release\\";
const std::string JLP_DLL_PATH = DLL_FOLDER + "JuanLesPIN.dll";
const std::string HON_DLL_PATH = DLL_FOLDER + "Honeypot.exe";


#define SSTR( x ) static_cast< std::ostringstream & >( \
        ( std::ostringstream() << std::dec << x ) ).str()

using std::vector;

#define DELAY_MINIMUM_VALUE 60000 // Threshold in ms for timing attacks


#define EVASION(type, subtype, title, description) Report::getInstance()->jsonEvasionReport(type, subtype, title, description)
#define BEHAVIOURREPORT(type, detail) Report::getInstance()->jsonBehaviourReport(type, detail)
#define BEHAVIOURREPORTARG(type, detail, arg) Report::getInstance()->jsonBehaviourReportWithArg(type, detail, arg)
#define BEHAVIOURREPORIDARG(type, detail, arg) Report::getInstance()->jsonBehaviourReportHooksIdWithArg(type, detail, arg)
#define BEHAVIOURREPORREGKEYHANDLE(symbol, kHandle) Report::getInstance()->jsonBehaviourReportRegistryKeyHandle(symbol, kHandle)
#define BEHAVIOURREPORTFILEHANDLE(symbol, fileHandle) Report::getInstance()->jsonBehaviourReportFileSystemHandle(symbol, fileHandle)
#define MYERROR(fmt, ...) Report::getInstance()->jsonErrorReport (fmt, __VA_ARGS__)
#define MYINFO(title, fmt, ...) Report::getInstance()->jsonInfoReport (title, fmt, __VA_ARGS__)

/*  Calculate the address of the base of the structure given its type, and an
    address of a field within the structure. (al-khaser)*/
#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (W::PCHAR)(address) - \
                                                  (W::ULONG_PTR)(&((type *)0)->field)))

/* From bluepill */
#define GET_STR_TO_UPPER(c, buf, bufSize)	do { \
			size_t i; \
			for (i = 0; i < bufSize; i++) { \
				(buf)[i] = toupper((c)[i]); \
				if ((c)[i] == '\0') break; \
			} \
} while (0)

namespace W {
#include "Windows.h"
#include "winternl.h"
#include "minwindef.h"
#include "tlhelp32.h"
#include "handleapi.h"
#include "shlwapi.h"
#include "psapi.h"
}

#pragma warning(disable: 4996) // wcsnicmp deprecated

// This makro assures that INVALID_HANDLE_VALUE (0xFFFFFFFF) returns FALSE
#define IsConsoleHandle(h) (((((unsigned long)h) & 0x10000003) == 0x3) ? TRUE : FALSE)
#define INVALID_HANDLE_VALUE ((W::HANDLE)(long)-1)


/*
enum OBJECT_INFORMATION_CLASS
{
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllInformation,
    ObjectDataInformation
};*/

typedef enum Complete_OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} Complete_OBJECT_INFORMATION_CLASS, * Complete_POBJECT_INFORMATION_CLASS;

struct OBJECT_NAME_INFORMATION
{
    W::UNICODE_STRING Name; // defined in winternl.h
    W::WCHAR NameBuffer;
};

typedef W::NTSTATUS (NTAPI* t_NtQueryObject)           (W::HANDLE Handle, Complete_OBJECT_INFORMATION_CLASS Info, W::PVOID Buffer, W::ULONG BufferSize, W::PULONG ReturnLength);
typedef int      (WINAPI* ZwQueryInformationProcess)(W::HANDLE, W::DWORD, W::PROCESS_BASIC_INFORMATION*, W::DWORD, W::DWORD*);

typedef struct Complete_PROCESS_BASIC_INFORMATION {
	W::PVOID Reserved1;
	W::PVOID PebBaseAddress;
	W::PVOID Reserved2[2];
	W::ULONG_PTR UniqueProcessId;
	W::ULONG_PTR ParentProcessId;
} Complete_PROCESS_BASIC_INFORMATION;

#define PROCESSDEBUGFLAGS 0x1F
#define PROCESSDEBUGPORT 0x7
#define PROCESSDEBUGOBJECT 0x1e
#define PROCESSBASICINFORMATION 0x0
#define SYSTEM_KERNEL_DEBUGGER_INFORMATION 0x23
#define CMDLINESIZE 600

// Config for mitigation
#define CPUID_1_MITIGATION true
#define NUMBEROFPROCESSOR_MITIGATION true
#define GETTICKCOUNT_MITIGATION true
#define MOUSEMOVEMENT_MITIGATION true

#define PROCDUMPBINARY "C:\\Procdump\\procdump.exe"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((long)0x00000000L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((long)0xC0000023L)
#endif

extern uint32_t sleepTime;
extern int sleepCounter;


std::wstring GetKeyPathFromKKEY(W::HKEY key);
Complete_PEB* FindPEBAddress(W::HANDLE hProcecss);
INT32 Usage();
string trim(const string& str);
W::DWORD GetProcessIdFromName(W::LPCTSTR szProcessName);
set<W::DWORD> GetProcessIdsFromName(W::LPCTSTR szProcessName);
std::string ProcessIdToName(W::DWORD processId);
W::LPCTSTR ErrorMessage(W::DWORD error);
wchar_t* getWStrFromPUnicodeString(W::PUNICODE_STRING pUnicodeString);
wchar_t* getWStrFromObjectAttribute(W::POBJECT_ATTRIBUTES pObjAttribute);
string getTimestamp();
string getUnixTimestamp();
string getUnixNanoTimestamp();
bool isSuspectedModule(W::LPVOID address, W::MEMORY_BASIC_INFORMATION mbi);
void* memmem(const void* haystack_start, size_t haystack_len, const void* needle_start, size_t needle_len);
void procDump(string filename);
std::string getDllName(const std::string& str);
std::string GetLastErrorAsString(W::LPTSTR lpszFunction);
//std::string ToNarrow(const wchar_t* s, char dfault = '?', const std::locale& loc = std::locale());
uint16_t our_htons(uint16_t value);
const char* our_inet_ntoa(W::in_addr ipaddr);
std::string GetNtPathFromHandle(W::HANDLE handle);
bool file_exists(const std::string& name);