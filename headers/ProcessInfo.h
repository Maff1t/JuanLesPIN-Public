#pragma once

#include "pin.H"
#include <vector>
#include <set>

using std::string;
using std::vector;
using std::pair;
using std::set;

namespace W {
    #include "winsock2.h"
    #include "ws2tcpip.h"
    #include "winsock.h"
    #include "Windows.h"
    #include "winternl.h"
    #include "minwindef.h"
    #include "WinBase.h"
}

struct Section {
    ADDRINT begin;
    ADDRINT end;
    string name;
    Section();
	Section (ADDRINT b, ADDRINT e, string n)
	{
        begin = b;
        end = e;
        name = n;
	}
};

typedef struct _PEB_LDR_DATA {
    W::BYTE Reserved1[8];
    W::PVOID Reserved2[3];
    W::LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    W::PVOID Reserved1[2];
    W::LIST_ENTRY InMemoryOrderLinks;
    W::PVOID Reserved2[2];
    W::PVOID DllBase;
    W::PVOID Reserved3[2];
    W::UNICODE_STRING FullDllName;
    W::BYTE Reserved4[8];
    W::PVOID Reserved5[3];
    union {
        W::ULONG CheckSum;
        W::PVOID Reserved6;
    } DUMMYUNIONNAME;
    W::ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

struct Complete_PEB {
    W::BYTE InheritedAddressSpace;
    W::BYTE ReadImageFileExecOptions;
    W::BYTE BeingDebugged;
    W::BYTE SpareBool;
    void* Mutant;
    void* ImageBaseAddress;
    _PEB_LDR_DATA* Ldr;
    W::_RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    void* SubSystemData;
    void* ProcessHeap;
    W::_RTL_CRITICAL_SECTION* FastPebLock;
    void* FastPebLockRoutine;
    void* FastPebUnlockRoutine;
    W::DWORD EnvironmentUpdateCount;
    void* KernelCallbackTable;
    W::DWORD SystemReserved[1];
    W::DWORD ExecuteOptions : 2; // bit offset: 34, len=2
    W::DWORD SpareBits : 30; // bit offset: 34, len=30
    W::BYTE FreeList[4];
    W::DWORD TlsExpansionCounter;
    void* TlsBitmap;
    W::DWORD TlsBitmapBits[2];
    void* ReadOnlySharedMemoryBase;
    void* ReadOnlySharedMemoryHeap;
    void** ReadOnlyStaticServerData;
    void* AnsiCodePageData;
    void* OemCodePageData;
    void* UnicodeCaseTableData;
    W::DWORD NumberOfProcessors;
    W::DWORD NtGlobalFlag;
    W::_LARGE_INTEGER CriticalSectionTimeout;
    W::DWORD HeapSegmentReserve;
    W::DWORD HeapSegmentCommit;
    W::DWORD HeapDeCommitTotalFreeThreshold;
    W::DWORD HeapDeCommitFreeBlockThreshold;
    W::DWORD NumberOfHeaps;
    W::DWORD MaximumNumberOfHeaps;
    void** ProcessHeaps;
    void* GdiSharedHandleTable;
    void* ProcessStarterHelper;
    W::DWORD GdiDCAttributeList;
    void* LoaderLock;
    W::DWORD OSMajorVersion;
    W::DWORD OSMinorVersion;
    W::WORD OSBuildNumber;
    W::WORD OSCSDVersion;
    W::DWORD OSPlatformId;
    W::DWORD ImageSubsystem;
    W::DWORD ImageSubsystemMajorVersion;
    W::DWORD ImageSubsystemMinorVersion;
    W::DWORD ImageProcessAffinityMask;
    W::DWORD GdiHandleBuffer[34];
    void (*PostProcessInitRoutine)();
    void* TlsExpansionBitmap;
    W::DWORD TlsExpansionBitmapBits[32];
    W::DWORD SessionId;
    W::_ULARGE_INTEGER AppCompatFlags;
    W::_ULARGE_INTEGER AppCompatFlagsUser;
    void* pShimData;
    void* AppCompatInfo;
    W::_UNICODE_STRING CSDVersion;
    void* ActivationContextData;
    void* ProcessAssemblyStorageMap;
    void* SystemDefaultActivationContextData;
    void* SystemAssemblyStorageMap;
    W::DWORD MinimumStackCommit;
};

extern W::PULONG sizeOfImageAddress; // I prefer to have it here for performance

class ProcessInfo
{
public:
	ProcessInfo(IMG img);
	~ProcessInfo();

    /* Getters & setters*/
    VOID set_peb(Complete_PEB* peb);
    Complete_PEB* get_peb();
	
    /* Utils */
    double getEntropy();
    VOID insertSection(Section s);
    BOOL isInsideRedZone(ADDRINT ip);
    VOID insertAllocatedMemory(W::LPVOID startAddress, W::DWORD size);
    VOID insertSuspectedDll(W::LPVOID startAddress, W::DWORD size);
    VOID insertGuardPage(W::LPVOID startAddress, W::DWORD size);
    BOOL isInsideAllocatedMemory(ADDRINT ip);
    BOOL isInsideSuspectDLL(ADDRINT ip);
    BOOL isInsideGuardPage(ADDRINT ip);

    void dumpRedZoneMemory(string filename);
	/* Maybe one day*/
    //string getSectionNameByIp(ADDRINT ip);
    //void PrintSections();
    
    ADDRINT baseAddress;
    ADDRINT end;

private:
    IMG img;
	Complete_PEB* peb;
    vector<Section> sections;
    set<pair<W::LPVOID, W::SIZE_T>> allocatedMemory; // From VirtualAlloc()
    set<pair<W::LPVOID, W::SIZE_T>> suspectDll;
    set<pair<W::LPVOID, W::SIZE_T>> guardPages; // From VirtualAlloc()
};

