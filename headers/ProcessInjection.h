#pragma once
#include "pin.H"

#include <map>
#include <set>
#include <vector>
#include <iostream>
#include <sstream>
#include <string>

#include "Utils.h"
#include "ProcessInfo.h"


#define MSGLEN 50
#define MAXDLLPATHLENGHT 500
#define PADDINGLETTER "#"

namespace W {
	#include "Windows.h"
	#include "processthreadsapi.h"
	#include "minwindef.h"
	#include "WinBase.h"
	#include "psapi.h"
}

using std::map;
using std::set;
using std::vector;
using std::pair;
using std::wstring;
using std::string;

typedef int (WINAPI* _NtUnmapViewOfSection)(W::HANDLE ProcessHandle, W::PVOID BaseAddress );

typedef struct
{
	W::OVERLAPPED oOverlap;
	W::HANDLE hPipeInst;
} PIPEINST, * LPPIPEINST;

extern W::HANDLE hHoneypot;
extern W::DWORD honeypotPID;
extern Complete_PEB* pPEB;
extern set <W::PVOID> remoteWrittenAddresses;
extern set <W::DWORD> hookedPID;
extern PIPEINST namedPipe;
extern char* waitBuffer;
extern set <pair <ADDRINT, size_t>> honeypotRedZone; // startAddress, size!
extern set <string> injectedDLL;

/* ---- HoneyPot Process functions! ---- */

bool initHoneypotProcess(string reportFileName, W::DWORD parentPid);
void terminateHoneypotProcess();
bool findHoneypotProcess();

/* ---- IPC With Named Pipe ASYNC ---- */

bool initNamedPipeServer(W::DWORD parentPid);
bool initNamedPipeClient(string namedPipeName);
void sendMessageToPipe(string label, string content);
void fetchMessageFromPipe();
void parseMessage(string message);

/* Utils for injected process */

void addToHoneypotRedZone(ADDRINT startAddress, size_t size);
bool isInsideRedZoneHoneypot(ADDRINT address);

void addToInjectedDLL(string dllName);
bool isInInjectedDLL(string dllName);
bool hookLoadedDll(string dllPathString); // If the DLL is already loaded, hook it!
int isLoadLibraryAddress(ADDRINT address); // Check if an address corresponds to the one of kernel32.LoadLibrary!




