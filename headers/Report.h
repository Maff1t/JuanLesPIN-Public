#pragma once

#include <iostream>
#include <fstream>
#include <cstdarg>
#include <unordered_set> 

#include <ProcessInfo.h>
#include <Utils.h>

namespace W {
	#include <Windows.h>
	#include "WinBase.h"
	#include "minwindef.h"
	#include "libloaderapi.h"
}

using std::set;


/* Library Hooks */
enum libraryHooksId {
	GETDISKFREESPACEEX,
	GLOBALMEMORYSTATUSEX,
	GETCURSORPOS,
	SETUPDIGETDEVICEREGISTRYPROPERTYW,
	DEVICEIOCONTROL,
	GETADAPTERSINFO,
	ENUMSERVICESSTATUSEXW,
	GETSYSTEMINFO,
	OPENPROCESS,
	GETMODULEHANDLE,
	ISDEBUGGERPRESENT,
	CHECKREMOTEDEBUGGERPRESENT,
	GETTHREADCONTEXT,
	VIRTUALALLOC,
	VIRTUALPROTECT,
	VIRTUALQUERY,
	CREATEFILE,
	GETSYSTEMFIRMWARETABLE,
	GETTICKCOUNT,
	TIMESETEVENT,
	WAITFORSINGLEOBJECT,
	PROCESS32NEXT,
	NTQUERYINFOPROCESS,
	NTQUERYSYSINFO,
	WMI,
	NETWORKBEHAVIOUR,
	THREADBEHAVIOUR,
	FSBEHAVIOUR,
	PROCESSBEHAVIOUR,
	REGISTRYBEHAVIOUR,
	SERVICEBEHAVIOUR
};

enum EvasionType {
	AntiDebug,
	AntiVM,
	AntiSandbox,
	TimingAttack,
	CodeInjection
};

#define MAX_DBG_MSG 300

// If the program waits more than 30 seconds, report timing attack!
#define TIMING_ATTACK_THRESHOLD 30000 

using std::string;

class Report {
public:
	Report(string filename, bool isHoneypot, bool knobInsAddrTracing);
	~Report();
	static Report* getInstance();

	string jsonAddField(string key, string data);
	void jsonEvasionReport(const char* type, const char* subtype, const char* title, const char* description);
	void jsonBehaviourReport(const char* type, const char* funcName);
	void jsonBehaviourReportWithArg(const char* type, const char* funcName, const char* arg);
	void jsonBehaviourReportHooksIdWithArg(uint32_t libHookid, const char* funcName, const char* arg);
	void jsonBehaviourReportRegistryKeyHandle(const char* funcName, W::HKEY keyHandle);
	void jsonBehaviourReportFileSystemHandle(const char* funcName, W::HANDLE handle);

	void jsonInfoReport(const char* title, const char* fmt, ...);
	void jsonErrorReport(const char* fmt, ...);
	void bblReport(ADDRINT bblAddress);
	
private:
	bool isHoneypot;
	bool skippingInstructions;
	static Report* instance;
	std::ofstream* outputFile;
	std::ofstream* bblOutFile; // To log BBL addresses
	std::set<ADDRINT> executedInstructions;
};
