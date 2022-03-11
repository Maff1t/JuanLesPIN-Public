#include "Utils.h"

#include <iostream>
#include "winerror.h"
#include <string>




#define HKCU_PREFIX  L"\\REGISTRY\\USER\\S-1-5-"
#define HKCU_PREFIX2 L"HKEY_USERS\\S-1-5-"
#define HKLM_PREFIX  L"\\REGISTRY\\MACHINE"

uint32_t sleepTime = 0;
int sleepCounter = 0;

/*
static uint32_t _reg_root_handle(W::HANDLE key_handle, wchar_t* regkey)
{
	const wchar_t* key = NULL;
	switch ((uintptr_t)key_handle) {
	case (uintptr_t)HKEY_CLASSES_ROOT:
		key = L"HKEY_CLASSES_ROOT";
		break;

	case (uintptr_t)HKEY_CURRENT_USER:
		key = L"HKEY_CURRENT_USER";
		break;

	case (uintptr_t)HKEY_LOCAL_MACHINE:
		key = L"HKEY_LOCAL_MACHINE";
		break;

	case (uintptr_t)HKEY_USERS:
		key = L"HKEY_USERS";
		break;

	case (uintptr_t)HKEY_PERFORMANCE_DATA:
		key = L"HKEY_PERFORMANCE_DATA";
		break;

	case (uintptr_t)HKEY_CURRENT_CONFIG:
		key = L"HKEY_CURRENT_CONFIG";
		break;

	case (uintptr_t)HKEY_DYN_DATA:
		key = L"HKEY_DYN_DATA";
		break;
	}

	if (key != NULL) {
		uint32_t length = lstrlenW(key);
		memmove(regkey, key, length * sizeof(wchar_t));
		return length;
	}
	return 0;
}


static uint32_t _reg_key_normalize(wchar_t* regkey)
{
	uint32_t length = 0;
	
	// TODO Add support for handling null-bytes in registry keys.
	for (wchar_t* in = regkey, *out = regkey; *in != 0;
		in++, out++, length++) {
		// Ignore superfluous backslashes.
		while (*in == '\\' && in[1] == '\\') {
			in++;
		}

		*out = *in;
	}

	regkey[length] = 0;

	// \\REGISTRY\\USER\\S-1-5-<SID of user> is just another way of writing
	// HKEY_CURRENT_USER, so we normalize it.
	if (W::_wcsnicmp(regkey, HKCU_PREFIX, lstrlenW(HKCU_PREFIX)) == 0) {
		const wchar_t* subkey = wcschr(regkey + lstrlenW(HKCU_PREFIX), '\\');
		uint32_t offset = _reg_root_handle(HKEY_CURRENT_USER, regkey);

		// Shouldn't be a null pointer but let's just make sure.
		if (subkey != NULL && length != 0) {
			// Subtract the part of the key from the length that
			// we're skipping.
			length -= subkey - regkey;

			memmove(&regkey[offset], subkey, length * sizeof(wchar_t));
			regkey[offset + length] = 0;
			return offset + length;
		}

		regkey[offset] = 0;
		return offset;
	}

	// HKEY_USERS\\S-1-5-<SID of user> is just another way of writing
	// HKEY_CURRENT_USER, so we normalize it.
	if (W::_wcsnicmp(regkey, HKCU_PREFIX2, lstrlenW(HKCU_PREFIX2)) == 0) {
		const wchar_t* subkey = wcschr(regkey + lstrlenW(HKCU_PREFIX2), '\\');
		uint32_t offset = _reg_root_handle(HKEY_CURRENT_USER, regkey);

		// Shouldn't be a null pointer but let's just make sure.
		if (subkey != NULL && length != 0) {
			// Subtract the part of the key from the length that
			// we're skipping.
			length -= subkey - regkey;

			memmove(&regkey[offset], subkey, length * sizeof(wchar_t));
			regkey[offset + length] = 0;
			return offset + length;
		}

		regkey[offset] = 0;
		return offset;
	}

	// HKEY_LOCAL_MACHINE might be expanded into \\REGISTRY\\MACHINE - we
	// normalize this as well.
	if (W::_wcsnicmp(regkey, HKLM_PREFIX, lstrlenW(HKLM_PREFIX)) == 0) {
		const wchar_t* subkey = &regkey[lstrlenW(HKLM_PREFIX)];

		// Subtract the part of the key from the length that
		// we're skipping.
		length -= lstrlenW(HKLM_PREFIX);

		// Because "HKEY_LOCAL_MACHINE" is actually a longer string than
		// "\\REGISTRY\\MACHINE" we first move the subkey and only then
		// write the HKEY_LOCAL_MACHINE prefix.
		memmove(regkey + lstrlenW(L"HKEY_LOCAL_MACHINE"),
			subkey, length * sizeof(wchar_t));

		// The HKEY_LOCAL_MACHINE prefix.
		length += _reg_root_handle(HKEY_LOCAL_MACHINE, regkey);

		regkey[length] = 0;
		return length;
	}
	return lstrlenW(regkey);
}
*/

t_NtQueryObject NtQueryObject()
{
	static t_NtQueryObject f_NtQueryObject = NULL;
	if (!f_NtQueryObject)
	{
		W::HMODULE h_NtDll = W::GetModuleHandle("Ntdll.dll"); // Ntdll is loaded into EVERY process!
		f_NtQueryObject = (t_NtQueryObject)GetProcAddress(h_NtDll, "NtQueryObject");
	}
	return f_NtQueryObject;
}

std::string GetNtPathFromHandle(W::HANDLE h_File)
{
	if (h_File == 0 || h_File == INVALID_HANDLE_VALUE)
		return std::string();
	if (IsConsoleHandle(h_File))
	{
		char buff[MAX_PATH];
		snprintf(buff, sizeof(buff), "\\Device\\Console%04X", (W::DWORD)(W::DWORD_PTR)h_File);
		return std::string(buff);
	}
	W::BYTE  u8_Buffer[2000];
	W::DWORD u32_ReqLength = 0;
	W::UNICODE_STRING* pk_Info = &((OBJECT_NAME_INFORMATION*)u8_Buffer)->Name;
	pk_Info->Buffer = 0;
	pk_Info->Length = 0;
	NtQueryObject()(h_File, ObjectNameInformation, u8_Buffer, sizeof(u8_Buffer), &u32_ReqLength);
	if (!pk_Info->Buffer || !pk_Info->Length) // On error pk_Info->Buffer is NULL
		return std::string();
	pk_Info->Buffer[pk_Info->Length / 2] = 0; // Length in Bytes!

	//*ps_NTPath = pk_Info->Buffer;

	std::wstring ws(pk_Info->Buffer);
	std::string keyVal(ws.begin(), ws.end());

	return keyVal;
}



std::wstring GetKeyPathFromKKEY(W::HKEY key)
{
	std::wstring keyPath;
	if (key != NULL) {
		W::LPCSTR dllName = "ntdll.dll";
		W::HMODULE dll = W::LoadLibrary(dllName);
		if (dll != NULL) {
			typedef W::DWORD(__stdcall* NtQueryKeyType)(
				W::HANDLE  KeyHandle,
				int KeyInformationClass,
				W::PVOID  KeyInformation,
				W::ULONG  Length,
				W::PULONG  ResultLength);
			NtQueryKeyType func = reinterpret_cast<NtQueryKeyType>(W::GetProcAddress(dll, "NtQueryKey"));
			if (func != NULL) {
				W::DWORD size = 0;
				W::DWORD result = 0;
				result = func(key, 3, 0, 0, &size);
				if (result == STATUS_BUFFER_TOO_SMALL)
				{
					size = size + 2;
					wchar_t* buffer = new wchar_t[size / sizeof(wchar_t)]; // size is in bytes
					if (buffer != NULL)
					{
						result = func(key, 3, buffer, size, &size);
						if (result == STATUS_SUCCESS)
						{
							buffer[size / sizeof(wchar_t)] = L'\0';
							keyPath = std::wstring(buffer + 2);
						}

						delete[] buffer;
					}
				}
			}
			FreeLibrary(dll);
		}
	}
	return keyPath;
}


Complete_PEB* FindPEBAddress(W::HANDLE hProcess) {
	Complete_PEB* peb;
	__asm {
		mov eax, fs:30h
		mov peb, eax
	}
    return peb;
}

INT32 Usage()
{
	std::cerr << "This tool prints out the number of dynamically executed " << std::endl <<
        "instructions, basic blocks and threads in the application." << std::endl << std::endl;

	std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;

    return -1;
}

string trim(const string& str)
{
    size_t first = str.find_first_not_of(' ');
    if (string::npos == first)
    {
        return str;
    }
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

W::DWORD GetProcessIdFromName(W::LPCTSTR szProcessName)
{
	W::PROCESSENTRY32 pe32;
	W::HANDLE hSnapshot = NULL;
	memset(&pe32, 0, sizeof(W::PROCESSENTRY32));

	// We want a snapshot of processes
	hSnapshot = W::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	// Now we can enumerate the running process, also 
	// we can't forget to set the PROCESSENTRY32.dwSize member
	// otherwise the following functions will fail
	pe32.dwSize = sizeof(W::PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32) == FALSE)
	{
		
		W::CloseHandle(hSnapshot);
		ERROR("Unable to find Id of process %s", szProcessName);
		return 0;
	}

	// Do our first comparison
	if (W::StrCmpI(pe32.szExeFile, szProcessName) == 0)
	{
		// Cleanup the mess
		W::CloseHandle(hSnapshot);
		return pe32.th32ProcessID;
	}

	// Most likely it won't match on the first try so 
	// we loop through the rest of the entries until
	// we find the matching entry or not one at all
	while (Process32Next(hSnapshot, &pe32))
	{
		if (W::StrCmpI(pe32.szExeFile, szProcessName) == 0)
		{
			// Cleanup the mess
			W::CloseHandle(hSnapshot);
			return pe32.th32ProcessID;
		}
	}

	// If we made it this far there wasn't a match, so we'll return 0
	// _tprintf(_T("\n-> Process %s is not running on this system ..."), szProcessName);

	W::CloseHandle(hSnapshot);
	ERROR("Unable to find Id of process %s", szProcessName);
	return 0;
}

set<W::DWORD> GetProcessIdsFromName(W::LPCTSTR szProcessName)
{
	W::PROCESSENTRY32 pe32;
	W::HANDLE hSnapshot = NULL;
	set<W::DWORD> setOfPids;
	memset(&pe32, 0, sizeof(W::PROCESSENTRY32));

	// We want a snapshot of processes
	hSnapshot = W::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	// Now we can enumerate the running process, also 
	// we can't forget to set the PROCESSENTRY32.dwSize member
	// otherwise the following functions will fail
	pe32.dwSize = sizeof(W::PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32) == FALSE)
	{

		W::CloseHandle(hSnapshot);
		ERROR("Unable to find Id of process %s", szProcessName);
		return setOfPids;
	}

	// Do our first comparison
	if (W::StrCmpI(pe32.szExeFile, szProcessName) == 0)
	{
		setOfPids.insert(pe32.th32ProcessID);
	}

	// Most likely it won't match on the first try so 
	// we loop through the rest of the entries until
	// we find the matching entry or not one at all
	while (Process32Next(hSnapshot, &pe32))
	{
		if (W::StrCmpI(pe32.szExeFile, szProcessName) == 0)
		{
			// Cleanup the mess
			W::CloseHandle(hSnapshot);
			setOfPids.insert(pe32.th32ProcessID);
		}
	}

	// If we made it this far there wasn't a match, so we'll return 0
	// _tprintf(_T("\n-> Process %s is not running on this system ..."), szProcessName);

	W::CloseHandle(hSnapshot);
	return setOfPids;
}

std::string ProcessIdToName(W::DWORD processId)
{
	std::string ret;
	W::HANDLE handle = W::OpenProcess(
		PROCESS_QUERY_LIMITED_INFORMATION,
		FALSE,
		processId /* This is the PID, you can find one from windows task manager */
	);
	if (handle)
	{
		W::DWORD buffSize = 1024;
		CHAR buffer[1024];
		if (W::QueryFullProcessImageNameA(handle, 0, buffer, &buffSize))
		{
			ret = buffer;
		}
		else
		{
			MYERROR("(ProcessIdToName) Error GetModuleBaseNameA : %lu", W::GetLastError());
		}
		W::CloseHandle(handle);
	}
	else
	{
		printf("Error OpenProcess : %lu", W::GetLastError());
	}
	return ret;
}

W::LPCTSTR ErrorMessage(W::DWORD error)

// Routine Description:
//      Retrieve the system error message for the last-error code
{

	W::LPVOID lpMsgBuf;

	W::FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		error,
		((((W::WORD)(1)) << 10) | (W::WORD)(0)),
		(W::LPTSTR)&lpMsgBuf,
		0, NULL);

	return((W::LPCTSTR)lpMsgBuf);
}

wchar_t* getWStrFromPUnicodeString(W::PUNICODE_STRING pUnicodeString)
{
	W::UNICODE_STRING ustring;

	/* Then read from memory the UNICODE_STRING struct*/
	PIN_SafeCopy((VOID*)&ustring, (VOID*)pUnicodeString, sizeof(W::UNICODE_STRING));
	wchar_t* buf = (wchar_t*)malloc(ustring.Length);

	PIN_SafeCopy((VOID*)buf, (VOID*)ustring.Buffer, ustring.Length);

	return buf;
}

wchar_t* getWStrFromObjectAttribute(W::POBJECT_ATTRIBUTES pObjAttribute) {
	if (pObjAttribute == NULL) {
		return NULL;
	}
	W::OBJECT_ATTRIBUTES obj_attr;
	
	/* Get OBJECT ATTRIBUTES structure value!*/
	PIN_SafeCopy((VOID*)&obj_attr, (VOID*)pObjAttribute, sizeof(W::OBJECT_ATTRIBUTES));
	/* Then read from memory the UNICODE_STRING struct and extract the buffer*/
	wchar_t* buf = getWStrFromPUnicodeString(obj_attr.ObjectName);	
	return buf;
}

string getTimestamp() {
	time_t rawtime;
	struct tm* timeinfo;
	char buffer[100];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", timeinfo);
	std::string str(buffer);

	return str;
}

string getUnixTimestamp()
{
	time_t t = std::time(0);
	std::stringstream ss;
	ss << t;
	return ss.str();
}

string getUnixNanoTimestamp()
{
	// Unfortunately, PIN doesn't support C++ 11 -> chrono
	W::FILETIME ft = { 0 };

	W::GetSystemTimeAsFileTime(&ft);

	W::LARGE_INTEGER li = { 0 };

	li.LowPart = ft.dwLowDateTime;
	li.HighPart = ft.dwHighDateTime;

	long long int hns = li.QuadPart;
	std::stringstream ss;
	ss << hns;
	return ss.str();
}

bool isSuspectedModule(W::LPVOID address, W::MEMORY_BASIC_INFORMATION mbi)
{
	W::HMODULE moduleHandle = 0;
	W::TCHAR moduleName[MAX_PATH];

	/*	Pin leaves traces in memory.
		In particular we want to hide 
		pincrt.dll, pinvm.dll and JuanLesPIN.dll
	*/
	W::SecureZeroMemory(moduleName, sizeof(W::TCHAR) * MAX_PATH);
	if (W::GetMappedFileName(W::GetCurrentProcess(), mbi.AllocationBase, moduleName, MAX_PATH) > 0) {
		std::string s (moduleName);
		return s.find("PIN") != string::npos || s.find("pin") != string::npos;
	}
	
}

void* memmem(const void* haystack_start, size_t haystack_len, const void* needle_start, size_t needle_len)
{

	const unsigned char* haystack = (const unsigned char*)haystack_start;
	const unsigned char* needle = (const unsigned char*)needle_start;
	const unsigned char* h = NULL;
	const unsigned char* n = NULL;
	size_t x = needle_len;

	/* The first occurrence of the empty string is deemed to occur at
	the beginning of the string.  */
	if (needle_len == 0)
		return (void*)haystack_start;

	/* Sanity check, otherwise the loop might search through the whole
		memory.  */
	if (haystack_len < needle_len)
		return NULL;

	for (; haystack_len--; haystack++) {

		x = needle_len;
		n = needle;
		h = haystack;

		if (haystack_len < needle_len)
			break;

		if ((*haystack != *needle) || (*haystack + needle_len != *needle + needle_len))
			continue;

		for (; x; h++, n++) {
			x--;

			if (*h != *n)
				break;

			if (x == 0)
				return (void*)haystack;
		}
	}

	return NULL;
}

void procDump(string filename)
{
	char cmdLine[CMDLINESIZE];
	W::LPSTARTUPINFOA pStartupInfo = new W::STARTUPINFOA();
	W::LPPROCESS_INFORMATION pProcessInfo = new W::PROCESS_INFORMATION();
	W::SECURITY_ATTRIBUTES sa = { sizeof(W::SECURITY_ATTRIBUTES), NULL, TRUE };
	W::DWORD pid = W::GetCurrentProcessId();

	snprintf(cmdLine, CMDLINESIZE, "%s %s %d %s", PROCDUMPBINARY, "-mp", pid, filename.c_str());
	if (!W::CreateProcessA(NULL, cmdLine, 0, 0, TRUE, CREATE_NO_WINDOW, 0, 0, pStartupInfo, pProcessInfo)) {
		MYERROR("CreateProcessA: error creating procdump process");
	}
	else {
		W::WaitForSingleObject(pProcessInfo->hProcess, 120000); // Wait 2 minutes for ProcDump to exit
		W::CloseHandle(pProcessInfo->hProcess);
	}
}

std::string getDllName(const std::string& str)
{
	std::size_t len = str.length();
	std::size_t found = str.find_last_of("/\\");
	std::size_t ext = str.find_last_of(".");
	if (ext >= len) return "";

	std::string name = str.substr(found + 1, ext - (found + 1));
	std::transform(name.begin(), name.end(), name.begin(), std::tolower);
	return name;
}


std::string GetLastErrorAsString(W::LPTSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code

	W::LPSTR messageBuffer = nullptr;
	W::DWORD errorMessageID = W::GetLastError();
	if (errorMessageID == 0) {
		return std::string(); //No error message has been recorded
	};
	size_t size = W::FormatMessage(
		//W::FORMAT_MESSAGE_ALLOCATE_BUFFER | W::FORMAT_MESSAGE_FROM_SYSTEM | W::FORMAT_MESSAGE_IGNORE_INSERTS,
		0x00000100 | 0x00001000 | 0x00000200,
		NULL,
		errorMessageID,
		//W::MAKELANGID(W::LANG_NEUTRAL, W::SUBLANG_DEFAULT),
		0x10000000000,
		(W::LPTSTR)&messageBuffer,
		0, NULL);
	std::string message(messageBuffer, size);
	W::LocalFree(messageBuffer);
	return message;
}



// https://github.com/cuckoosandbox/monitor/blob/master/src/misc.c

const char* our_inet_ntoa(W::in_addr ipaddr)
{
	static char ip[32];
	snprintf(ip, sizeof(ip), "%d.%d.%d.%d",
		ipaddr.s_addr & 0xff, (ipaddr.s_addr >> 8) & 0xff,
		(ipaddr.s_addr >> 16) & 0xff, (ipaddr.s_addr >> 24) & 0xff);
	return ip;
}

uint16_t our_htons(uint16_t value)
{
	return ((value & 0xff) << 8) | ((value >> 8) & 0xff);
}

bool file_exists(const std::string& name)
{
	struct stat buffer;
	return (stat(name.c_str(), &buffer) == 0);
}