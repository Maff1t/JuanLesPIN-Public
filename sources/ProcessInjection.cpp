#include "ProcessInjection.h"

W::HANDLE hHoneypot = NULL;
W::DWORD honeypotPID = NULL;
Complete_PEB* pPEB = NULL;
set <W::PVOID> remoteWrittenAddresses;
set <W::DWORD> hookedPID;
PIPEINST namedPipe;
char* waitBuffer = NULL;
set <pair <ADDRINT, size_t>> honeypotRedZone; // startAddress, size!
set <string> injectedDLL;

/* ---- HoneyPot Process functions! ---- */

bool initHoneypotProcess(string reportFileName, W::DWORD parentPid) {
    W::LPSTARTUPINFOA pStartupInfo = new W::STARTUPINFOA();
    W::LPPROCESS_INFORMATION pProcessInfo = new W::PROCESS_INFORMATION();
    W::SECURITY_ATTRIBUTES sa = { sizeof(W::SECURITY_ATTRIBUTES), NULL, TRUE };
    char cmdLine[CMDLINESIZE];
    std::stringstream namedPipeName, report;
    namedPipeName << "\\\\.\\pipe\\honeypotPipe_" << parentPid;
    report << reportFileName << "-honeypot-" << parentPid;
    snprintf(cmdLine, CMDLINESIZE, "-follow_execv -t  C:\\pin\\source\\tools\\JuanLesPIN\\Release\\JuanLesPIN.dll -honeypot 1 -pipeName %s -report %s -- C:\\pin\\source\\tools\\JuanLesPIN\\Release\\Honeypot.exe", namedPipeName.str().c_str(), report.str().c_str());
    /* Creating Honeypot Process */
    if (!W::CreateProcessA("C:\\pin\\pin.exe", cmdLine, 0, 0, TRUE, CREATE_NO_WINDOW, 0, 0, pStartupInfo, pProcessInfo)) {
        MYERROR("CreateProcessA: error creating honeypot process");
        return false;
    }   
    return true;
}

bool findHoneypotProcess()
{
    honeypotPID = GetProcessIdFromName("Honeypot.exe");
    if (honeypotPID == 0) {
        MYERROR("Unable to find Honeypot.exe process!");
        return false;
    }
        
    hHoneypot = W::OpenProcess(PROCESS_ALL_ACCESS, FALSE, honeypotPID);
    
    return true;
}

void terminateHoneypotProcess()
{
    if (!hHoneypot) return;
    if (!W::TerminateProcess(hHoneypot, 2))
        MYERROR("Unable to terminate Honeypot process");
}

/* ---- IPC With Named Pipe ASYNC ---- */

bool initNamedPipeServer(W::DWORD parentPid)
{
    std::stringstream namedPipeName;
    namedPipeName << "\\\\.\\pipe\\honeypotPipe_" << parentPid;

    memset(&namedPipe.oOverlap, 0, sizeof(W::OVERLAPPED));

    W::HANDLE hEvent = W::CreateEvent(
        NULL,    // default security attribute 
        TRUE,    // manual-reset event 
        TRUE,    // initial state = signaled 
        NULL);   // unnamed event object 

    if (hEvent == NULL)
    {
        MYERROR("CreateEvent failed");
        return false;
    }

    namedPipe.oOverlap.hEvent = hEvent;

    namedPipe.hPipeInst = W::CreateNamedPipe(
        namedPipeName.str().c_str(), // name of the pipe
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, // Async
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, // send data as a MESSAGE stream
        1, // only allow 1 instance of this pipe
        3 * MSGLEN * sizeof(char), 
        3 * MSGLEN * sizeof(char),
        0, // use default wait time
        NULL // use default security attributes
    );

    if (namedPipe.hPipeInst == NULL) {
        MYERROR("Failed to create pipe instance");
        return false;
    }

    W::BOOL fConnected = FALSE;

    fConnected = W::ConnectNamedPipe(namedPipe.hPipeInst, &namedPipe.oOverlap);
    
    if (fConnected) {
        MYERROR("Failed to make connection on named pipe.");
        W::CloseHandle(namedPipe.hPipeInst); // close the pipe
        return false;
    }

    return true;
}

bool initNamedPipeClient(string namedPipeName)
{
    W::HANDLE hEvent = W::CreateEvent(
        NULL,    // default security attribute 
        TRUE,    // manual-reset event 
        TRUE,    // initial state = signaled 
        NULL);   // unnamed event object 

    if (hEvent == NULL)
    {
        MYERROR("CreateEvent failed");
        return false;
    }

    namedPipe.oOverlap.hEvent = hEvent;

    namedPipe.hPipeInst = W::CreateFile(
        namedPipeName.c_str(),
        GENERIC_READ, // only need read access
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL
    );
    
    if (namedPipe.hPipeInst == ((W::HANDLE)(W::LONG_PTR)-1) || W::GetLastError() == ERROR_FILE_NOT_FOUND) { //((W::HANDLE)(W::LONG_PTR)-1) == INVALID_HANDLE_VALUE
        MYERROR("Failed to connect to pipe.");
        return false;
    } 

    //MYINFO("PIPE CLIENT CONNECTED");
    return true;

}

void sendMessageToPipe(string label, string content) {
    if (!namedPipe.hPipeInst) return;

    W::BOOL fsuccess;
    W::DWORD NumberOfBytesTransferred = 0;
    fsuccess = W::GetOverlappedResult(namedPipe.hPipeInst, &namedPipe.oOverlap, &NumberOfBytesTransferred, TRUE);
    if (fsuccess) {
        string message(label + " " + content + " ");
        for (size_t i = 0; i < MSGLEN - message.length(); i++) {
            message.append(PADDINGLETTER);
        }

        if (!W::WriteFile(namedPipe.hPipeInst, message.c_str(), MSGLEN, NULL, &namedPipe.oOverlap)) {
                MYERROR("Error WriteFile");
                return;
        }

        //MYINFO("WROTE ON PIPE");
    }
    else {
        MYERROR("Error sendMessageToPipe, GetOverlappedResult");
    }
    //}
}

void fetchMessageFromPipe()
{   
    if (!namedPipe.hPipeInst) return;

    W::BOOL fsuccess;
    W::DWORD NumberOfBytesTransferred = 0;
    W::DWORD TotalBytesAvail = 0;
    W::DWORD dwError;

    fsuccess = W::GetOverlappedResult(namedPipe.hPipeInst, &namedPipe.oOverlap, &NumberOfBytesTransferred, FALSE);
    if (fsuccess && waitBuffer != NULL) {
        //MYINFO("FOUND BUFFER");
        string buf(waitBuffer);
        parseMessage(buf);
        free(waitBuffer);
        waitBuffer = NULL;
        return;
    }

    //fsuccess = W::WaitForSingleObject(namedPipe.oOverlap.hEvent, 0);

    /* If the specified object is in the signaled state -> fsuccess == WAIT_OBJECT_0 */
    if (fsuccess) {
        
        char * buffer = (char*)malloc(sizeof(char) * MSGLEN);
        memset(buffer, 0, MSGLEN);
        fsuccess = W::ReadFile(namedPipe.hPipeInst, buffer, MSGLEN, NULL, &namedPipe.oOverlap);
        dwError = W::GetLastError();
        if (!fsuccess && dwError != ERROR_IO_PENDING) {
            MYERROR("ReadFile error");
            return;
        }
        else if (!fsuccess) {
            //MYINFO("WAIT BUFFER!");
            waitBuffer = buffer;
            return;
        }
        else {
            parseMessage(string(buffer));
            free(buffer);
            waitBuffer = NULL;
        }
     
    }
}

void parseMessage(string message)
{
    std::istringstream ss(message);
    string token;
    /* Get Label */
    std::getline(ss, token, ' ');
    if (token == "[CODE]") { /* Shellcode injection */
        std::getline(ss, token, ' ');
        ADDRINT startAddress = strtol(token.c_str(), NULL, 16);
        std::getline(ss, token, ' ');
        size_t size = std::atoi(token.c_str());
        addToHoneypotRedZone(startAddress, size);
    }
    else if (token == "[DLL]") { /* DLL injection */
        std::getline(ss, token, ' ');
        ADDRINT loadLibraryAddress = strtol(token.c_str(), NULL, 16);
        std::getline(ss, token, ' ');
        ADDRINT dllPathAddress = strtol(token.c_str(), NULL, 16);
        std::stringstream dllPathString;
        int isLoadLibrary = isLoadLibraryAddress(loadLibraryAddress);
        if (!isLoadLibrary)
            return;
        if (isLoadLibrary == 1) { // It means that is LoadLibraryW
            /* Retriving DLL Path from memory! */
            wchar_t* dllPath = (wchar_t*)malloc(sizeof(wchar_t) * MAXDLLPATHLENGHT);
            PIN_SafeCopy(dllPath, (VOID*)dllPathAddress, sizeof(wchar_t) * MAXDLLPATHLENGHT);
            wstring ws(dllPath);
            string s(ws.begin(), ws.end());
            dllPathString << s;
        }
        else { // LoadLibraryA
            /* Retriving DLL Path from memory! */
            char* dllPath = (char*)malloc(sizeof(char) * MAXDLLPATHLENGHT);
            PIN_SafeCopy(dllPath, (VOID*)dllPathAddress, sizeof(char) * MAXDLLPATHLENGHT);
            string s(dllPath);
            dllPathString << s;
        }
        
        /* Check if it is really a dll, and if so report DLL Injection, and hook the memory associated! */
        if (dllPathString.str().find(".dll") != string::npos) {
            string message("Malware loaded " + dllPathString.str() + " into another process memory");
            EVASION("CODE INJECTION", NULL, "dll_injection", message.c_str());
            
            /* Check if the DLL is already loaded. If it is, hook it. If not, save it for later!!*/
            if (!hookLoadedDll(dllPathString.str()))
                addToInjectedDLL(dllPathString.str());
        }
    }
    else {
        MYERROR("Unable to parse message %s", message.c_str());
    }
}

/* Utils for injected process */
void addToHoneypotRedZone(ADDRINT startAddress, size_t size) {
    //MYINFO("addToInjectedMemory %d %d", startAddress, size);
    honeypotRedZone.insert(pair<ADDRINT, size_t>(startAddress, size));
}

void addToInjectedDLL(string dllName) {
    //MYINFO("addToInjectedDLL %s", dllName.c_str());
    injectedDLL.insert(dllName);
}

bool isInsideRedZoneHoneypot(ADDRINT address) {
    
    ADDRINT startAddr;
    for (auto it = honeypotRedZone.begin(); it != honeypotRedZone.end(); it++) {
        startAddr = it->first;
        if (address > startAddr && address < (startAddr + it->second))
            return true;
    }
    return false;
}

bool isInInjectedDLL(string dllName) {
    return (bool)injectedDLL.count(dllName);
}

bool hookLoadedDll(string dllPathString) {
    W::HANDLE snapshot = W::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, W::GetCurrentProcessId());

    if (snapshot == ((W::HANDLE)(W::LONG_PTR) - 1)) //INVALID_HANDLE_VALUE
    {
        MYERROR("Failed to get snapshot");
    }
    else
    {
        W::MODULEENTRY32 module = { 0 };
        module.dwSize = sizeof(W::MODULEENTRY32);
        if (W::Module32First(snapshot, &module) != FALSE)
        {
            do
            {
                if (dllPathString == string(module.szExePath)) {
                    addToHoneypotRedZone((ADDRINT)module.modBaseAddr, (size_t)module.modBaseSize);
                    return true;
                }

            } while (Module32Next(snapshot, &module) != FALSE);
        }
        else
        {
            MYERROR("Failed to get first module");
        }

        W::CloseHandle(snapshot);
    }
    
    return false;
}

int isLoadLibraryAddress(ADDRINT address) {
    /* Obtain a handle to kernel32 */
    W::HMODULE hKernel32 = W::GetModuleHandle("kernel32.dll");
    if (hKernel32 == NULL) {
        MYERROR("isLoadLibraryAddress, Get kernel32 module");
        return 0;
    }

    /*  I need to know if it is LoadLibraryW or LoadlibraryA because 
        I have to parse correctly the argument
    */
    W::FARPROC LoadLibraryW = W::GetProcAddress(hKernel32, "LoadLibraryW");
    if ((W::UINT32)LoadLibraryW == (W::UINT32) address) return 1;

    W::FARPROC LoadLibraryA = W::GetProcAddress(hKernel32, "LoadLibraryA");
    if ((W::UINT32)LoadLibraryA == (W::UINT32) address) return 2;

    return 0;
}