#include <iostream>
#include <Windows.h>
#include <string>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>

//#pragma comment(lib, "cmcfg32.lib")

std::string GetLastErrorAsString();
HANDLE FindMinesw();
BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege);
HMODULE GetModule(HANDLE hProc);
LPVOID GetDataSection(LPVOID lpBuff);

int main(void)
{
    HANDLE tokenH = 0;
    HANDLE hProc;
    /*
    if (!OpenProcessToken(hProc, TOKEN_ALL_ACCESS, &tokenH))
        return - 1;
    if (!SetPrivilege(tokenH, SE_DEBUG_NAME, true))
    {
        
        std::cout << "Error: SetPrivilege"<<std::endl;
        return -1;
    }
    */
  
    hProc = FindMinesw();
    HMODULE hMod = GetModule(hProc);
    printf("%x \n", hMod);
    hMod = hMod + 0x1800;
    //std::cout << (DWORD)hMod;
    return 0;
}

LPVOID GetDataSection(LPVOID lpBuff)
{



}

HMODULE GetModule(HANDLE hProc)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;
    unsigned int i;

    if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProc, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
            {
                std::wstring wstrModName = szModName;
                //you will need to change this to the name of the exe of the foreign process
                std::wstring wstrModContain = L"winmine.exe";
                if (wstrModName.find(wstrModContain) != std::string::npos)
                {
                    CloseHandle(hProc);
                    return hMods[i];
                }
            }
        }
    }
    return nullptr;
}
BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}
HANDLE FindMinesw()
{
    HANDLE hProcessSnap;
    HANDLE hProcess = 0;
    PROCESSENTRY32 pe32;
    DWORD dwPriorityClass;
    std::wstring winmine (TEXT("winmine.exe"));
    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        std::cout << GetLastErrorAsString() << std::endl;
        return(FALSE);
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32))
    {
        std::cout << GetLastErrorAsString() << std::endl; // show cause of failure
        CloseHandle(hProcessSnap);          // clean the snapshot object
        return(FALSE);
    }

    // Now walk the snapshot of processes, and
    // display information about each process in turn
    do
    {
        if (!winmine.compare(pe32.szExeFile))
        {
            std::wcout << "PROCESS NAME: " << pe32.szExeFile << std::endl;
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);

            std::cout << "Process ID        = " << pe32.th32ProcessID << std::endl;
            std::cout << "Thread count      = " << pe32.cntThreads << std::endl;
            std::cout << "Parent process ID = " << pe32.th32ParentProcessID << std::endl;
            std::cout << "Priority base     = " << pe32.pcPriClassBase << std::endl;
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return hProcess;
}

std::string GetLastErrorAsString()
{
    //Get the error message ID, if any.
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0) {
        return std::string(); //No error message has been recorded
    }

    LPSTR messageBuffer = nullptr;

    //Ask Win32 to give us the string version of that message ID.
    //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    //Copy the error message into a std::string.
    std::string message(messageBuffer, size);

    //Free the Win32's string's buffer.
    LocalFree(messageBuffer);

    return message;
}