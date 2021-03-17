#pragma once
#include <windows.h>
#include <stdio.h>

#include "syscalls-asm.h"

#define STATUS_SUCCESS 0
#define STATUS_UNSUCCESSFUL 0xC0000001
#define OBJ_CASE_INSENSITIVE 0x00000040L

#define IFEO_REG_KEY L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
#define SILENT_PROCESS_EXIT_REG_KEY L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\"
#define LOCAL_DUMP 0x2
#define FLG_MONITOR_SILENT_PROCESS_EXIT 0x200
#define MiniDumpWithFullMemory 0x2

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)



// Unicode function
typedef VOID(WINAPI* _RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS(NTAPI* _RtlAppendUnicodeToString)(PUNICODE_STRING Destination, PCWSTR Source);
typedef VOID(WINAPI* _RtlFreeUnicodeString)(PUNICODE_STRING UnicodeString);
typedef NTSTATUS(NTAPI* _RtlReportSilentProcessExit)(HANDLE ProcessHandle, NTSTATUS ExitStatus);