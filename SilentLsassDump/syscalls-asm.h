#pragma once
#include "Syscalls.h"

#define ZwtTEBAsm64 GetTEBAsm64
#define ZwAdjustPrivilegesToken NtAdjustPrivilegesToken
#define ZwClose NtClose
#define ZwCreateKey NtCreateKey
#define ZwCreateThreadEx NtCreateThreadEx
#define ZwDeleteKey NtDeleteKey
#define ZwOpenKey NtOpenKey
#define ZwOpenProcess NtOpenProcess
#define ZwOpenProcessToken NtOpenProcessToken
#define ZwSetValueKey NtSetValueKey