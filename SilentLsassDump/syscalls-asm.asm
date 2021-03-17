.code

GetTEBAsm64 PROC PUBLIC
	push rbx 
    xor rbx, rbx 
    xor rax, rax 
    mov rbx, qword ptr gs:[30h] 
	mov rax, rbx 
	pop rbx 
	ret 
GetTEBAsm64 ENDP


NtAdjustPrivilegesToken PROC PUBLIC
mov rax, gs:[60h]
NtAdjustPrivilegesToken_Check_X_X_XXXX:
	cmp dword ptr [rax+118h], 6
	je  NtAdjustPrivilegesToken_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtAdjustPrivilegesToken_Check_10_0_XXXX
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_Check_6_X_XXXX:
	cmp dword ptr [rax+11ch], 1
	je  NtAdjustPrivilegesToken_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtAdjustPrivilegesToken_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtAdjustPrivilegesToken_SystemCall_6_3_XXXX
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_Check_6_1_XXXX:
	cmp word ptr [rax+120h], 7600
	je  NtAdjustPrivilegesToken_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtAdjustPrivilegesToken_SystemCall_6_1_7601
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_Check_10_0_XXXX:
	cmp word ptr [rax+120h], 10240
	je  NtAdjustPrivilegesToken_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtAdjustPrivilegesToken_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtAdjustPrivilegesToken_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtAdjustPrivilegesToken_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtAdjustPrivilegesToken_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtAdjustPrivilegesToken_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtAdjustPrivilegesToken_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtAdjustPrivilegesToken_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtAdjustPrivilegesToken_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtAdjustPrivilegesToken_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtAdjustPrivilegesToken_SystemCall_10_0_19042
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_SystemCall_6_1_7600:
	mov eax, 003eh
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_1_7601:
	mov eax, 003eh
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_2_XXXX:
	mov eax, 003fh
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_3_XXXX:
	mov eax, 0040h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_10240:
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_10586:
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_14393:
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_15063:
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_16299:
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_17134:
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_17763:
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_18362:
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_18363:
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_19041:
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_19042:
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_Unknown:
	ret
NtAdjustPrivilegesToken_Epilogue:
	mov r10, rcx
	syscall
	ret
NtAdjustPrivilegesToken ENDP


NtClose PROC PUBLIC
mov rax, gs:[60h]
NtClose_Check_X_X_XXXX:
	cmp dword ptr [rax+118h], 6
	je  NtClose_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtClose_Check_10_0_XXXX
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_X_XXXX:
	cmp dword ptr [rax+11ch], 1
	je  NtClose_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtClose_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtClose_SystemCall_6_3_XXXX
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_1_XXXX:
	cmp word ptr [rax+120h], 7600
	je  NtClose_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtClose_SystemCall_6_1_7601
	jmp NtClose_SystemCall_Unknown
NtClose_Check_10_0_XXXX:
	cmp word ptr [rax+120h], 10240
	je  NtClose_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtClose_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtClose_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtClose_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtClose_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtClose_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtClose_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtClose_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtClose_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtClose_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtClose_SystemCall_10_0_19042
	jmp NtClose_SystemCall_Unknown
NtClose_SystemCall_6_1_7600:
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_1_7601:
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_2_XXXX:
	mov eax, 000dh
	jmp NtClose_Epilogue
NtClose_SystemCall_6_3_XXXX:
	mov eax, 000eh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_10240:
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_10586:
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_14393:
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_15063:
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_16299:
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_17134:
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_17763:
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_18362:
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_18363:
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_19041:
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_19042:
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_Unknown:
	ret
NtClose_Epilogue:
	mov r10, rcx
	syscall
	ret
NtClose ENDP


NtCreateKey PROC PUBLIC
mov rax, gs:[60h]
NtCreateKey_Check_X_X_XXXX:
	cmp dword ptr [rax+118h], 6
	je  NtCreateKey_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtCreateKey_Check_10_0_XXXX
	jmp NtCreateKey_SystemCall_Unknown
NtCreateKey_Check_6_X_XXXX:
	cmp dword ptr [rax+11ch], 1
	je  NtCreateKey_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtCreateKey_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtCreateKey_SystemCall_6_3_XXXX
	jmp NtCreateKey_SystemCall_Unknown
NtCreateKey_Check_6_1_XXXX:
	cmp word ptr [rax+120h], 7600
	je  NtCreateKey_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtCreateKey_SystemCall_6_1_7601
	jmp NtCreateKey_SystemCall_Unknown
NtCreateKey_Check_10_0_XXXX:
	cmp word ptr [rax+120h], 10240
	je  NtCreateKey_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtCreateKey_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtCreateKey_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtCreateKey_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtCreateKey_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtCreateKey_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtCreateKey_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtCreateKey_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtCreateKey_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtCreateKey_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtCreateKey_SystemCall_10_0_19042
	jmp NtCreateKey_SystemCall_Unknown
NtCreateKey_SystemCall_6_1_7600:
	mov eax, 001ah
	jmp NtCreateKey_Epilogue
NtCreateKey_SystemCall_6_1_7601:
	mov eax, 001ah
	jmp NtCreateKey_Epilogue
NtCreateKey_SystemCall_6_2_XXXX:
	mov eax, 001bh
	jmp NtCreateKey_Epilogue
NtCreateKey_SystemCall_6_3_XXXX:
	mov eax, 001ch
	jmp NtCreateKey_Epilogue
NtCreateKey_SystemCall_10_0_10240:
	mov eax, 001dh
	jmp NtCreateKey_Epilogue
NtCreateKey_SystemCall_10_0_10586:
	mov eax, 001dh
	jmp NtCreateKey_Epilogue
NtCreateKey_SystemCall_10_0_14393:
	mov eax, 001dh
	jmp NtCreateKey_Epilogue
NtCreateKey_SystemCall_10_0_15063:
	mov eax, 001dh
	jmp NtCreateKey_Epilogue
NtCreateKey_SystemCall_10_0_16299:
	mov eax, 001dh
	jmp NtCreateKey_Epilogue
NtCreateKey_SystemCall_10_0_17134:
	mov eax, 001dh
	jmp NtCreateKey_Epilogue
NtCreateKey_SystemCall_10_0_17763:
	mov eax, 001dh
	jmp NtCreateKey_Epilogue
NtCreateKey_SystemCall_10_0_18362:
	mov eax, 001dh
	jmp NtCreateKey_Epilogue
NtCreateKey_SystemCall_10_0_18363:
	mov eax, 001dh
	jmp NtCreateKey_Epilogue
NtCreateKey_SystemCall_10_0_19041:
	mov eax, 001dh
	jmp NtCreateKey_Epilogue
NtCreateKey_SystemCall_10_0_19042:
	mov eax, 001dh
	jmp NtCreateKey_Epilogue
NtCreateKey_SystemCall_Unknown:
	ret
NtCreateKey_Epilogue:
	mov r10, rcx
	syscall
	ret
NtCreateKey ENDP


NtCreateThreadEx PROC PUBLIC
mov rax, gs:[60h]
NtCreateThreadEx_Check_X_X_XXXX:
	cmp dword ptr [rax+118h], 6
	je  NtCreateThreadEx_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtCreateThreadEx_Check_10_0_XXXX
	jmp NtCreateThreadEx_SystemCall_Unknown
NtCreateThreadEx_Check_6_X_XXXX:
	cmp dword ptr [rax+11ch], 1
	je  NtCreateThreadEx_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtCreateThreadEx_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtCreateThreadEx_SystemCall_6_3_XXXX
	jmp NtCreateThreadEx_SystemCall_Unknown
NtCreateThreadEx_Check_6_1_XXXX:
	cmp word ptr [rax+120h], 7600
	je  NtCreateThreadEx_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtCreateThreadEx_SystemCall_6_1_7601
	jmp NtCreateThreadEx_SystemCall_Unknown
NtCreateThreadEx_Check_10_0_XXXX:
	cmp word ptr [rax+120h], 10240
	je  NtCreateThreadEx_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtCreateThreadEx_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtCreateThreadEx_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtCreateThreadEx_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtCreateThreadEx_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtCreateThreadEx_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtCreateThreadEx_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtCreateThreadEx_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtCreateThreadEx_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtCreateThreadEx_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtCreateThreadEx_SystemCall_10_0_19042
	jmp NtCreateThreadEx_SystemCall_Unknown
NtCreateThreadEx_SystemCall_6_1_7600:
	mov eax, 00a5h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_6_1_7601:
	mov eax, 00a5h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_6_2_XXXX:
	mov eax, 00afh
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_6_3_XXXX:
	mov eax, 00b0h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_10240:
	mov eax, 00b3h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_10586:
	mov eax, 00b4h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_14393:
	mov eax, 00b6h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_15063:
	mov eax, 00b9h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_16299:
	mov eax, 00bah
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_17134:
	mov eax, 00bbh
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_17763:
	mov eax, 00bch
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_18362:
	mov eax, 00bdh
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_18363:
	mov eax, 00bdh
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_19041:
	mov eax, 00c1h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_19042:
	mov eax, 00c1h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_Unknown:
	ret
NtCreateThreadEx_Epilogue:
	mov r10, rcx
	syscall
	ret
NtCreateThreadEx ENDP


NtDeleteKey PROC PUBLIC
mov rax, gs:[60h]
NtDeleteKey_Check_X_X_XXXX:
	cmp dword ptr [rax+118h], 6
	je  NtDeleteKey_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtDeleteKey_Check_10_0_XXXX
	jmp NtDeleteKey_SystemCall_Unknown
NtDeleteKey_Check_6_X_XXXX:
	cmp dword ptr [rax+11ch], 1
	je  NtDeleteKey_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtDeleteKey_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtDeleteKey_SystemCall_6_3_XXXX
	jmp NtDeleteKey_SystemCall_Unknown
NtDeleteKey_Check_6_1_XXXX:
	cmp word ptr [rax+120h], 7600
	je  NtDeleteKey_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtDeleteKey_SystemCall_6_1_7601
	jmp NtDeleteKey_SystemCall_Unknown
NtDeleteKey_Check_10_0_XXXX:
	cmp word ptr [rax+120h], 10240
	je  NtDeleteKey_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtDeleteKey_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtDeleteKey_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtDeleteKey_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtDeleteKey_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtDeleteKey_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtDeleteKey_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtDeleteKey_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtDeleteKey_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtDeleteKey_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtDeleteKey_SystemCall_10_0_19042
	jmp NtDeleteKey_SystemCall_Unknown
NtDeleteKey_SystemCall_6_1_7600:
	mov eax, 00b3h
	jmp NtDeleteKey_Epilogue
NtDeleteKey_SystemCall_6_1_7601:
	mov eax, 00b3h
	jmp NtDeleteKey_Epilogue
NtDeleteKey_SystemCall_6_2_XXXX:
	mov eax, 00c0h
	jmp NtDeleteKey_Epilogue
NtDeleteKey_SystemCall_6_3_XXXX:
	mov eax, 00c2h
	jmp NtDeleteKey_Epilogue
NtDeleteKey_SystemCall_10_0_10240:
	mov eax, 00c5h
	jmp NtDeleteKey_Epilogue
NtDeleteKey_SystemCall_10_0_10586:
	mov eax, 00c6h
	jmp NtDeleteKey_Epilogue
NtDeleteKey_SystemCall_10_0_14393:
	mov eax, 00c8h
	jmp NtDeleteKey_Epilogue
NtDeleteKey_SystemCall_10_0_15063:
	mov eax, 00cbh
	jmp NtDeleteKey_Epilogue
NtDeleteKey_SystemCall_10_0_16299:
	mov eax, 00cch
	jmp NtDeleteKey_Epilogue
NtDeleteKey_SystemCall_10_0_17134:
	mov eax, 00cdh
	jmp NtDeleteKey_Epilogue
NtDeleteKey_SystemCall_10_0_17763:
	mov eax, 00ceh
	jmp NtDeleteKey_Epilogue
NtDeleteKey_SystemCall_10_0_18362:
	mov eax, 00cfh
	jmp NtDeleteKey_Epilogue
NtDeleteKey_SystemCall_10_0_18363:
	mov eax, 00cfh
	jmp NtDeleteKey_Epilogue
NtDeleteKey_SystemCall_10_0_19041:
	mov eax, 00d3h
	jmp NtDeleteKey_Epilogue
NtDeleteKey_SystemCall_10_0_19042:
	mov eax, 00d3h
	jmp NtDeleteKey_Epilogue
NtDeleteKey_SystemCall_Unknown:
	ret
NtDeleteKey_Epilogue:
	mov r10, rcx
	syscall
	ret
NtDeleteKey ENDP


NtOpenKey PROC PUBLIC
mov rax, gs:[60h]
NtOpenKey_Check_X_X_XXXX:
	cmp dword ptr [rax+118h], 6
	je  NtOpenKey_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtOpenKey_Check_10_0_XXXX
	jmp NtOpenKey_SystemCall_Unknown
NtOpenKey_Check_6_X_XXXX:
	cmp dword ptr [rax+11ch], 1
	je  NtOpenKey_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtOpenKey_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtOpenKey_SystemCall_6_3_XXXX
	jmp NtOpenKey_SystemCall_Unknown
NtOpenKey_Check_6_1_XXXX:
	cmp word ptr [rax+120h], 7600
	je  NtOpenKey_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtOpenKey_SystemCall_6_1_7601
	jmp NtOpenKey_SystemCall_Unknown
NtOpenKey_Check_10_0_XXXX:
	cmp word ptr [rax+120h], 10240
	je  NtOpenKey_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtOpenKey_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtOpenKey_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtOpenKey_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtOpenKey_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtOpenKey_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtOpenKey_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtOpenKey_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtOpenKey_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtOpenKey_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtOpenKey_SystemCall_10_0_19042
	jmp NtOpenKey_SystemCall_Unknown
NtOpenKey_SystemCall_6_1_7600:
	mov eax, 000fh
	jmp NtOpenKey_Epilogue
NtOpenKey_SystemCall_6_1_7601:
	mov eax, 000fh
	jmp NtOpenKey_Epilogue
NtOpenKey_SystemCall_6_2_XXXX:
	mov eax, 0010h
	jmp NtOpenKey_Epilogue
NtOpenKey_SystemCall_6_3_XXXX:
	mov eax, 0011h
	jmp NtOpenKey_Epilogue
NtOpenKey_SystemCall_10_0_10240:
	mov eax, 0012h
	jmp NtOpenKey_Epilogue
NtOpenKey_SystemCall_10_0_10586:
	mov eax, 0012h
	jmp NtOpenKey_Epilogue
NtOpenKey_SystemCall_10_0_14393:
	mov eax, 0012h
	jmp NtOpenKey_Epilogue
NtOpenKey_SystemCall_10_0_15063:
	mov eax, 0012h
	jmp NtOpenKey_Epilogue
NtOpenKey_SystemCall_10_0_16299:
	mov eax, 0012h
	jmp NtOpenKey_Epilogue
NtOpenKey_SystemCall_10_0_17134:
	mov eax, 0012h
	jmp NtOpenKey_Epilogue
NtOpenKey_SystemCall_10_0_17763:
	mov eax, 0012h
	jmp NtOpenKey_Epilogue
NtOpenKey_SystemCall_10_0_18362:
	mov eax, 0012h
	jmp NtOpenKey_Epilogue
NtOpenKey_SystemCall_10_0_18363:
	mov eax, 0012h
	jmp NtOpenKey_Epilogue
NtOpenKey_SystemCall_10_0_19041:
	mov eax, 0012h
	jmp NtOpenKey_Epilogue
NtOpenKey_SystemCall_10_0_19042:
	mov eax, 0012h
	jmp NtOpenKey_Epilogue
NtOpenKey_SystemCall_Unknown:
	ret
NtOpenKey_Epilogue:
	mov r10, rcx
	syscall
	ret
NtOpenKey ENDP


NtOpenProcess PROC PUBLIC
mov rax, gs:[60h]
NtOpenProcess_Check_X_X_XXXX:
	cmp dword ptr [rax+118h], 6
	je  NtOpenProcess_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtOpenProcess_Check_10_0_XXXX
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_6_X_XXXX:
	cmp dword ptr [rax+11ch], 1
	je  NtOpenProcess_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtOpenProcess_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtOpenProcess_SystemCall_6_3_XXXX
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_6_1_XXXX:
	cmp word ptr [rax+120h], 7600
	je  NtOpenProcess_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtOpenProcess_SystemCall_6_1_7601
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_10_0_XXXX:
	cmp word ptr [rax+120h], 10240
	je  NtOpenProcess_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtOpenProcess_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtOpenProcess_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtOpenProcess_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtOpenProcess_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtOpenProcess_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtOpenProcess_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtOpenProcess_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtOpenProcess_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtOpenProcess_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtOpenProcess_SystemCall_10_0_19042
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_SystemCall_6_1_7600:
	mov eax, 0023h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_1_7601:
	mov eax, 0023h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_2_XXXX:
	mov eax, 0024h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_3_XXXX:
	mov eax, 0025h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_10240:
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_10586:
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_14393:
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_15063:
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_16299:
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_17134:
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_17763:
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_18362:
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_18363:
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_19041:
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_19042:
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_Unknown:
	ret
NtOpenProcess_Epilogue:
	mov r10, rcx
	syscall
	ret
NtOpenProcess ENDP


NtOpenProcessToken PROC PUBLIC
mov rax, gs:[60h]
NtOpenProcessToken_Check_X_X_XXXX:
	cmp dword ptr [rax+118h], 6
	je  NtOpenProcessToken_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtOpenProcessToken_Check_10_0_XXXX
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_Check_6_X_XXXX:
	cmp dword ptr [rax+11ch], 1
	je  NtOpenProcessToken_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtOpenProcessToken_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtOpenProcessToken_SystemCall_6_3_XXXX
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_Check_6_1_XXXX:
	cmp word ptr [rax+120h], 7600
	je  NtOpenProcessToken_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtOpenProcessToken_SystemCall_6_1_7601
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_Check_10_0_XXXX:
	cmp word ptr [rax+120h], 10240
	je  NtOpenProcessToken_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtOpenProcessToken_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtOpenProcessToken_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtOpenProcessToken_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtOpenProcessToken_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtOpenProcessToken_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtOpenProcessToken_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtOpenProcessToken_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtOpenProcessToken_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtOpenProcessToken_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtOpenProcessToken_SystemCall_10_0_19042
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_SystemCall_6_1_7600:
	mov eax, 00f9h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_6_1_7601:
	mov eax, 00f9h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_6_2_XXXX:
	mov eax, 010bh
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_6_3_XXXX:
	mov eax, 010eh
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_10240:
	mov eax, 0114h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_10586:
	mov eax, 0117h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_14393:
	mov eax, 0119h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_15063:
	mov eax, 011dh
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_16299:
	mov eax, 011fh
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_17134:
	mov eax, 0121h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_17763:
	mov eax, 0122h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_18362:
	mov eax, 0123h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_18363:
	mov eax, 0123h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_19041:
	mov eax, 0128h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_19042:
	mov eax, 0128h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_Unknown:
	ret
NtOpenProcessToken_Epilogue:
	mov r10, rcx
	syscall
	ret
NtOpenProcessToken ENDP


NtSetValueKey PROC PUBLIC
mov rax, gs:[60h]
NtSetValueKey_Check_X_X_XXXX:
	cmp dword ptr [rax+118h], 6
	je  NtSetValueKey_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtSetValueKey_Check_10_0_XXXX
	jmp NtSetValueKey_SystemCall_Unknown
NtSetValueKey_Check_6_X_XXXX:
	cmp dword ptr [rax+11ch], 1
	je  NtSetValueKey_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtSetValueKey_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtSetValueKey_SystemCall_6_3_XXXX
	jmp NtSetValueKey_SystemCall_Unknown
NtSetValueKey_Check_6_1_XXXX:
	cmp word ptr [rax+120h], 7600
	je  NtSetValueKey_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtSetValueKey_SystemCall_6_1_7601
	jmp NtSetValueKey_SystemCall_Unknown
NtSetValueKey_Check_10_0_XXXX:
	cmp word ptr [rax+120h], 10240
	je  NtSetValueKey_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtSetValueKey_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtSetValueKey_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtSetValueKey_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtSetValueKey_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtSetValueKey_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtSetValueKey_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtSetValueKey_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtSetValueKey_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtSetValueKey_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtSetValueKey_SystemCall_10_0_19042
	jmp NtSetValueKey_SystemCall_Unknown
NtSetValueKey_SystemCall_6_1_7600:
	mov eax, 005dh
	jmp NtSetValueKey_Epilogue
NtSetValueKey_SystemCall_6_1_7601:
	mov eax, 005dh
	jmp NtSetValueKey_Epilogue
NtSetValueKey_SystemCall_6_2_XXXX:
	mov eax, 005eh
	jmp NtSetValueKey_Epilogue
NtSetValueKey_SystemCall_6_3_XXXX:
	mov eax, 005fh
	jmp NtSetValueKey_Epilogue
NtSetValueKey_SystemCall_10_0_10240:
	mov eax, 0060h
	jmp NtSetValueKey_Epilogue
NtSetValueKey_SystemCall_10_0_10586:
	mov eax, 0060h
	jmp NtSetValueKey_Epilogue
NtSetValueKey_SystemCall_10_0_14393:
	mov eax, 0060h
	jmp NtSetValueKey_Epilogue
NtSetValueKey_SystemCall_10_0_15063:
	mov eax, 0060h
	jmp NtSetValueKey_Epilogue
NtSetValueKey_SystemCall_10_0_16299:
	mov eax, 0060h
	jmp NtSetValueKey_Epilogue
NtSetValueKey_SystemCall_10_0_17134:
	mov eax, 0060h
	jmp NtSetValueKey_Epilogue
NtSetValueKey_SystemCall_10_0_17763:
	mov eax, 0060h
	jmp NtSetValueKey_Epilogue
NtSetValueKey_SystemCall_10_0_18362:
	mov eax, 0060h
	jmp NtSetValueKey_Epilogue
NtSetValueKey_SystemCall_10_0_18363:
	mov eax, 0060h
	jmp NtSetValueKey_Epilogue
NtSetValueKey_SystemCall_10_0_19041:
	mov eax, 0060h
	jmp NtSetValueKey_Epilogue
NtSetValueKey_SystemCall_10_0_19042:
	mov eax, 0060h
	jmp NtSetValueKey_Epilogue
NtSetValueKey_SystemCall_Unknown:
	ret
NtSetValueKey_Epilogue:
	mov r10, rcx
	syscall
	ret
NtSetValueKey ENDP
END