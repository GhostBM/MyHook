.code
GetR11Value proc
    mov rax, r11    ; 将 R14 的值存入 RAX（返回值寄存器）
    ret
GetR11Value endp


HookAddress proc
    mov  r14, rcx
    mov  r15, rdx
    jmp  r15
    ret
HookAddress endp

end