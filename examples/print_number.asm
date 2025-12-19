section .data
    digit db '0', 10             ; ASCII '0' + newline
    len   equ $ - digit

section .text
    global _start

_start:
    mov ecx, 10                  ; loop counter

.loop:
    push ecx

    ; write(stdout, digit, len)
    mov eax, 4
    mov ebx, 1
    mov ecx, digit               ; buffer pointer
    mov edx, len                 ; 2 bytes: digit + newline
    int 0x80

    inc byte [digit]             ; next digit

    pop ecx		      ; check loop counter
    dec ecx
    jnz .loop

    ; exit(0)
    mov eax, 1
    mov ebx, 0
    int 0x80
