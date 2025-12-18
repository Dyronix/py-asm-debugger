.global _start

.extern printf

.section .rodata
.number_format:
  .string "%d\n"

.section .text
_start:
  lea ecx, [esp+4]
  and esp, -16
  push DWORD PTR [ecx-4]
  push ebp
  mov ebp, esp
  push ecx
  sub esp, 20
  mov DWORD PTR [ebp-12], 0
  mov DWORD PTR [ebp-16], 1
  jmp .check_number_x
  mov eax, 1
  mov ebx, 0
  int 0x80
.fib:
  mov edx, DWORD PTR [ebp-12]
  mov eax, DWORD PTR [ebp-16]
  add eax, edx
  mov DWORD PTR [ebp-20], eax
  sub esp, 8
  push DWORD PTR [ebp-12]
  push OFFSET FLAT:.number_format
  call "printf"
  add esp, 16
  mov eax, DWORD PTR [ebp-16]
  mov DWORD PTR [ebp-12], eax
  mov eax, DWORD PTR [ebp-20]
  mov DWORD PTR [ebp-16], eax
.check_number_x:
  cmp DWORD PTR [ebp-12], 254
  jle .fib
  mov eax, 1
  xor ebx, ebx        
  int 0x80            
