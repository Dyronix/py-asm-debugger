section .data
    	even db "Even", 10
    	even_len equ $ - even
    	odd db "Odd", 10
    	odd_len equ $ - odd

section .text
	global _start

_start:
	mov eax, 6	; we should try different numbers
	
	test eax, 1
	jz .even
.odd:
	mov ecx, odd
	mov edx, odd_len
	jmp .print

.even:
	mov ecx, even
	mov edx, even_len

.print:
	mov eax, 4
	mov ebx, 1
	int 0x80

	mov eax, 1
	mov ebx, 0
	int 0x80

