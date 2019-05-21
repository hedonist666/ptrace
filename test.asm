;test.asm

section .text
  global _start

_start:
  mov rsi, suka1
  call print_string
  mov rsi, suka2
  call print_string
  xor rdi, rdi
  mov rax, 60
  syscall

print_string:
  mov rax, 1
  mov rdi, 1
  mov rdx, 5
  syscall
  ret

section .data:
  suka1 db "suka1"
  suka2 db "suka2"

