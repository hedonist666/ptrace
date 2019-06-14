;test.asm

section .text
  global _start

_start:
  call f1
  call f2
  xor rdi, rdi
  mov rax, 60
  syscall

f1:
  mov rsi, suka1
  call print_string
  ret

f2:
  mov rsi, suka2
  call print_string
  ret

print_string:
  mov rax, 1
  mov rdi, 1
  mov rdx, 5
  syscall
  ret

section .data:
  suka1 db "suka1"
  suka2 db "suka2"

