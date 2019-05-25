; t2.asm

section .text
  global _start

_start:
  mov rdi, 0
  mov rsi, 0
  push 0x1488
lp:
  inc rsi
  call plus
  jmp lp

plus:
  add rdi, rsi
  ret
