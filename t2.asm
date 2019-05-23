; t2.asm

section .text
  global _start

_start:
  mov rdi, 1
  mov rsi, 0
lp:
  call inc 
  mov rsi, rdi
  loop lp

inc:
  add rdi, rsi
  ret
