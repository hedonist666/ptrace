#!/bin/bash

make
./t2 &
./a.out -p `pidof ./t2` -f plus
kill `pidof ./t2`



#nasm -f elf64 -g t2.asm  && ld -m elf_x86_64 -o t2 t2.o
