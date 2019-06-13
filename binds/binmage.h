#include <signal.h>
#include <stdbool.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/user.h>

#define STACK_DATA 256
#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) (PAGE_ALIGN(x) + PAGE_SIZE)
#define WORD_ALIGN(x) ((x+7) & ~7)
#define DO_CHECKS


typedef struct Break {
  Elf64_Addr addr;
  long orig;
  struct Break* prev;
} Break;

typedef struct handle {
  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr;
  Elf64_Shdr *shdr;

  struct stat st;

  bool running;
  int status;

  pid_t pid;

  Break* bp;

  uint8_t* mem;

  struct user_regs_struct pt_reg;
  char* exec;
} binar_t;


int pid_write(int, void*, const void*, size_t);
int pid_read(int, void*, void*, size_t);


Elf64_Addr lookup_symbol(binar_t*, const char*);
//void print_regs(struct user_regs_struct);
void wrt_sym(binar_t*, int, long);
char* get_exe_name(int);
void sighandler(int);
