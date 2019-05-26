#include <signal.h>
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
#define BASE_ADDRESS 0x00100000



typedef enum {
  EXE_MODE,
  PID_MODE
} Mode;

typedef struct handle {
  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr;
  Elf64_Shdr *shdr;
  uint8_t *mem;
  char* symname;
  Elf64_Addr symaddr;
  struct user_regs_struct pt_reg;
  char* exec;
} handle_t;

int vict_pid;

static inline volatile void*
evil_mmap(void*, uint64_t, uint64_t, uint64_t, int64_t, uint64_t)
__attribute__ ( (aligned(8), __always_inline__) );

uint64_t injection_code(void*) __attribute__ ( (aligned(8)) );
uint64_t get_text_base(pid_t);

int pid_write(int, void*, const void*, size_t);
int pid_read(int, void*, void*, size_t);

uint8_t* create_fn_shellcode(void (*fn)(), size_t len);

Elf64_Addr lookup_symbol(handle_t*, const char*);
void print_regs(struct user_regs_struct);
void wrt_sym(handle_t*, int, long);
char* get_exe_name(int);
void sighandler(int);
