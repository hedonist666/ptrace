#include "pwn.h"




void main(int argc, char** argv, char** envp) {
  handle_t h;
  int fd;
  int pid, status;
  long trap, orig;
  struct stat st;


  if (argc < 3) {
    printf("usage: %s program function\n", argv[0]);
    exit(0);
  }

  h.exec = strdup (argv[1]);
  printf("PROGRAM BEGIND TRACED: %s\n", h.exec);
  h.symname = strdup (argv[2]);
  printf("FUNCTION BEGIND TRACED: %s\n", h.symname);

  fd = open(h.exec, O_RDONLY); if (fd < 0) { perror("open"); exit(-1); }

  if ( fstat(fd, &st) < 0 ) { perror("fstat"); exit(-1); }

  h.mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0); 
  if (h.mem == MAP_FAILED) { perror("mmap"); exit(-1); }

  if ( strcmp( (char*) h.mem, "\x7f""ELF" ) < 0 ) { printf("%s is not an ELF file\n", h.exec); exit(0); }

  h.ehdr = (Elf64_Ehdr*) h.mem;
  h.phdr = (Elf64_Phdr*) &h.mem[ h.ehdr->e_phoff  ];
  h.shdr = (Elf64_Shdr*) &h.mem[ h.ehdr->e_shoff  ];
  
  if (h.ehdr->e_type != ET_EXEC && h.ehdr->e_type != ET_DYN) {
    printf("%s is not an ELF executable\n", h.exec);
    exit(-1);
  }

  if (h.ehdr->e_shstrndx == 0 || h.ehdr->e_shoff == 0 || h.ehdr->e_shnum == 0) {
    puts("Section header table not found");
    exit(-1);
  }

  h.symaddr = lookup_symbol(&h, h.symname);
  if (h.symaddr == 0) {
    printf("Unable to find symbol: %s not found in %s\n", h.symname, h.exec);
    exit(0);
  }

  printf("Symadddr: 0x%lx\n", h.symaddr);

  close(fd);

  pid = fork(); if (pid < 0) { perror("fork"); exit(-1); }

  if (pid == 0) {
    if (ptrace(PTRACE_TRACEME, pid, NULL, NULL) < 0) { perror("PTRACE_TRACEME"); exit(-1); }
    char* args[2];
    args[0] = h.exec;
    args[1] = NULL;
    execve(h.exec, args, envp);
    exit(0);
  }
  wait(&status);

  printf("Beginning analysis of pid: %d at %lx\n", pid, h.symaddr);

  orig = ptrace(PTRACE_PEEKTEXT, pid, h.symaddr, NULL);
  if (orig < 0) { perror("PTRACE_PEEKTEXT"); exit(-1); }

  trap = (orig & ~0xff) | 0xcc;

  wrt_sym(&h, pid, trap);

trace:
  if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) { perror("PTRACE_CONT"); exit(-1); }
  wait(&status);

  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, &h.pt_reg) < 0) { perror("PTRACE_GETREGS"); exit(-1); }
      printf("\nExecutable %s (pid: %d) has hit breakpoint 0x%lx\n", h.exec, pid, h.symaddr);
      print_regs(h.pt_reg);
      puts("PRESS ANY KEY TO CONTINUE");
      getchar();
      wrt_sym(&h, pid, orig);
      h.pt_reg.rip -= 1;
      if (ptrace(PTRACE_SETREGS, pid, NULL, &h.pt_reg) < 0) {
        perror("PTRACE_SETREGS");
        exit(-1);
      }
      if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) { perror("PTRACE_SINGLESTEP"); exit(-1); }
      wait(NULL);
      wrt_sym(&h, pid, trap);
      goto trace;
  }
  if (WIFEXITED(status)) printf("\nCompleted tracing pid: %d\n", pid);
  exit(0);
}



Elf64_Addr lookup_symbol(handle_t* h, const char* symname) {
  int i, j;
  char* strtab;
  Elf64_Sym* symtab;

  for (i = 0; i < h->ehdr->e_shnum; ++i) {

    if (h->shdr[i].sh_type == SHT_SYMTAB) {

      strtab = (char*) &h->mem[h->shdr[h->shdr[i].sh_link].sh_offset];
      symtab = (Elf64_Sym*) &h->mem[h->shdr[i].sh_offset];

      for (j = 0; j < h->shdr[i].sh_size/sizeof(Elf64_Sym); ++j) {
        
        if (strcmp(&strtab[symtab->st_name], symname) == 0) return (symtab->st_value);
        ++symtab;

      }

    }

  }

  return 0;
}

void print_regs(struct user_regs_struct pt_reg) {
printf(
    "%%rcx: %llx\n"
    "%%rdx: %llx\n"
    "%%rbx: %llx\n"
    "%%rax: %llx\n"
    "%%rdi: %llx\n"
    "%%rsi: %llx\n"    
    "%%r8: %llx\n"
    "%%r9: %llx\n"
    "%%r10: %llx\n"
    "%%r11: %llx\n"
    "%%r12 %llx\n"
    "%%r13 %llx\n"
    "%%r14: %llx\n"
    "%%r15: %llx\n"
    "%%rsp: %llx\n", pt_reg.rcx, pt_reg.rdx, pt_reg.rbx, pt_reg.rax, pt_reg.rdi, pt_reg.rsi, pt_reg.r8, pt_reg.r9, pt_reg.r10, pt_reg.r11, pt_reg.r12, pt_reg.r13, pt_reg.r14, pt_reg.r15, pt_reg.rsp);
}

void wrt_sym(handle_t* h, int pid, long data) {
  if (ptrace(PTRACE_POKETEXT, pid, h->symaddr, data) < 0) { 
    perror("PTRACE_POKETEXT"); 
    exit(-1);
  }
}
