#include "pwn.h"




int main(int argc, char** argv, char** envp) {

/*VARIABLES============================================*/
  int fd;
  Mode m;
  handle_t h;
  int c, res;
  struct stat st;
  long trap, orig;
  int status, pid;
/*=====================================================*/

  if (argc < 5) {
    printf("Usage: %s -e/-p arg -f fname", argv[0]);
    exit(0);
  }

  memset(&h, 0, sizeof(handle_t));
  
/*PARSING ARGUMENTS====================================*/
  while ( ( c = getopt(argc, argv, "f:e:p:") ) != -1 ) {
    switch(c) {
      case 'p':
        vict_pid = atoi(optarg);
        h.exec = get_exe_name(vict_pid);
        m = PID_MODE;
        break;
      case 'e':
        h.exec = strdup(optarg); 
        m = EXE_MODE;
        break;
      case 'f':
        h.symname = strdup(optarg);
        break;
      default:
        puts("unknown option...");
        break;
    }
  }
  if (h.exec == NULL || h.symname == NULL) {
    puts("provide correct arguments pro favor");
    exit(0);
  }
/*=====================================================*/


/*PREPARATION==========================================*/
  signal(SIGINT, sighandler);

  fd = open(h.exec, O_RDONLY);
  assert(fd >= 0);
  
  res = fstat(fd, &st);
  assert(res >= 0);

  h.mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  assert(h.mem != MAP_FAILED);

  h.ehdr = (Elf64_Ehdr*) h.mem;
  h.shdr = (Elf64_Shdr*) &h.mem[ h.ehdr->e_shoff ];
  h.phdr = (Elf64_Phdr*) &h.mem[ h.ehdr->e_phoff ];
/*=====================================================*/


/*SOME CHECKS==========================================*/
  if ( strcmp(h.mem, "\x7f""ELF") < 0 ) {
    printf("%s is not an elf file\n", argv[0]);
    exit(0);
  }
  if ( h.ehdr->e_type != ET_EXEC ) {
    printf("%s is not an executable\n", argv[0]);
    exit(0);
  }
  if (h.ehdr->e_shstrndx == 0 || h.ehdr->e_shoff == 0 || h.ehdr->e_shnum == 0) {
    puts("section headers not founf @_@");
    exit(0);
  }
/*=====================================================*/

  h.symaddr = lookup_symbol(&h, h.symname);
  assert(h.symaddr != 0);

  close(fd);

/*PREPARATION FOR DEBUGGING @_@========================*/
  if (m == EXE_MODE) {
    vict_pid = fork();
    assert(vict_pid >= 0);
    if (vict_pid == 0) {
      res = ptrace(PTRACE_TRACEME, vict_pid, NULL, NULL);
      assert(res >= 0);
      char* args[2];
      args[0] = h.exec;
      argv[1] = NULL;
      execve(h.exec, args, envp);
    }
  }
  else if (m == PID_MODE) {
    res = ptrace(PTRACE_ATTACH, vict_pid, NULL, NULL);
    assert(res >= 0);
  }
  wait(&status);
/*=====================================================*/

  printf("Beginnig analysis of pid: %d at: %s (0x%lx)...\n", vict_pid, h.symname, h.symaddr);


/*SETTING BREAKPOINT===================================*/
  orig = ptrace(PTRACE_PEEKTEXT, vict_pid, h.symaddr, NULL);
  assert(orig >= 0);

  trap = (orig & ~0xff) | 0xcc;

  wrt_sym(&h, vict_pid, trap);
  
/*=====================================================*/

/*ACTUAL DEBUGGING (probably)==========================*/
trace:
  res = ptrace(PTRACE_CONT, vict_pid, NULL, NULL);
  assert(res >= 0);

  wait(&status);
  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
    res = ptrace(PTRACE_GETREGS, vict_pid, NULL, &h.pt_reg);
    assert(res >= 0);
    printf("\n Executable: %s (%d) has hit breakpoint 0x%lx\n", h.exec, vict_pid, h.symaddr);
    print_regs(h.pt_reg);
    puts("Press enter to continue");
    getchar();

    wrt_sym(&h, vict_pid, orig);

    h.pt_reg.rip = h.pt_reg.rip - 1;
    res = ptrace(PTRACE_SETREGS, vict_pid, NULL, &h.pt_reg);
    assert(res >= 0);

    res = ptrace(PTRACE_SINGLESTEP, vict_pid, NULL, NULL);
    assert(res >= 0);
    wait(NULL);
    
    wrt_sym(&h, vict_pid, trap);

    goto trace;
  }
  else if ( WIFEXITED(status) ) {
    printf("Completed tracing pid: %d\n", vict_pid);
    exit(0);
  }
  else {
    puts("child unexpectedly stopped @_@");
    exit(-1);
  }
/*=====================================================*/
  
}





char* get_exe_name(int pid) {
  char cmdline[255];
  char* path = (char*) malloc( 512*sizeof(char) );
  int fd;
  snprintf(cmdline, 255, "/proc/%d/cmdline", pid);
  fd = open(cmdline, O_RDONLY);
  assert(fd >= 0);
  int r = read(fd, path, 512);
  assert(r >= 0);
  return path;
}

void sighandler(int sig) {
  printf("Caught SIGINT: Detaching from %d\n", vict_pid);
  int res = ptrace(PTRACE_DETACH, vict_pid, NULL, NULL);
  assert(res >= 0);
  exit(0);
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
  int res = ptrace(PTRACE_POKETEXT, pid, h->symaddr, data);
  assert(res >= 0);
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
