#include "ruby.h"
#include "binmage.h"
#include "extconf.h"


int pid_read(int pid, void* dst, void* src, size_t len) {
  if (len % sizeof(void*)) len = len/sizeof(void*) + 1;
  else len /= sizeof(void*);

  unsigned char* s = (unsigned char*) src;
  unsigned char* d = (unsigned char*) dst;
  unsigned long word;

  for (; len != 0; len -= 1) {
     word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL); 
     if (word == 1) return 1;
     *(long *)d = word;
     d += sizeof(unsigned long);
     s += sizeof(unsigned long);
  }
 
  return 0;
}



char* get_exe_name(int pid) {

  char cmdline[255];
  char* path = (char*) malloc( 512*sizeof(char) );
  int fd;

  snprintf(cmdline, 255, "/proc/%d/cmdline", pid);

  fd = open(cmdline, O_RDONLY);
  if (fd < 0) rb_raise(rb_eRuntimeError, "get_exe_name::open");

  int r = read(fd, path, 512);
  if (r < 0) rb_raise(rb_eRuntimeError, "get_exe_name::read");

  return path;

}

VALUE get_exe_name_wrapper(VALUE self, VALUE pid) {
  Check_Type(pid, T_FIXNUM);
  int p = FIX2INT(pid);
  char* name = get_exe_name(p);
  return rb_str_new_cstr(name);  
}



Elf64_Addr lookup_symbol(binar_t* h, const char* symname) {
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


static void dealloc(void* ptr) {
  binar_t* h;
  int res;
  h = (binar_t*) ptr;
  if (h->running) {
    ptrace(PTRACE_DETACH, h->pid, NULL, NULL);
  } 
  res = munmap(h->mem, h->st.st_size);

  if (!res) {
    rb_raise(rb_eRuntimeError, "munmap error...");
  }
  
}



const struct rb_data_type_struct rb_binar_type = {
  "Nightowl/binar",
  {0, dealloc, 0, },
  0, 1488,
  RUBY_TYPED_FREE_IMMEDIATELY,
};


static VALUE allocate(VALUE klass) {
  binar_t* h;

  VALUE obj = TypedData_Make_Struct(klass, binar_t, &rb_binar_type, h);
  memset(h, 0, sizeof(h) );

  return obj;
}


static VALUE initialize(VALUE self, VALUE vic) {
  binar_t* h; 
  int res, status;
  TypedData_Get_Struct(self, binar_t, &rb_binar_type, h);

  switch(TYPE(vic)) {
    case T_STRING:
      h->exec = strdup( StringValuePtr( vic ) ); 
      h->running = false;
      break;
    case T_FIXNUM:
      h->pid = FIX2INT(vic);
      h->exec = get_exe_name(h->pid);
      h->running = true;
      break;
    default:
      rb_raise(rb_eTypeError, "invalid value");
      break;
  } 
  int fd = open(h->exec, O_RDONLY);
  if (fd < 0) rb_raise(rb_eRuntimeError, "unable to open file");

  res = fstat(fd, &h->st);
  if (res < 0) rb_raise(rb_eRuntimeError, "fstat"); 

  h->mem = mmap(NULL, h->st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (h->mem == MAP_FAILED) rb_raise(rb_eRuntimeError, "mmap");

  h->ehdr = (Elf64_Ehdr*) h->mem;
  h->phdr = (Elf64_Phdr*) &h->mem[h->ehdr->e_phoff];
  h->shdr = (Elf64_Shdr*) &h->mem[h->ehdr->e_shoff];

#ifdef DO_CHECKS
  if ( strcmp(h->mem, "\x7f""ELF") < 0 ) {
    rb_raise(rb_eRuntimeError, "%s is not an elf file\n", h->exec); 
  }
  if ( h->ehdr->e_type != ET_EXEC ) {
    rb_raise(rb_eRuntimeError, "%s is not an executable\n", h->exec); 
  }
  if (h->ehdr->e_shstrndx == 0 || h->ehdr->e_shoff == 0 || h->ehdr->e_shnum == 0) {
    rb_raise(rb_eRuntimeError, "section headers not found @_@"); 
  }
#endif

  if (h->running) {
    res = ptrace(PTRACE_ATTACH, h->pid, NULL, NULL);  
    if (res < 0) rb_raise(rb_eRuntimeError, "unable to attach");
  }

  else {
    h->pid = fork();
    if (h->pid < 0) rb_raise(rb_eRuntimeError, "fork");
    if (h->pid == 0) {
      res = ptrace(PTRACE_TRACEME, h->pid, NULL, NULL);
      if (res < 0) rb_raise(rb_eRuntimeError, "traceme");
      char* args[2];
      args[0] = h->exec;
      args[1] = NULL;
      execve(h->exec, args, NULL); //r u sure?
    }
  }
  wait(&h->status);
  
}

static Break* find_bp(binar_t* h ,long ad) {
  Break* c;
  for (c = h->bp; c->addr != ad; c = c->prev) {
    if (c == NULL) {
      return NULL;
    }
  }
  return c;
}

static VALUE cont(VALUE self) {
  binar_t* h;
  int res;
  TypedData_Get_Struct(self, binar_t, &rb_binar_type, h);


  res = ptrace(PTRACE_CONT, h->pid, NULL, NULL);
  if (res < 0) rb_raise(rb_eRuntimeError, "ptrace_cont");
  wait(&h->status);

  if (WIFSTOPPED(h->status) && WSTOPSIG(h->status) == SIGTRAP) {

    res = ptrace(PTRACE_GETREGS, h->pid, NULL, &h->pt_reg);
    printf("\nExecutable: %s (%d) has hit breakpoint 0x%lx\n", h->exec, h->pid, h->pt_reg.rip);
    Break* bp = find_bp(h, h->pt_reg.rip - 1); 
    if (bp == NULL) rb_raise(rb_eRuntimeError, "something's wrong, real shit @_@");
    
    res = ptrace(PTRACE_POKETEXT, h->pid, bp->addr, bp->orig);

    h->pt_reg.rip = h->pt_reg.rip - 1;
    res = ptrace(PTRACE_SETREGS, h->pid, NULL, &h->pt_reg);
    if (res < 0) rb_raise(rb_eRuntimeError, "cont::setregs");

    res = ptrace(PTRACE_SINGLESTEP, h->pid, NULL, NULL);
    if (res < 0) rb_raise(rb_eRuntimeError, "cont::setregs");

    wait(NULL);
    
    long trap = (bp->orig & ~0xff) | 0xcc;
    res = ptrace(PTRACE_POKETEXT, h->pid, bp->addr, trap);


  }
  else if ( WIFEXITED(h->status) ) {
    printf("\nCompleted tracing pid: %d\n", h->pid);
  }
  else {
    puts("child unexpectedly stopped @_@");
  }

  return Qnil;
}



static VALUE place_break(VALUE self, VALUE address) {
  int a;
  int res;
  long trap;
  binar_t* h;
  TypedData_Get_Struct(self, binar_t, &rb_binar_type, h);

  if (TYPE(address) == T_FIXNUM) {
    a = FIX2LONG(address);
  }
  else if (TYPE(address) == T_STRING) {
    char* s = StringValuePtr(address);
    a = lookup_symbol(h, s);
  }
  else {
    rb_raise(rb_eTypeError, "invalid value");
  }

  Break* p    = h->bp;
  h->bp       = (Break*) malloc(sizeof(Break));
  h->bp->prev = p;
  h->bp->addr = a;
  h->bp->orig = ptrace(PTRACE_PEEKTEXT, h->pid, a, NULL);
  if (h->bp->orig < 0) rb_raise(rb_eRuntimeError, "ptrace_peektext");
  trap = (h->bp->orig & ~0xff) | 0xcc;
  res = ptrace(PTRACE_POKETEXT, h->pid, a, trap);
  if (res < 0) rb_raise(rb_eRuntimeError, "ptrace_poketext");

  return Qnil;
}

static VALUE del_break(VALUE self, VALUE address) {
  int a;
  int res;
  binar_t* h;
  Break* p;
  TypedData_Get_Struct(self, binar_t, &rb_binar_type, h);

  if (TYPE(address) == T_FIXNUM) {
    a = FIX2LONG(address);
  }
  else if (TYPE(address) == T_STRING) {
    char* s = StringValuePtr(address);
    a = lookup_symbol(h, s);
  }
  else {
    rb_raise(rb_eTypeError, "invalid value");
  }


  Break* n;
  for (p = h->bp; p->addr != a; p = p->prev) {
    if (p == NULL) {
      puts("unknown breakpoint");
      return Qnil;
      n = p;
    }
  } 
  
  res = ptrace(PTRACE_POKETEXT, h->pid, p->addr, p->orig);
  if (res < 0) rb_raise(rb_eRuntimeError, "ptrace_poketext");

  n->prev = p->prev;
  free(p);

  return Qnil;

}

static VALUE lookup_symbol_wrapper(VALUE self, VALUE sym) {
  
  char* s;
  binar_t* h;
  int ret;
  VALUE res;

  Check_Type(sym, T_STRING);
  s = StringValuePtr(sym);
  TypedData_Get_Struct(self, binar_t, &rb_binar_type, h);

  ret = lookup_symbol(h, s);
  res = ret ? INT2NUM (ret) : Qnil;
  return res;

}

static VALUE print_breaks(VALUE self) {
  binar_t* h;
  Break* c;
  int i;
  TypedData_Get_Struct(self, binar_t, &rb_binar_type, h);

  for (c = h->bp, i = 1; c != NULL; c = c->prev, ++i) {
    printf("%d: %p\n\n", i, c->addr);
  }
 
  return Qnil;
}


static VALUE print_regs(VALUE self) {
  binar_t* h;
  int res;
  TypedData_Get_Struct(self, binar_t, &rb_binar_type, h);

  res = ptrace(PTRACE_GETREGS, h->pid, NULL, &h->pt_reg);
  if (res < 0) rb_raise(rb_eRuntimeError, "ptrace_poketext");

  printf(
      "%%rcx: %llx\n"
      "%%rdx: %llx\n"
      "%%rbx: %llx\n"
      "%%rax: %llx\n"
      "%%rdi: %llx\n"
      "%%rsi: %llx\n"    
      "%%r8:  %llx\n"
      "%%r9:  %llx\n"
      "%%r10: %llx\n"
      "%%r11: %llx\n"
      "%%r12  %llx\n"
      "%%r13  %llx\n"
      "%%r14: %llx\n"
      "%%r15: %llx\n"
      "%%rsp: %llx\n", h->pt_reg.rcx, h->pt_reg.rdx, h->pt_reg.rbx, h->pt_reg.rax, h->pt_reg.rdi, h->pt_reg.rsi, h->pt_reg.r8, h->pt_reg.r9, h->pt_reg.r10, h->pt_reg.r11, h->pt_reg.r12, h->pt_reg.r13, h->pt_reg.r14, h->pt_reg.r15, h->pt_reg.rsp);

  return Qnil;
}


void Init_binmage() {
  VALUE mod = rb_define_module("Binmage");
  VALUE bin = rb_define_class_under(mod, "Binar", rb_cObject);

  rb_define_method(mod, "get_exe_name", get_exe_name_wrapper, 1);
  
  rb_define_alloc_func(bin, allocate);

  rb_define_method(bin, "initialize", initialize, 1);
  rb_define_method(bin, "lookup_symbol", lookup_symbol_wrapper, 1);
  rb_define_method(bin, "print_regs", print_regs, 0);
  rb_define_method(bin, "continue", cont, 0);
  rb_define_method(bin, "place_breakpoint", place_break, 1);
  rb_define_method(bin, "delete_breakpoint", del_break, 1);
  rb_define_method(bin, "breakpoints", print_breaks, 0);
}
