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
  assert(fd >= 0);

  int r = read(fd, path, 512);
  assert(r >= 0);

  return path;
}

void print_regs(struct user_regs_struct pt_reg) {
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
    "%%rsp: %llx\n", pt_reg.rcx, pt_reg.rdx, pt_reg.rbx, pt_reg.rax, pt_reg.rdi, pt_reg.rsi, pt_reg.r8, pt_reg.r9, pt_reg.r10, pt_reg.r11, pt_reg.r12, pt_reg.r13, pt_reg.r14, pt_reg.r15, pt_reg.rsp);
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
  h = (binar_t*) h;
  if (h->running) {
    ptrace(PTRACE_DETACH, h->pid, NULL, NULL);
  } 
  res = munmap(h->mem, h->st.st_size);

  if (!res) {
    rb_raise(rb_eRuntimeError, "munmap error...");
  }
}



static const struct rb_data_type_struct rb_binar_type = {
  "Nightowl/binar",
  {0, dealloc, 0},
  0, 1488, 0
};


static VALUE allocate(VALUE klass) {
  binar_t* h;

  VALUE obj = TypedData_Make_Struct(klass, binar_t, &rb_binar_type, h);
  memset(h, 0, sizeof(h) );

  return obj;
}


static VALUE initialize(VALUE self, VALUE vic) {
  binar_t* h; 
  TypedData_Get_Struct(self, binar_t, &rb_binar_type, h);

  switch(TYPE(vic)) {
    case T_STRING:
      h->exec = StringValuePtr( vic ); 
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

  int res = fstat(fd, &h->st);
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

  }

  else {

  }
  
}


static VALUE lookup_symbol_wrapper(VALUE self, VALUE sym) {
  
  Check_Type(sym, T_STRING);
  char* s = StringValuePtr(sym);
  binar_t* h;
  TypedData_Get_Struct(self, binar_t, &rb_binar_type, h);
  VALUE res = INT2NUM (lookup_symbol(h, s));
  return res;

}

void Init_binmage() {
  VALUE mod = rb_define_module("Binmage");
  VALUE bin = rb_define_class_under(mod, "Binar", rb_cObject);
  
  rb_define_alloc_func(bin, allocate);

  rb_define_method(bin, "initialize", initialize, 1);
  rb_define_method(bin, "lookup_symbol", lookup_symbol_wrapper, 1);
}
