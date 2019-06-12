#include "pwn.h"

int main() {
  printf("%x %lx\n", 4097, PAGE_ALIGN_UP(4097));
}
