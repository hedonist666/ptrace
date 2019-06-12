#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/user.h>

int main() {
  struct user_regs_struct u;
  printf("%d\n", sizeof(u));
}
