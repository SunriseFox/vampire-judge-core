#include <iostream>
#include <unistd.h>
#include <sys/syscall.h>

using namespace std;

int main() {
  for (int i = 0; i < 100 * 10000; i++) {
    syscall(-1, NULL);
  }
}