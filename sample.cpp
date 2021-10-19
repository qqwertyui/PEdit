#include <cstdio>
#include <windows.h>
#include <winnt.h>

int main() {
  int size = sizeof(IMAGE_NT_HEADERS32);

  printf("Minimal size: %d\n", size);
  return 0;
}