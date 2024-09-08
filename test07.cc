#include "m61.hh"
#include <cassert>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <iostream>
// Check for correct allocation alignment.

int main() {
  double *ptr = (double *)m61_malloc(sizeof(double));
  // std::cout << alignof(std::max_align_t) << " " << alignof(unsigned long
  // long);
  assert((uintptr_t)ptr % alignof(double) == 0);
  assert((uintptr_t)ptr % alignof(unsigned long long) == 0);
  assert((uintptr_t)ptr % alignof(std::max_align_t) == 0);

  char *ptr2 = (char *)m61_malloc(1);
  // std::cout << (uintptr_t)ptr2;
  assert((uintptr_t)ptr2 % alignof(double) == 0);
  assert((uintptr_t)ptr2 % alignof(unsigned long long) == 0);
  assert((uintptr_t)ptr2 % alignof(std::max_align_t) == 0);

  m61_free(ptr);
  m61_free(ptr2);
}
