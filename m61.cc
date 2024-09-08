#include "m61.hh"
#include <cassert>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <set>
#include <sys/mman.h>

struct m61_memory_buffer {
  char *buffer;
  size_t pos = 0;
  size_t size = 8 << 20; /* 8 MiB */
  m61_statistics stats;
  std::set<void *> freeAllocated;
  std::map<void *, size_t> allocationSizes;
  std::map<void *, size_t> statAllocationSizes;
  std::map<void *, char> boundaryValue;
  m61_memory_buffer();
  ~m61_memory_buffer();
};

static m61_memory_buffer default_buffer;

m61_memory_buffer::m61_memory_buffer() {
  void *buf = mmap(nullptr,    // Place the buffer at a random address
                   this->size, // Buffer should be 8 MiB big
                   PROT_WRITE, // We want to read and write the buffer
                   MAP_ANON | MAP_PRIVATE, -1, 0);
  // We want memory freshly allocated by the OS
  assert(buf != MAP_FAILED);
  this->buffer = (char *)buf;
  memset(&this->stats, 0, sizeof(m61_statistics));
  stats.heap_min = (uintptr_t)buf;
  stats.heap_max = (uintptr_t)buf;
}

m61_memory_buffer::~m61_memory_buffer() { munmap(this->buffer, this->size); }

// I defined this, a = allocation
void *m61_find_free_space(size_t sz) {
  for (void *a : default_buffer.freeAllocated) {
    if (default_buffer.allocationSizes[a] >= sz) {
      default_buffer.freeAllocated.erase(a);
      void *ptr = a;
      return ptr;
    }
    auto aIt = default_buffer.allocationSizes.find(a);
    aIt++;
    if (aIt == default_buffer.allocationSizes.end()) {
      if (default_buffer.pos - default_buffer.allocationSizes[a] + sz <=
          default_buffer.size) {
        void *ptr = a;
        return ptr;
      }
    }
  }
  return nullptr;
}
/// m61_malloc(sz, file, line)
///    Returns a pointer to `sz` bytes of freshly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc may
///    return either `nullptr` or a pointer to a unique allocation.
///    The allocation request was made at source code location `file`:`line`.

void *m61_malloc(size_t sz, const char *file, int line) {
  (void)file, (void)line; // avoid uninitialized variable warnings
                          // Your code here.

  if (default_buffer.pos + sz > default_buffer.size ||
      sz >= SIZE_MAX - default_buffer.pos) {
    // Not enough space left in default buffer for allocation, try to find space
    // in freed memory
    void *ptr = m61_find_free_space(sz);
    if (ptr == nullptr) {
      default_buffer.stats.nfail++;
      default_buffer.stats.fail_size += sz;
      // std::cout << "khrit hna\n";
      return nullptr;
    }
    size_t bufferMovement;
    if (sz % alignof(std::max_align_t) == 0)
      bufferMovement = sz;
    else
      bufferMovement =
          (sz / alignof(std::max_align_t)) * alignof(std::max_align_t) +
          alignof(std::max_align_t);
    if (bufferMovement < default_buffer.allocationSizes[ptr]) {
      void *freePtr = (void *)((unsigned long)ptr + bufferMovement);
      default_buffer.freeAllocated.insert(freePtr);
      default_buffer.allocationSizes[freePtr] =
          default_buffer.allocationSizes[ptr] - bufferMovement;
    }
    default_buffer.allocationSizes[ptr] = bufferMovement;
    default_buffer.freeAllocated.erase(ptr);
    default_buffer.stats.ntotal += 1;
    default_buffer.stats.nactive++;
    default_buffer.stats.total_size += sz;
    default_buffer.statAllocationSizes[ptr] = sz;
    return ptr;
  }
  // Otherwise there is enough space; claim the next `sz` bytes
  default_buffer.stats.ntotal += 1;
  default_buffer.stats.nactive++;
  default_buffer.stats.total_size += sz;
  void *ptr = &default_buffer.buffer[default_buffer.pos];
  default_buffer.stats.heap_max = (uintptr_t)ptr + sz;
  size_t bufferMovement;
  if (sz % alignof(std::max_align_t) == 0)
    bufferMovement = sz;
  else
    bufferMovement =
        (sz / alignof(std::max_align_t)) * alignof(std::max_align_t) +
        alignof(std::max_align_t);
  default_buffer.pos += bufferMovement;
  default_buffer.allocationSizes[ptr] = bufferMovement;
  default_buffer.statAllocationSizes[ptr] = sz;
  default_buffer.stats.active_size += sz;
  unsigned long intptr = (unsigned long)ptr;
  default_buffer.boundaryValue[ptr] = *((char *)intptr + bufferMovement);
  return ptr;
}

/// m61_free(ptr, file, line)
///    Frees the memory allocation pointed to by `ptr`. If `ptr == nullptr`,
///    does nothing. Otherwise, `ptr` must point to a currently active
///    allocation returned by `m61_malloc`. The free was called at location
///    `file`:`line`.

void m61_free(void *ptr, const char *file, int line) {
  // avoid uninitialized variable warnings
  (void)ptr, (void)file, (void)line;

  // Your code here. The handout code does nothing!
  if (ptr == nullptr)
    return;
  if ((unsigned long)ptr < default_buffer.stats.heap_min ||
      (unsigned long)ptr > default_buffer.stats.heap_max) {
    std::cerr << "MEMORY BUG: " << file << ":" << line
              << ": invalid free of pointer " << ptr << ", not in heap\n";
    abort();
  }
  if (default_buffer.allocationSizes.find(ptr) ==
      default_buffer.allocationSizes.end()) {
    std::cerr << "MEMORY BUG: " << file << ":" << line
              << ": invalid free of pointer " << ptr << ", not allocated\n";
    abort();
  }
  if (default_buffer.freeAllocated.find(ptr) !=
      default_buffer.freeAllocated.end()) {
    std::cerr << "MEMORY BUG: " << file << ":" << line
              << ": invalid free of pointer " << ptr << ", double free\n";
    abort();
  }
  char boundaryChar =
      *((char *)((unsigned long)ptr + default_buffer.allocationSizes[ptr]));
  void *boundaryAddr =
      (void *)((unsigned long)ptr + default_buffer.allocationSizes[ptr]);
  if (default_buffer.allocationSizes.find(boundaryAddr) ==
      default_buffer.allocationSizes.end()) {
    if (boundaryChar != default_buffer.boundaryValue[ptr]) {
      std::cerr << "MEMORY BUG: " << file << ":" << line
                << ": detected wild write during free of pointer " << ptr;
      abort();
    }
  }
  default_buffer.stats.nactive--;
  default_buffer.freeAllocated.insert(ptr);
  default_buffer.stats.active_size -= default_buffer.statAllocationSizes[ptr];
  void *ptrToExtend =
      (void *)((unsigned long)ptr + default_buffer.allocationSizes[ptr]);
  if (default_buffer.freeAllocated.find(ptrToExtend) !=
      default_buffer.freeAllocated.end()) {
    default_buffer.allocationSizes[ptr] +=
        default_buffer.allocationSizes[ptrToExtend];
    default_buffer.allocationSizes.erase(ptrToExtend);
    default_buffer.freeAllocated.erase(ptrToExtend);
  }
  auto ptrIt = default_buffer.allocationSizes.find(ptr);
  if (ptrIt != default_buffer.allocationSizes.begin()) {
    --ptrIt;
    if (default_buffer.freeAllocated.find(ptrIt->first) !=
        default_buffer.freeAllocated.end()) {
      ptrIt->second += default_buffer.allocationSizes[ptr];
      default_buffer.allocationSizes.erase(ptr);
      default_buffer.freeAllocated.erase(ptr);
    }
  }
}

/// m61_calloc(count, sz, file, line)
///    Returns a pointer a fresh dynamic memory allocation big enough to
///    hold an array of `count` elements of `sz` bytes each. Returned
///    memory is initialized to zero. The allocation request was at
///    location `file`:`line`. Returns `nullptr` if out of memory; may
///    also return `nullptr` if `count == 0` or `size == 0`.

void *m61_calloc(size_t count, size_t sz, const char *file, int line) {
  // Your code here (not needed for first tests).
  if (sz > (SIZE_MAX - default_buffer.pos) / count) {
    default_buffer.stats.nfail++;
    default_buffer.stats.fail_size = SIZE_MAX;
    return nullptr;
  }
  // handout code
  void *ptr = m61_malloc(count * sz, file, line);
  if (ptr) {
    memset(ptr, 0, count * sz);
  }
  return ptr;
}

/// m61_get_statistics()
///    Return the current memory statistics.

m61_statistics m61_get_statistics() {
  // Your code here.
  // The handout code sets all statistics to enormous numbers.
  return default_buffer.stats;
}

/// m61_print_statistics()
///    Prints the current memory statistics.

void m61_print_statistics() {
  m61_statistics stats = m61_get_statistics();
  printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
         stats.nactive, stats.ntotal, stats.nfail);
  printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
         stats.active_size, stats.total_size, stats.fail_size);
}

/// m61_print_leak_report()
///    Prints a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_print_leak_report() {
  // Your code here.
}
