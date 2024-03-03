#ifndef SAFE_ALLOC_H
#define SAFE_ALLOC_H

#include <stdlib.h>

#define MAX_ALLOC 209715200  // 200 Mo


static inline void* safe_malloc(size_t n)
{
    return (n > MAX_ALLOC) ? NULL: malloc(n);
}

static inline void* safe_calloc(size_t n)
{
    return (n > MAX_ALLOC) ? NULL: calloc(n, 1);
}

static inline void* __attribute_warn_unused_result__ safe_realloc(void* ptr, size_t n)
{
    return (n > MAX_ALLOC) ? NULL: realloc(ptr, n);
}

#endif