#ifndef SAFE_ALLOC_H
#define SAFE_ALLOC_H

#include <stddef.h>

void* safe_malloc(size_t n);

void* safe_calloc(size_t n);

void* __attribute_warn_unused_result__ safe_realloc(void* ptr, size_t n);

void safe_free(void* ptr);

#endif