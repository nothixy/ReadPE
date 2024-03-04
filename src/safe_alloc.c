#include <stdlib.h>
#include <stdio.h>
#include "src/safe_alloc.h"

#define MAX_ALLOC 2097152  // 2 Mo
#define MAX_ALLOC_TOTAL (100 * MAX_ALLOC)

static size_t _total_alloc = 0;

void* safe_malloc(size_t n)
{
    if(n > MAX_ALLOC)
        return NULL;
    
    if(_total_alloc + n > MAX_ALLOC_TOTAL)
    {
        return NULL;
    }
        
    size_t* p = (size_t*) malloc(sizeof(size_t) + n);
    if(p == NULL)
    {
        return NULL;
    }
    *p = n;

    _total_alloc += n;

    return p+1;
}

void* safe_calloc(size_t n)
{
    if(n > MAX_ALLOC)
        return NULL;

    if(_total_alloc + n > MAX_ALLOC_TOTAL)
    {
        return NULL;
    }
        
    size_t* p = (size_t*) calloc(sizeof(size_t) + n, 1);
    if(p == NULL)
    {
        return NULL;
    }
    *p = n;

    _total_alloc += n;

    return p+1;
}

void* __attribute_warn_unused_result__ safe_realloc(void* ptr, size_t n)
{
    if(n > MAX_ALLOC)
    {
        safe_free(ptr);
        return NULL;
    }
    
    size_t old = 0;

    if(ptr != NULL)
        old = ((size_t*)ptr)[-1];

    if(_total_alloc - old + n > MAX_ALLOC_TOTAL)
    {
        safe_free(ptr);
        return NULL;
    }

    size_t* p;
    
    if(ptr == NULL)
        p = malloc(sizeof(size_t) + n);
    else
        p = realloc((size_t*)ptr - 1, sizeof(size_t) + n);

    if(p == NULL)
    {
        safe_free(ptr);
        return NULL;
    }
    
    *p = n;

    _total_alloc += n - old;

    return p + 1;
}

void safe_free(void* ptr)
{
    if(ptr == NULL)
    {
        return;
    }
    _total_alloc -= ((size_t*)ptr)[-1];
    free((size_t*)ptr - 1);
}