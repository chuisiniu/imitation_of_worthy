#ifndef __MEMHOOK_H__
#define __MEMHOOK_H__

#include <stdlib.h>

#include "config.h"

#ifdef USE_MEMHOOK
extern void *(*mem_alloc)(size_t size);
extern void *(*mem_realloc)(void *ptr, size_t size);
extern void (*mem_free)(void *ptr);

void mem_set_hook(
	void *(*mem_alloc)(size_t size),
	void *(*mem_realloc)(void *ptr, size_t size),
	void (*mem_free)(void *ptr));
#else
static void *(*mem_alloc)(size_t size) = malloc;
static void *(*mem_realloc)(void *ptr, size_t size) = realloc;
static void (*mem_free)(void *ptr) = free;
#endif /* USE_MEMHOOK */



#endif
