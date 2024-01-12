#include <stdlib.h>
#include <assert.h>

#include "memhook.h"

void *(*mem_alloc)(size_t size) = malloc;
void *(*mem_realloc)(void *ptr, size_t size) = realloc;
void (*mem_free)(void *ptr) = free;


void mem_set_hook(
	void *(*alloc_fn)(size_t size),
	void *(*realloc_fn)(void *ptr, size_t size),
	void (*free_fn)(void *ptr))
{
	assert(NULL != alloc_fn);
	assert(NULL != realloc_fn);
	assert(NULL != free_fn);

	mem_alloc = alloc_fn;
	mem_realloc = realloc_fn;
	mem_free = free_fn;
}
