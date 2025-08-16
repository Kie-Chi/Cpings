/*
    Utilities.
*/

#ifndef _GENERIC_H_
#define _GENERIC_H_

#include "common.h"
#include "arena.h"

struct link {
    struct link* next;
};

void link_append(struct link* link, struct link* new_link);

size_t link_length(struct link* link);

void link_free(struct link* link);

void* alloc_memory(size_t size);
void *arena_alloc_memory(Arena *a, size_t size_bytes);

void nsleep(long nsec);

unsigned int strtok_ex(char** out, size_t outbuf_len, char* s, char* delim);

void* _memmem(const void* haystack, size_t haystacklen,const void* needle, size_t needlelen);

char *_strdup(const char *s);

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#endif // !_GENERIC_H_
