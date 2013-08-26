#ifndef __XALLOC_H
#define __XALLOC_H

#include <stdlib.h>
#include <string.h>

void *xalloc(size_t size);
char *xstrndup(const char *s, size_t n);
void *xrealloc(void *buffer, size_t size);

static inline char *xstrdup(const char *s) {
	return xstrndup(s, strlen(s));
}

#endif  /* __XALLOC_H */
