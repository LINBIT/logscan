#include <stdio.h>
#include <string.h>
#include "xalloc.h"

void *xalloc(size_t size)
{
	void *buffer;

	buffer = malloc(size);
	if (!buffer) {
		perror("");
		exit(1);
	}
	return buffer;
}

char *xstrndup(const char *s, size_t n)
{
	char *t = strndup(s, n);
	if (!t) {
		perror("");
		exit(1);
	}
	return t;
}

void *xrealloc(void *buffer, size_t size)
{
	buffer = realloc(buffer, size);
	if (!buffer) {
		perror("");
		exit(1);
	}
	return buffer;
}
