/*
   Author: Andreas Gruenbacher <agruen@linbit.com>

   Copyright (C) 2013 LINBIT HA-Solutions GmbH, http://www.linbit.com

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   See the COPYING file for details.
*/

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
