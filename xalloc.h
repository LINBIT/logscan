/*
   Author: Andreas Gruenbacher <agruen@linbit.com>

   Copyright (C) 2013 LINBIT HA-Solutions GmbH, http://www.linbit.com

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   See the COPYING file for details.
*/

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
