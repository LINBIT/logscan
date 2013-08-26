#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "error.h"

void fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
	exit(1);
}
