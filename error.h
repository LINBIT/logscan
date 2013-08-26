#ifndef __ERROR_H
#define __ERROR_H

#include "error.h"

void fatal(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));;

#endif  /* __ERROR_H */
