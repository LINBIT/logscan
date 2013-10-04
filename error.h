/*
   Author: Andreas Gruenbacher <agruen@linbit.com>

   Copyright (C) 2013 LINBIT HA-Solutions GmbH, http://www.linbit.com

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   See the COPYING file for details.
*/

#ifndef __ERROR_H
#define __ERROR_H

#include "error.h"

void fatal(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));;

#endif  /* __ERROR_H */
