/*
 * Copyright (c) 2018 Gabriel López <gabilm@um.es>, Rafael Marín <rafa@um.es>, Fernando Pereñiguez <fernando.pereniguez@cud.upct.es> 
 *
 * This file is part of cfgipsec2.
 *
 * cfgipsec2 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cfgipsec2 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */




#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include "log.h"

int verbose_level = 1;

void
set_verbose_level(int level) {

	verbose_level = level;
}

int get_verbose_level() {
    
    return verbose_level;
}


void
ci2log_printf(int priority, const char *fmt, ...)
{
    char *format;
    va_list ap;

    va_start(ap, fmt);
    vsyslog(priority, fmt, ap);
    va_end(ap);

        format = malloc(9 + strlen(fmt) + 2);
        if (!format) {
            fprintf(stderr, "ERROR: Memory allocation failed (%s:%d)", __FILE__, __LINE__);
            return;
        }

        switch (priority) {
        case LOG_ERR:
            sprintf(format, "ERROR: %s\n", fmt);
            break;
        case LOG_INFO:
            sprintf(format, "INFO: %s\n", fmt);
            break;
        case LOG_DEBUG:
            sprintf(format, "DEBUG: %s\n", fmt);
            break;
        default:
            sprintf(format, "UNKNOWN: %s\n", fmt);
            break;
        }

        va_start(ap, fmt);
        vfprintf(stderr, format, ap);
        va_end(ap);

        free(format);

}