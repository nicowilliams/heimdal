/*
 * Copyright (c) 2011 James E. Ingram
 * Copyright (c) 2024 Heimdal Project
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 * Implementation of the getdelim() function from POSIX 2008.
 *
 * getdelim() reads from a stream until a specified delimiter is encountered.
 *
 * See: http://pubs.opengroup.org/onlinepubs/9699919799/functions/getdelim.html
 *
 * NOTE: It is always the caller's responsibility to free the line buffer, even
 * when an error occurs.
 */

#include <config.h>

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "roken.h"

#ifndef SSIZE_MAX
#define SSIZE_MAX ((ssize_t)(SIZE_MAX / 2))
#endif

#define GETDELIM_MINLEN 16       /* minimum line buffer size */
#define GETDELIM_MAXLEN 65536    /* maximum line buffer size */

#ifndef HAVE_GETDELIM

ROKEN_LIB_FUNCTION ssize_t ROKEN_LIB_CALL
getdelim(char **lineptr, size_t *n, int delimiter, FILE *stream)
{
    char *buf, *pos;
    int c;
    ssize_t bytes;
    size_t read;

    if (lineptr == NULL || n == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (stream == NULL) {
        errno = EBADF;
        return -1;
    }


    /* read characters until delimiter is found, end of file is reached, or an
       error occurs. */
    read = 0;
    bytes = 0;
    buf = *lineptr;
    pos = buf;
    while ((c = getc(stream)) != EOF) {
        if (bytes + 1 >= SSIZE_MAX) {
            errno = ERANGE;
            return -1;
        }
        read++;
        bytes++;
        if (*n < GETDELIM_MINLEN || read >= *n - 2 /* 1 for the delimiter, one for a NUL */) {
            size_t newsz = *n + (GETDELIM_MINLEN + ((*n) >> 1));

            /*
             * Better than an overflow check like (size_t)SSIZE_MAX - newsz <
             * newsz.  Obviously we assume larger than 16-bit architectures.
             */
            if (newsz > GETDELIM_MAXLEN) {
                errno = ERANGE;
                return -1;
            }
            buf = realloc(*lineptr, newsz);
            if (buf == NULL) {
                /* ENOMEM */
                return -1;
            }
            *n = newsz;
            pos = buf + bytes - 1;
            *lineptr = buf;
        }

        *pos++ = (char)c;
        if (c == delimiter) {
            *pos = '\0';
            return bytes;
        }
    }

    if (ferror(stream) || (feof(stream) && (bytes == 0))) {
        /* EOF, or an error from getc(). */
        return -1;
    }

    *pos = '\0';
    return bytes;
}

#endif /* !HAVE_GETDELIM */
