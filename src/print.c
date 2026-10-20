/* print.c — buffered beacon output */
#include "print.h"
#include "../common/strutil.h"
#include <stdarg.h>

int _vsnprintf(char *buffer, unsigned long size, const char *fmt, va_list args);

static char *buf    __attribute__((section(".data"))); /* pending output */
static unsigned len __attribute__((section(".data"))); /* chars used */
static unsigned cap __attribute__((section(".data"))); /* bytes allocated */

#define FIRST_PICK 512 /* bytes; doubled from here on demand */

/* ensure room for n more chars plus a slack byte; 0 on alloc failure */
static int reserve(unsigned n)
{
    unsigned want = len + n + 1;
    unsigned newcap;
    char *nb;
    unsigned i;

    if (buf && want <= cap)
        return 1;
    newcap = cap ? cap : FIRST_PICK;
    while (newcap < want)
        newcap *= 2;
    nb = (char *)mem_alloc((size_t)newcap);
    if (!nb)
        return 0;
    for (i = 0; i < len; i++)
        nb[i] = buf[i];
    mem_free(buf);
    buf = nb;
    cap = newcap;
    return 1;
}

void internal_printf(const char *fmt, ...)
{
    va_list args;
    int need;

    va_start(args, fmt);
    need = _vsnprintf(0, 0, fmt, args); /* size query pass */
    va_end(args);
    if (need < 0)
        return; /* encoding failure; drop the fragment */
    if (!reserve((unsigned)need))
        return;
    va_start(args, fmt);
    _vsnprintf(buf + len, (unsigned long)(cap - len), fmt, args);
    va_end(args);
    len += (unsigned)need;
}

void printoutput(int type)
{
    if (len)
        BeaconOutput(type, buf, (int)len);
    mem_free(buf);
    buf = 0;
    len = 0;
    cap = 0;
}
