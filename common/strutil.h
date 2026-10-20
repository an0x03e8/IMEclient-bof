/* strutil.h — string helpers */
#ifndef IMEBOF_STRUTIL_H
#define IMEBOF_STRUTIL_H

#include <stddef.h>
#include "winlean.h"

void *mem_alloc(size_t n);
void  mem_free(void *p);

int str_wlen(const wchar_t *s);

int utf16_to_utf8(const wchar_t *s, int len, char **out);
int utf8_to_utf16(const char *s, int bytes, wchar_t **out);

wchar_t *str_dup(const wchar_t *s);
wchar_t *str_cat(const wchar_t *a, const wchar_t *b);

wchar_t *guid_to_str(const unsigned char guid[16], wchar_t *out);
int guid_from_str(const wchar_t *s, unsigned char out[16]);

#endif