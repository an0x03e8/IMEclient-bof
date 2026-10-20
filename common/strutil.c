/* strutil.c — see strutil.h. No CRT: loops only, plus the winlean imports. */
#include "strutil.h"

void *mem_alloc(size_t n)
{
    return n ? (void *)LocalAlloc(0, n) : 0;
}

void mem_free(void *p)
{
    if (p)
        LocalFree(p);
}

int str_wlen(const wchar_t *s)
{
    int n = 0;
    if (!s)
        return 0;
    while (s[n])
        n++;
    return n;
}

static void wcopy(wchar_t *dst, const wchar_t *src, int n)
{
    int i;
    for (i = 0; i < n; i++)
        dst[i] = src[i];
}

int utf16_to_utf8(const wchar_t *s, int len, char **out)
{
    int n;
    if (!out)
        return -1;
    *out = 0;
    if (!s)
        return -1;
    if (len < 0)
        len = str_wlen(s);
    if (len == 0) {
        *out = (char *)mem_alloc(1);
        if (!*out)
            return -1;
        (*out)[0] = 0;
        return 0;
    }
    n = WideCharToMultiByte(CP_UTF8, 0, s, len, 0, 0, 0, 0);
    if (n <= 0)
        return -1;
    *out = (char *)mem_alloc((size_t)n + 1);
    if (!*out)
        return -1;
    n = WideCharToMultiByte(CP_UTF8, 0, s, len, *out, n, 0, 0);
    if (n <= 0) {
        mem_free(*out);
        *out = 0;
        return -1;
    }
    (*out)[n] = 0;
    return n;
}

int utf8_to_utf16(const char *s, int bytes, wchar_t **out)
{
    int n;
    if (!out)
        return -1;
    *out = 0;
    if (!s)
        return -1;
    if (bytes < 0) {
        bytes = 0;
        while (s[bytes])
            bytes++;
    }
    if (bytes == 0) {
        *out = (wchar_t *)mem_alloc(sizeof(wchar_t));
        if (!*out)
            return -1;
        (*out)[0] = 0;
        return 0;
    }
    n = MultiByteToWideChar(CP_UTF8, 0, s, bytes, 0, 0);
    if (n <= 0)
        return -1;
    *out = (wchar_t *)mem_alloc(((size_t)n + 1) * sizeof(wchar_t));
    if (!*out)
        return -1;
    n = MultiByteToWideChar(CP_UTF8, 0, s, bytes, *out, n);
    if (n <= 0) {
        mem_free(*out);
        *out = 0;
        return -1;
    }
    (*out)[n] = 0;
    return n;
}

wchar_t *str_dup(const wchar_t *s)
{
    int n;
    wchar_t *r;
    if (!s)
        return 0;
    n = str_wlen(s);
    r = (wchar_t *)mem_alloc(((size_t)n + 1) * sizeof(wchar_t));
    if (!r)
        return 0;
    wcopy(r, s, n);
    r[n] = 0;
    return r;
}

wchar_t *str_cat(const wchar_t *a, const wchar_t *b)
{
    int na, nb;
    wchar_t *r;
    if (!a)
        return str_dup(b);
    if (!b)
        return str_dup(a);
    na = str_wlen(a);
    nb = str_wlen(b);
    r = (wchar_t *)mem_alloc(((size_t)na + nb + 1) * sizeof(wchar_t));
    if (!r)
        return 0;
    wcopy(r, a, na);
    wcopy(r + na, b, nb);
    r[na + nb] = 0;
    return r;
}

static int hexval(wchar_t c)
{
    if (c >= L'0' && c <= L'9')
        return (int)(c - L'0');
    if (c >= L'a' && c <= L'f')
        return (int)(c - L'a') + 10;
    if (c >= L'A' && c <= L'F')
        return (int)(c - L'A') + 10;
    return -1;
}

static const wchar_t HEXD[] = L"0123456789abcdef";

static void put_byte_hex(unsigned char b, wchar_t *dst)
{
    dst[0] = HEXD[(b >> 4) & 0xF];
    dst[1] = HEXD[b & 0xF];
}

wchar_t *guid_to_str(const unsigned char guid[16], wchar_t *out)
{
    int i, p = 0;
    if (!guid || !out)
        return 0;
    /* data1 (4 bytes, printed most significant first = reverse order) */
    for (i = 3; i >= 0; i--) {
        put_byte_hex(guid[i], out + p);
        p += 2;
    }
    out[p++] = L'-';
    for (i = 1; i >= 0; i--) { /* data2 */
        put_byte_hex(guid[4 + i], out + p);
        p += 2;
    }
    out[p++] = L'-';
    for (i = 1; i >= 0; i--) { /* data3 */
        put_byte_hex(guid[6 + i], out + p);
        p += 2;
    }
    out[p++] = L'-';
    for (i = 8; i < 10; i++) { /* data4, sequential */
        put_byte_hex(guid[i], out + p);
        p += 2;
    }
    out[p++] = L'-';
    for (i = 10; i < 16; i++) {
        put_byte_hex(guid[i], out + p);
        p += 2;
    }
    out[36] = 0;
    return out;
}

int guid_from_str(const wchar_t *s, unsigned char out[16])
{
    unsigned char b[16];
    int n = 0, i;
    if (!s || !out)
        return 1;
    for (; *s; s++) {
        int v = hexval(*s);
        if (v >= 0) {
            if (n >= 32)
                return 1; /* too many digits */
            if (n & 1)
                b[n / 2] = (unsigned char)(b[n / 2] | (unsigned char)v);
            else
                b[n / 2] = (unsigned char)(v << 4);
            n++;
        } else if (*s == L'-' || *s == L'{' || *s == L'}' || *s == L' ' ||
                   *s == L'\t') {
            /* separator */
        } else {
            return 1; /* unexpected character */
        }
    }
    if (n != 32)
        return 1;
    /* string is MSB-first per field; raw layout is little-endian for the
     * first three fields (C# Guid.ToByteArray order) */
    out[0] = b[3]; out[1] = b[2]; out[2] = b[1]; out[3] = b[0];
    out[4] = b[5]; out[5] = b[4];
    out[6] = b[7]; out[7] = b[6];
    for (i = 8; i < 16; i++)
        out[i] = b[i];
    return 0;
}
