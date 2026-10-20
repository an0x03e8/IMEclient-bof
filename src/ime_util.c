/* ime_util.c — see ime_util.h. Pure C: no CRT, no win32, no allocation. */
#include "ime_util.h"

static char ci_char(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

int su_len(const char *s)
{
    int n = 0;
    if (s)
        while (s[n])
            n++;
    return n;
}

int su_ci_eq(const char *a, const char *b)
{
    int i = 0;
    if (!a || !b)
        return a == b;
    for (;;) {
        char ca = a[i], cb = b[i];
        if (!ca || !cb)
            return ca == cb;
        if (ci_char(ca) != ci_char(cb))
            return 0;
        i++;
    }
}

int su_ci_nfind(const char *h, int from, int to, const char *n)
{
    int nl = su_len(n), i;
    if (!h || nl <= 0)
        return -1;
    for (i = from; i + nl <= to; i++) {
        int j, ok = 1;
        for (j = 0; j < nl; j++) {
            if (ci_char(h[i + j]) != ci_char(n[j])) {
                ok = 0;
                break;
            }
        }
        if (ok)
            return i;
    }
    return -1;
}

int su_ci_find(const char *h, int hlen, const char *n)
{
    return su_ci_nfind(h, 0, hlen, n);
}

int su_ci_prefix(const char *s, int slen, const char *pre)
{
    int pl = su_len(pre), i;
    if (slen < pl)
        return 0;
    for (i = 0; i < pl; i++)
        if (ci_char(s[i]) != ci_char(pre[i]))
            return 0;
    return 1;
}

int su_digits(const char *s)
{
    int i = 0;
    if (!s || !s[0])
        return 0;
    while (s[i]) {
        if (s[i] < '0' || s[i] > '9')
            return 0;
        i++;
    }
    return 1;
}

/* ClientSupportedVersions - same set as IntuneRestClient.cs:213. */
static const char CLIENT_VERSIONS_CSV[] =
    "1.1,2.0,2.1,3.0,4.0,6.0,7.0,8.0,8.1,8.2,"
    "9.0,9.1,9.2,9.3,9.4,9.5,9.6,9.7,9.8,9.9,"
    "9.10,9.11,9.12,9.13,9.14,9.15,9.16,9.17,9.18,"
    "9.19,9.20,9.21,9.22,9.23,9.24,9.25,9.26,9.27,"
    "9.28,9.29,9.30,9.31,9.32,9.33,9.34,"
    "10.3,10.4,10.5,10.6,10.7,10.8,10.9,10.10,10.11,"
    "10.12,10.13,10.14,10.15,10.16,10.17,"
    "11.1,11.2,11.3,11.4,11.5,"
    "12.1,12.2,12.3,12.4,12.5,12.6,12.7,12.8,12.9,"
    "13.2,13.3,13.4,13.5,13.6,"
    "14.1,14.2,14.3,14.4,14.5,14.6,14.7,14.8,14.9,"
    "14.10,14.11,14.12,"
    "15.0,15.1,15.2,"
    "16.3,16.4,16.5,16.6,16.7,16.8,"
    "17.0,"
    "18.2,18.3,18.4,18.5,18.6,18.7,18.8,18.9,18.10";

/* is `v` one of the comma-separated tokens of `csv` (trimmed, case-insens)? */
static int csv_has(const char *csv, const char *v)
{
    int n = su_len(csv), i = 0, vl = su_len(v);
    while (i < n) {
        int start, end;
        while (i < n && (csv[i] == ' ' || csv[i] == '\t'))
            i++;
        start = i;
        while (i < n && csv[i] != ',')
            i++;
        end = i;
        i++;
        while (end > start && (csv[end - 1] == ' ' || csv[end - 1] == '\t'))
            end--;
        if (end - start == vl) {
            int j, ok = 1;
            for (j = 0; j < vl; j++)
                if (ci_char(csv[start + j]) != ci_char(v[j])) {
                    ok = 0;
                    break;
                }
            if (ok)
                return 1;
        }
    }
    return 0;
}

static int ver_parse(const char *s, int *maj, int *min)
{
    int m = 0, n = 0, i = 0;
    while (s[i] >= '0' && s[i] <= '9')
        m = m * 10 + (s[i++] - '0');
    if (s[i] != '.')
        return 0;
    i++;
    while (s[i] >= '0' && s[i] <= '9')
        n = n * 10 + (s[i++] - '0');
    if (s[i])
        return 0;
    *maj = m;
    *min = n;
    return 1;
}

const char *ime_version_pick(const char *csv)
{
    static char bestbuf[8]; /* .bss, no reloc; best token, NUL-terminated */
    const char *best = 0;
    int bmaj = -1, bmin = -1;
    int n = su_len(CLIENT_VERSIONS_CSV), i = 0;

    if (!csv || !csv[0])
        return "9.0";
    while (i < n) {
        int start, end, mj, mn, k;
        char tok[8];
        while (i < n && CLIENT_VERSIONS_CSV[i] == ',')
            i++;
        start = i;
        while (i < n && CLIENT_VERSIONS_CSV[i] != ',')
            i++;
        end = i;
        i++;
        if (end - start <= 0 || end - start >= (int)sizeof(tok))
            continue;
        for (k = 0; k < end - start; k++)
            tok[k] = CLIENT_VERSIONS_CSV[start + k];
        tok[end - start] = 0;
        if (!csv_has(csv, tok))
            continue;
        if (!ver_parse(tok, &mj, &mn))
            continue;
        if (!best || mj > bmaj || (mj == bmaj && mn > bmin)) {
            int k2;
            for (k2 = 0; k2 < end - start; k2++)
                bestbuf[k2] = CLIENT_VERSIONS_CSV[start + k2];
            bestbuf[end - start] = 0;
            best = bestbuf; /* NUL-terminated, static, no reloc */
            bmaj = mj;
            bmin = mn;
        }
    }
    return best ? best : "9.0";
}

int ime_json_str(const char *json, int len, const char *key, char *out,
                 int outmax)
{
    json_span v;
    int i, o = 0;
    if (!json_find(json, len, key, &v))
        return -1;
    if (!(v.len >= 2 && v.p[0] == '"' && v.p[v.len - 1] == '"')) {
        /* non-string: raw copy, truncated */
        for (i = 0; i < v.len && o < outmax - 1; i++)
            out[o++] = v.p[i];
        out[o] = 0;
        return o;
    }
    for (i = 1; i < v.len - 1 && o < outmax - 1; i++) {
        char c = v.p[i];
        if (c == '\\' && i + 1 < v.len - 1) {
            char n2 = v.p[++i];
            if (n2 == '"' || n2 == '\\' || n2 == '/')
                c = n2;
            else if (n2 == 'n')
                c = '\n';
            else if (n2 == 'r')
                c = '\r';
            else if (n2 == 't')
                c = '\t';
            else if (n2 == 'b')
                c = '\b';
            else if (n2 == 'f')
                c = '\f';
            else { /* \uXXXX & friends: keep both chars verbatim */
                out[o++] = c;
                if (o >= outmax - 1)
                    break;
                c = n2;
            }
        }
        out[o++] = c;
    }
    out[o] = 0;
    return o;
}

int ime_odata_action_target(const char *json, int len, const char *action,
                            json_span *out)
{
    /* the three probes of Program.cs ExtractODataActionTarget, in order */
    static const char LONGPFX[] =
        "#Microsoft.Services.SystemCenter.IWService.Common.";
    char pat[96];
    int alen = su_len(action), round;
    if (alen > 40 || !json || !out)
        return 0;

    for (round = 0; round < 3; round++) {
        int p = 0, i, idx, s, e, t;
        pat[p++] = '"';
        if (round == 0)
            pat[p++] = '#';
        if (round == 2) {
            /* LONGPFX carries its own leading '#' */
            for (i = 0; LONGPFX[i]; i++)
                pat[p++] = LONGPFX[i];
        }
        for (i = 0; i < alen; i++)
            pat[p++] = action[i];
        pat[p++] = '"';
        pat[p] = 0;

        idx = su_ci_find(json, len, pat);
        if (idx < 0)
            continue;
        s = idx + p;
        e = len < s + 300 ? len : s + 300; /* the 300-char window */
        t = su_ci_nfind(json, s, e, "\"target\"");
        if (t < 0)
            continue;
        if (json_string_at(json, len, t, out))
            return 1; /* raw quoted-string body, exactly like the C# */
    }
    return 0;
}

char *ime_bof_arg_utf8(char **pp, int *rem)
{
    char *p;
    unsigned int blen;
    char *out = 0;

    if (!pp || !*pp || !rem || *rem < 4)
        return 0;
    p = *pp;
    /* CS 4.x bof_pack "Z": length prefix is BIG-endian, payload UTF-16LE
     * (empirical: beacon hexdump 00 00 00 20 + wide "C:\...", totals 330) */
    blen = ((unsigned char)p[0] << 24) | ((unsigned char)p[1] << 16) |
           ((unsigned char)p[2] << 8) | (unsigned char)p[3];
    p += 4;
    *rem -= 4;
    if ((int)blen > *rem)
        return 0;
    /* length covers the wide chars + wide NUL; convert exactly that many */
    if (utf16_to_utf8((const wchar_t *)p, (int)(blen / 2), &out) < 0)
        return 0;
    *pp = p + blen;
    *rem -= (int)blen;
    return out;
}
