/* jsonlite.c — see jsonlite.h. Pure C, no CRT, no allocation. */
#include "jsonlite.h"

static int is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static int find_ch(const char *s, int len, char c, int from)
{
    int i;
    for (i = (from < 0 ? 0 : from); i < len; i++)
        if (s[i] == c)
            return i;
    return -1;
}

static int key_at(const char *json, int len, int pos, const char *key, int klen)
{
    int i;
    if (pos < 0 || pos + klen + 2 > len)
        return 0;
    if (json[pos] != '"' || json[pos + 1 + klen] != '"')
        return 0;
    for (i = 0; i < klen; i++)
        if (json[pos + 1 + i] != key[i])
            return 0;
    return 1;
}

/* returns index just past the value starting at from, or -1 if malformed */
static int skip_value(const char *json, int len, int from)
{
    int i = from;
    char open;
    if (from >= len)
        return -1;
    open = json[i];
    if (open == '"') {
        i++;
        while (i < len) {
            if (json[i] == '\\') {
                i += 2; /* may step past end; loop bound re-checks */
                continue;
            }
            if (json[i] == '"')
                return i + 1;
            i++;
        }
        return -1;
    }
    if (open == '{' || open == '[') {
        int depth = 0;
        char close = (open == '{') ? '}' : ']';
        for (; i < len; i++) {
            char c = json[i];
            if (c == '"') { /* skip string with escapes */
                i++;
                while (i < len) {
                    if (json[i] == '\\') {
                        i += 2;
                        continue;
                    }
                    if (json[i] == '"')
                        break;
                    i++;
                }
                if (i >= len)
                    return -1;
                continue;
            }
            if (c == '{' || c == '[')
                depth++;
            else if (c == '}' || c == ']') {
                depth--;
                if (depth == 0 && c == close)
                    return i + 1;
                if (depth < 0)
                    return -1;
            }
        }
        return -1;
    }
    /* bare token: number / true / false / null, ends at , } ] or ws */
    while (i < len && !is_ws(json[i]) && json[i] != ',' && json[i] != '}' &&
           json[i] != ']')
        i++;
    return (i == from) ? -1 : i;
}

int json_find(const char *json, int len, const char *key, json_span *val)
{
    int klen = 0, i;
    if (!json || len <= 0 || !key || !val)
        return 0;
    while (key[klen])
        klen++;
    if (klen == 0)
        return 0;
    for (i = 0; i + klen + 2 <= len; i++) {
        int j, end;
        if (!key_at(json, len, i, key, klen))
            continue;
        j = i + klen + 2;
        while (j < len && is_ws(json[j]))
            j++;
        if (j >= len || json[j] != ':')
            continue;
        j++;
        while (j < len && is_ws(json[j]))
            j++;
        end = skip_value(json, len, j);
        if (end < 0)
            continue;
        val->p = json + j;
        val->len = end - j;
        return 1;
    }
    return 0;
}

int json_string_at(const char *json, int len, int key_pos, json_span *out)
{
    int colon, open, close;
    if (!json || !out || key_pos < 0 || key_pos >= len)
        return 0;
    colon = find_ch(json, len, ':', key_pos);
    if (colon < 0)
        return 0;
    open = find_ch(json, len, '"', colon + 1);
    /* guard window colon+10 mirrors Program.cs:791 */
    if (open < 0 || open > colon + 10)
        return 0;
    close = open + 1;
    while (close < len) {
        if (json[close] == '"' && json[close - 1] != '\\')
            break;
        close++;
    }
    if (close >= len)
        return 0;
    out->p = json + open + 1;
    out->len = close - open - 1;
    return 1;
}

int json_array_iter(const char *json, int len, const char *key, json_iter *it,
                    json_span *elem)
{
    int p, end;
    json_span v;
    if (!json || !it || !elem || len <= 0)
        return 0;
    if (!it->started) {
        if (!json_find(json, len, key, &v))
            return 0;
        if (v.len < 1 || v.p[0] != '[')
            return 0;
        it->began = (int)(v.p + 1 - json);
        it->pos = it->began;
        it->started = 1;
    }
    p = it->pos;
    while (p < len && is_ws(json[p]))
        p++;
    if (p >= len)
        return 0;
    if (json[p] == ']') {
        it->pos = p + 1;
        return 0;
    }
    end = skip_value(json, len, p);
    if (end < 0)
        return 0;
    elem->p = json + p;
    elem->len = end - p;
    p = end;
    while (p < len && is_ws(json[p]))
        p++;
    if (p < len && json[p] == ',')
        p++;
    it->pos = p;
    return 1;
}
