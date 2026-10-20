/* jsonlite.h — substring JSON extraction over raw (UTF-8) response bodies.*/
#ifndef IMEBOF_JSONLITE_H
#define IMEBOF_JSONLITE_H

typedef struct {
    const char *p; /* start of the span (never NUL-terminated by us) */
    int len;
} json_span;

typedef struct {
    int began;   /* index just past the opening '[' */
    int pos;     /* next scan position */
    int started; /* 0 until the array has been located */
} json_iter;

int json_find(const char *json, int len, const char *key, json_span *val);

int json_string_at(const char *json, int len, int key_pos, json_span *out);

int json_array_iter(const char *json, int len, const char *key,
                    json_iter *it, json_span *elem);

#endif
