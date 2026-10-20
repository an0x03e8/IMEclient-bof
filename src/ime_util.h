#ifndef IMEBOF_IME_UTIL_H
#define IMEBOF_IME_UTIL_H

#include "../common/jsonlite.h"
#include "../common/strutil.h"

int su_len(const char *s);
int su_ci_eq(const char *a, const char *b);       /* NUL-terminated both */
int su_ci_nfind(const char *h, int from, int to, const char *needle);
int su_ci_find(const char *h, int hlen, const char *needle);
int su_ci_prefix(const char *s, int slen, const char *prefix);
int su_digits(const char *s); /* nonempty, all '0'..'9', NUL-terminated */

const char *ime_version_pick(const char *csv);
int ime_json_str(const char *json, int len, const char *key, char *out,
                 int outmax);
int ime_odata_action_target(const char *json, int len, const char *action,
                            json_span *out);
char *ime_bof_arg_utf8(char **pp, int *rem);

#endif
