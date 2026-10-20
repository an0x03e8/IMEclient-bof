/* http.h — winhttp REST helper for the BOFs */
#ifndef IMEBOF_HTTP_H
#define IMEBOF_HTTP_H

#include "bofapi.h"

enum {
    HTTP_GET     = 0,
    HTTP_POST    = 1,
    HTTP_OPTIONS = 2
};

/* result codes */
#define HTTP_OK   0  /* 2xx */
#define HTTP_ERR  1  /* completed, non-2xx */
#define HTTP_FAIL (-1) /* transport failure before/at response */

int http_json(int method, const wchar_t *url, const wchar_t *req_headers,
              const char *body, char **out_body, DWORD *status);

int http_ex(int method, const wchar_t *url, const wchar_t *req_headers,
            const char *body, int body_len, char **out_body, DWORD *status,
            char **out_headers);

#endif
