#ifndef IMEBOF_IME_API_H
#define IMEBOF_IME_API_H

#include "bofapi.h"
#include "imectx.h"

/* ime_ctx_get + the standard error line; NULL when ime_auth has not run. */
ime_ctx *ime_ctx_require(void);

/* "{service params}" of IntuneRestClient BuildQueryParams, wide:
 * api-version=<ver>&ssp=..&ssp-version=..&os=..&os-version=..&os-sub=..
 * &arch=x64&mgmt-agent=Mdm[&device-id=<devid>] */
wchar_t *ime_api_service_params(const ime_ctx *c, const wchar_t *ver);

/* Request headers. GET/OPTIONS shape = BuildRequest (Authorization, Accept
 * fullmetadata, Accept-Language, client-request-id). POST shape =
 * PostActionAsync (Authorization, Accept-Language, client-request-id,
 * Content-Type: application/json - no Accept odata). */
wchar_t *ime_api_headers(const ime_ctx *c, int post);

/* url + ('?' | '&') + q */
wchar_t *ime_url_append(const wchar_t *url, const wchar_t *q);

/* The four calls. `ver` comes from ime_api_negotiate. GET/POST append the
 * service params (device-id included), mirroring GetAsync/PostActionAsync. */
int ime_api_get(const ime_ctx *c, const wchar_t *ver, const wchar_t *url,
                char **body, DWORD *status);
int ime_api_post(const ime_ctx *c, const wchar_t *ver, const wchar_t *url,
                 const char *body, char **resp, DWORD *status);
int ime_api_list_apps(const ime_ctx *c, const wchar_t *ver, char **body,
                      DWORD *status);

/* OPTIONS <iwurl> + api-supported-versions parse (port of
 * NegotiateApiVersionAsync). Never fails: falls back to "9.0" like the C#,
 * transport trouble included (the subsequent call then fails visibly).
 * *ver is a heap wide string (small leak per invocation, beacon-lifetime). */
void ime_api_negotiate(const ime_ctx *c, wchar_t **ver);

/* Standard error print: "<who>: HTTP <status>: <body head 300>" — always
 * print status+body on failure. */
void ime_http_error(const char *who, DWORD status, const char *body);

#endif /* IMEBOF_IME_API_H */
