#include "ime_api.h"
#include "http.h"
#include "ime_util.h"
#include "../common/strutil.h"
#include "print.h"

ime_ctx *ime_ctx_require(void)
{
    ime_ctx *c = ime_ctx_get();
    if (!c) {
        internal_printf("ime: no imeCtx present - run: ime-token; ime-auth");
        printoutput(CALLBACK_ERROR);
    }
    return c;
}

/* str_cat into a, freeing the old a (chain builder) */
static wchar_t *catfree(wchar_t *a, const wchar_t *b)
{
    wchar_t *r = str_cat(a, b);
    mem_free(a);
    return r;
}

/* 16 pseudo-random bytes for the client-request-id header; quality is
 * irrelevant (request correlation only), so tick + counter + address mix. */
static void pseudorandom16(unsigned char *b)
{
    static unsigned counter;
    DWORD t = GetTickCount();
    int i;
    counter++;
    for (i = 0; i < 4; i++)
        b[i] = (unsigned char)(t >> (8 * i));
    b[4] = (unsigned char)counter;
    b[5] = (unsigned char)(counter >> 8);
    b[6] = (unsigned char)(t ^ (counter << 3));
    b[7] = (unsigned char)(t >> 13);
    t = t * 2654435761u + counter;
    for (i = 8; i < 16; i++)
        b[i] = (unsigned char)(t >> ((i % 4) * 8)), t = t * 1103515245u + 12345u;
}

wchar_t *ime_api_service_params(const ime_ctx *c, const wchar_t *ver)
{
    /* order mirrors BuildQueryParams; the fixed tail is one literal */
    wchar_t *p = str_cat(L"api-version=", ver ? ver : L"9.0");
    p = catfree(p, L"&ssp=WindowsSSP&ssp-version=11.2.1753.0&os=Windows"
                   L"&os-version=10.0.26100.0&os-sub=None&arch=x64"
                   L"&mgmt-agent=Mdm");
    if (c->devid && c->devid[0]) {
        p = catfree(p, L"&device-id=");
        p = catfree(p, c->devid);
    }
    return p;
}

wchar_t *ime_api_headers(const ime_ctx *c, int post)
{
    wchar_t *h, g[37];
    unsigned char seed[16];
    if (!c || !c->enrollment)
        return str_dup(L"");
    h = str_cat(L"Authorization: Bearer ", c->enrollment);
    h = catfree(h, L"\r\n");
    if (!post)
        h = catfree(h, L"Accept: application/json; odata=fullmetadata\r\n");
    h = catfree(h, L"Accept-Language: en-US\r\n");
    pseudorandom16(seed);
    guid_to_str(seed, g);
    h = catfree(h, L"client-request-id: ");
    h = catfree(h, g);
    h = catfree(h, L"\r\n");
    if (post)
        h = catfree(h, L"Content-Type: application/json\r\n");
    return h;
}

wchar_t *ime_url_append(const wchar_t *url, const wchar_t *q)
{
    int n = str_wlen(url), i, has_q = 0;
    wchar_t *r1, *r2;
    for (i = 0; i < n; i++)
        if (url[i] == L'?') {
            has_q = 1;
            break;
        }
    r1 = str_cat(url, has_q ? L"&" : L"?");
    if (!r1)
        return 0;
    r2 = str_cat(r1, q);
    mem_free(r1);
    return r2;
}

static int call_json(const ime_ctx *c, int post, const wchar_t *ver,
                     const wchar_t *url, const char *body, char **out,
                     DWORD *status)
{
    wchar_t *params = ime_api_service_params(c, ver);
    wchar_t *full = ime_url_append(url, params);
    wchar_t *h = ime_api_headers(c, post);
    int rc;
    mem_free(params);
    rc = post ? http_json(HTTP_POST, full, h, body, out, status)
              : http_json(HTTP_GET, full, h, 0, out, status);
    mem_free(full);
    mem_free(h);
    return rc;
}

int ime_api_get(const ime_ctx *c, const wchar_t *ver, const wchar_t *url,
                char **body, DWORD *status)
{
    return call_json(c, 0, ver, url, 0, body, status);
}

int ime_api_post(const ime_ctx *c, const wchar_t *ver, const wchar_t *url,
                 const char *body, char **resp, DWORD *status)
{
    return call_json(c, 1, ver, url, body, resp, status);
}

int ime_api_list_apps(const ime_ctx *c, const wchar_t *ver, char **body,
                      DWORD *status)
{
    /* ListApplicationsRawAsync(top:100), as in the C# client */
    int rc;
    wchar_t *url = str_cat(c->iwurl, L"/Applications?$top=100&$skip=0");
    if (!url)
        return HTTP_FAIL;
    rc = ime_api_get(c, ver, url, body, status);
    mem_free(url);
    return rc;
}

/* copy the value of response header `name` out of a RAW_HEADERS_CRLF block */
static void header_value(const char *hdrs, const char *name, char *out, int outmax)
{
    int i = su_ci_find(hdrs, su_len(hdrs), name), j, o = 0;
    out[0] = 0;
    if (i < 0)
        return;
    j = i + su_len(name);
    while (hdrs[j] && hdrs[j] != ':')
        j++;
    if (hdrs[j] != ':')
    {
        out[0] = 0;
        return;
    }
    j++;
    while (hdrs[j] == ' ' || hdrs[j] == '\t')
        j++;
    while (hdrs[j] && hdrs[j] != '\r' && hdrs[j] != '\n' && o < outmax - 1)
        out[o++] = hdrs[j++];
    while (o > 0 && (out[o - 1] == ' ' || out[o - 1] == '\t'))
        o--;
    out[o] = 0;
}

void ime_api_negotiate(const ime_ctx *c, wchar_t **ver)
{
    char *body = 0, *hdrs = 0, val[160];
    const char *picked;
    wchar_t *h = ime_api_headers(c, 0);
    DWORD st = 0;
    int rc;

    *ver = 0;
    val[0] = 0;
    /* OPTIONS against the service root, BuildRequest shape; the C# ignores
     * the status code and reads only the header (NegotiateApiVersionAsync). */
    rc = http_ex(HTTP_OPTIONS, c->iwurl, h, 0, 0, &body, &st, &hdrs);
    mem_free(h);
    (void)rc;
    if (hdrs)
        header_value(hdrs, "api-supported-versions", val, (int)sizeof(val));
    picked = ime_version_pick(val);
    if (utf8_to_utf16(picked, -1, ver) < 0 || !*ver)
        *ver = str_dup(L"9.0");
    if (!*ver)
        return;
    internal_printf("[ime] api-version %s\n", picked);
    mem_free(body);
    mem_free(hdrs);
}

void ime_http_error(const char *who, DWORD status, const char *body)
{
    char head[304];
    int n = 0;
    if (!body)
        body = "";
    while (body[n] && n < 300)
        head[n] = body[n], n++;
    while (n > 0 && (head[n - 1] == '\r' || head[n - 1] == '\n'))
        n--;
    head[n] = 0;
    if (status == 0)
        internal_printf("%s: transport failure\n", who);
    else
        internal_printf("%s: HTTP %u: %s\n", who, status, head);
    printoutput(CALLBACK_ERROR);
}
