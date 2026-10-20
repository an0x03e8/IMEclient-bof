/* http.c — winhttp GET/POST/OPTIONS */
#include "http.h"
#include "../common/strutil.h"

/* ---- winhttp imports (BOF convention: hand-declared) --------------- */
typedef void *HINTERNET_;

#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY 0
#define WINHTTP_FLAG_SECURE               0x00800000u
#define WINHTTP_ADDREQ_FLAG_ADD           0x20000000u
#define WINHTTP_QUERY_STATUS_CODE         19
#define WINHTTP_QUERY_RAW_HEADERS_CRLF    22
#define WINHTTP_QUERY_FLAG_NUMBER         0x20000000u
#define INTERNET_SCHEME_HTTPS             2

typedef struct {
    DWORD dwStructSize;
    wchar_t *lpszScheme;    DWORD dwSchemeLength;
    int nScheme;
    wchar_t *lpszHostName;  DWORD dwHostNameLength;
    int nPort;
    wchar_t *lpszUserName;  DWORD dwUserNameLength;
    wchar_t *lpszPassword;  DWORD dwPasswordLength;
    wchar_t *lpszUrlPath;   DWORD dwUrlPathLength;
    wchar_t *lpszExtraInfo; DWORD dwExtraInfoLength;
} url_components;

DECLSPEC_IMPORT HINTERNET_ WINAPI WinHttpOpen(const wchar_t *agent, DWORD access,
                                              const wchar_t *proxy,
                                              const wchar_t *bypass, DWORD flags);
DECLSPEC_IMPORT int WINAPI WinHttpSetTimeouts(HINTERNET_ h, int resolve, int connect,
                                              int send, int receive);
DECLSPEC_IMPORT HINTERNET_ WINAPI WinHttpConnect(HINTERNET_ h, const wchar_t *host,
                                                 unsigned short port, DWORD reserved);
DECLSPEC_IMPORT HINTERNET_ WINAPI WinHttpOpenRequest(HINTERNET_ hConnect,
                                                     const wchar_t *verb,
                                                     const wchar_t *object,
                                                     const wchar_t *version,
                                                     const wchar_t *referer,
                                                     const wchar_t **accept_types,
                                                     DWORD flags);
DECLSPEC_IMPORT int WINAPI WinHttpAddRequestHeaders(HINTERNET_ h, const wchar_t *headers,
                                                    DWORD len, DWORD modifiers);
DECLSPEC_IMPORT int WINAPI WinHttpSendRequest(HINTERNET_ h, const wchar_t *hdrs,
                                              DWORD hdrs_len, void *optional,
                                              DWORD optional_len, DWORD total_len,
                                              unsigned long long context);
DECLSPEC_IMPORT int WINAPI WinHttpReceiveResponse(HINTERNET_ h, void *reserved);
DECLSPEC_IMPORT int WINAPI WinHttpQueryDataAvailable(HINTERNET_ h, DWORD *available);
DECLSPEC_IMPORT int WINAPI WinHttpReadData(HINTERNET_ h, void *buffer, DWORD to_read,
                                           DWORD *read);
DECLSPEC_IMPORT int WINAPI WinHttpQueryHeaders(HINTERNET_ h, DWORD info, DWORD name,
                                               void *buffer, DWORD *len, DWORD *index);
DECLSPEC_IMPORT int WINAPI WinHttpCrackUrl(const wchar_t *url, DWORD len, DWORD flags,
                                           url_components *components);
DECLSPEC_IMPORT int WINAPI WinHttpCloseHandle(HINTERNET_ h);

#define HDR_RESERVE 8 /* slack so terminator fits under either len unit */

/* tiny local mem ops (no CRT; strutil's statics are not exported) */
static void zmem(void *p, unsigned long n)
{
    char *c = (char *)p;
    unsigned long i;
    for (i = 0; i < n; i++)
        c[i] = 0;
}

static void bytes_copy(char *d, const char *s, int n)
{
    int i;
    for (i = 0; i < n; i++)
        d[i] = s[i];
}

static void wide_copy(wchar_t *d, const wchar_t *s, int n)
{
    int i;
    for (i = 0; i < n; i++)
        d[i] = s[i];
}

static void close3(HINTERNET_ a, HINTERNET_ b, HINTERNET_ c)
{
    if (c)
        WinHttpCloseHandle(c);
    if (b)
        WinHttpCloseHandle(b);
    if (a)
        WinHttpCloseHandle(a);
}

static const wchar_t *verb_for(int method)
{
    static const wchar_t GET[] = L"GET";
    static const wchar_t POST[] = L"POST";
    static const wchar_t OPT[] = L"OPTIONS";
    if (method == HTTP_POST)
        return POST;
    if (method == HTTP_OPTIONS)
        return OPT;
    return GET;
}

int http_ex(int method, const wchar_t *url, const wchar_t *req_headers,
            const char *body, int body_len, char **out_body, DWORD *out_status,
            char **out_headers)
{
    static const wchar_t AGENT[] = L"IMEclient-bof/0.1";
    HINTERNET_ hs = 0, hc = 0, hr = 0;
    url_components uc;
    wchar_t *s_scheme = 0, *s_host = 0, *s_path = 0, *s_extra = 0, *object = 0;
    char *buf = 0;
    int total = 0, cap = 8192, ret = HTTP_FAIL;
    DWORD status = 0;

    if (out_body)
        *out_body = 0;
    if (out_headers)
        *out_headers = 0;
    if (out_status)
        *out_status = 0;
    if (!url) {
        if (out_status)
            *out_status = 0xFFFFFFFFu; /* usage error marker */
        return HTTP_FAIL;
    }

    /* --- crack the URL (scheme/host/port/path+query) ---------------------- */
    s_scheme = (wchar_t *)mem_alloc((16 + HDR_RESERVE) * sizeof(wchar_t));
    s_host = (wchar_t *)mem_alloc((512 + HDR_RESERVE) * sizeof(wchar_t));
    s_path = (wchar_t *)mem_alloc((2048 + HDR_RESERVE) * sizeof(wchar_t));
    s_extra = (wchar_t *)mem_alloc((4096 + HDR_RESERVE) * sizeof(wchar_t));
    if (!s_scheme || !s_host || !s_path || !s_extra)
        goto fail_alloc;

    zmem(&uc, sizeof(uc));
    uc.dwStructSize = (DWORD)sizeof(uc);
    uc.lpszScheme = s_scheme;
    uc.dwSchemeLength = 16;
    uc.lpszHostName = s_host;
    uc.dwHostNameLength = 512;
    uc.lpszUrlPath = s_path;
    uc.dwUrlPathLength = 2048;
    uc.lpszExtraInfo = s_extra;
    uc.dwExtraInfoLength = 4096;
    if (!WinHttpCrackUrl(url, (DWORD)str_wlen(url), 0, &uc))
        goto fail_alloc;

    /* object = path + query */
    {
        int lp = str_wlen(s_path), le = str_wlen(s_extra);
        object = (wchar_t *)mem_alloc(((size_t)lp + le + 1) * sizeof(wchar_t));
        if (!object)
            goto fail_alloc;
        wide_copy(object, s_path, lp);
        wide_copy(object + lp, s_extra, le);
        object[lp + le] = 0;
    }

    /* --- session / request ------------------------------------------------ */
    hs = WinHttpOpen(AGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 0, 0, 0);
    if (!hs)
        goto fail_alloc;
    WinHttpSetTimeouts(hs, 15000, 15000, 15000, 60000); /* resolve/con/send/recv */

    hc = WinHttpConnect(hs, s_host, (unsigned short)uc.nPort, 0);
    if (!hc)
        goto fail_alloc;

    hr = WinHttpOpenRequest(hc, verb_for(method), object, 0, 0, 0,
                            (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hr)
        goto fail_alloc;

    if (req_headers && req_headers[0]) {
        if (!WinHttpAddRequestHeaders(hr, req_headers, (DWORD)str_wlen(req_headers),
                                      WINHTTP_ADDREQ_FLAG_ADD))
            goto fail_alloc;
    }

    {
        DWORD blen = (body && body_len != 0) ? (DWORD)body_len : 0;
        if (!WinHttpSendRequest(hr, 0, 0, (void *)body, blen, blen, 0))
            goto fail_alloc;
    }
    if (!WinHttpReceiveResponse(hr, 0))
        goto fail_alloc;

    /* --- status ----------------------------------------------------------- */
    {
        DWORD code = 0, clen = sizeof(DWORD);
        if (WinHttpQueryHeaders(hr, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                0, &code, &clen, 0))
            status = code;
    }
    if (out_status)
        *out_status = status;

    /* --- response headers (optional, for negotiation) ---------------------- */
    if (out_headers) {
        DWORD hlen = 16384; /* bytes of UTF-16 header block */
        wchar_t *hbuf = (wchar_t *)mem_alloc(40000); /* fits 16KiB as bytes or chars */
        if (hbuf && WinHttpQueryHeaders(hr, WINHTTP_QUERY_RAW_HEADERS_CRLF, 0, hbuf,
                                        &hlen, 0)) {
            char *narrow = 0;
            if (utf16_to_utf8(hbuf, -1, &narrow) >= 0)
                *out_headers = narrow;
        }
        mem_free(hbuf);
    }

    /* --- body: grow-and-read loop ----------------------------------------- */
    buf = (char *)mem_alloc((size_t)cap);
    if (!buf)
        goto fail_alloc;
    for (;;) {
        DWORD avail = 0, got = 0;
        if (!WinHttpQueryDataAvailable(hr, &avail) || avail == 0)
            break;
        if (total > (8 << 20)) /* sanity cap: 8 MB */
            break;
        if (total + (int)avail + 1 > cap) {
            char *nb;
            while (total + (int)avail + 1 > cap)
                cap *= 2;
            nb = (char *)mem_alloc((size_t)cap);
            if (!nb)
                goto fail_alloc;
            bytes_copy(nb, buf, total);
            mem_free(buf);
            buf = nb;
        }
        if (!WinHttpReadData(hr, buf + total, avail, &got) || got == 0)
            break;
        total += (int)got;
    }
    buf[total] = 0;
    if (out_body)
        *out_body = buf;
    else
        mem_free(buf);
    buf = 0;

    ret = (status >= 200 && status <= 299) ? HTTP_OK : HTTP_ERR;
    goto done;

fail_alloc:
    ret = HTTP_FAIL;
    if (out_status)
        *out_status = 0;

done:
    mem_free(buf);
    mem_free(object);
    mem_free(s_scheme);
    mem_free(s_host);
    mem_free(s_path);
    mem_free(s_extra);
    close3(hs, hc, hr);
    return ret;
}

int http_json(int method, const wchar_t *url, const wchar_t *req_headers,
              const char *body, char **out_body, DWORD *status)
{
    int len = -1; /* NUL-terminated convention */
    if (body) {
        const char *p = body;
        len = 0;
        while (p[len])
            len++;
    }
    return http_ex(method, url, req_headers, body, len, out_body, status, 0);
}
