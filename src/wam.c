/* wam.c — see wam.h. Silent AAD token via the OS broker */
#include "wam.h"
#include "../common/strutil.h"

#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT extern
#endif
#ifndef WINAPI
#define WINAPI
#endif

typedef int HRESULT;

/* ---- GUIDs, verbatim from WamTokenProvider.cs ---------------------------- */
typedef struct {
    unsigned int a;
    unsigned short b, c;
    unsigned char d[8];
} wam_guid;

/* ---- combase.dll (src/combase.def -> $(OBJ)/libcombase.a) ------------- */
DECLSPEC_IMPORT int WINAPI RoInitialize(int threading_model);
DECLSPEC_IMPORT int WINAPI RoUninitialize(void);
DECLSPEC_IMPORT int WINAPI RoGetActivationFactory(void *activatable_class_id,
                                                  const wam_guid *iid,
                                                  void **factory);
DECLSPEC_IMPORT int WINAPI WindowsCreateString(const wchar_t *source_string,
                                               unsigned int length,
                                               void **hstring);
DECLSPEC_IMPORT int WINAPI WindowsDeleteString(void *hstring);
DECLSPEC_IMPORT const wchar_t *WINAPI WindowsGetStringRawBuffer(
    void *hstring, unsigned int *length);

DECLSPEC_IMPORT void WINAPI Sleep(unsigned long ms);

#define RO_INIT_MULTITHREADED 1
#define RO_INIT_FALSE        1 /* S_FALSE: already initialized */
#define RO_INIT_CHANGED_MODE 0x80010106u
#define WAM_EFAIL            0x80004005u /* our shape failures */
#define WAM_ETIMEOUT         0x80004007u /* await hit the 30 s cap */
#define WAM_ECANCELED        0x80004006u /* op reported Canceled */

/* AsyncStatus */
#define AS_STARTED   0
#define AS_COMPLETED 1
#define AS_CANCELED  2
#define AS_ERROR     3

#define WAM_GUID(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7) \
    { a, b, c, { d0, d1, d2, d3, d4, d5, d6, d7 } }

static const wam_guid IID_MGR = /* IWebAuthenticationCoreManagerStatics */
    WAM_GUID(0x6aca7c92u, 0xa581, 0x4479, 0x9c, 0x10, 0x75, 0x2e, 0xff, 0x44, 0xfd, 0x34);
static const wam_guid IID_REQFAC = /* IWebTokenRequestFactory */
    WAM_GUID(0x6cf2141cu, 0x0ff0, 0x4c67, 0xb8, 0x4f, 0x99, 0xdd, 0xbe, 0x4a, 0x72, 0xc9);
static const wam_guid IID_ASYNCINFO = /* IAsyncInfo */
    WAM_GUID(0x00000036u, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);

static const wchar_t AAD_PROVIDER_ID[] = L"https://login.microsoft.com";
static const wchar_t AAD_AUTHORITY_ORG[] = L"organizations";
static const wchar_t AAD_AUTHORITY[] = L"https://login.microsoftonline.com/common";
static const wchar_t CLIENT_ID[] = L"9ba1a5c7-f17a-4de9-a1f1-6178c8d51223";
/* fixed correlation id: diagnostics only, uniqueness not load-bearing */
static const wchar_t CORRELATION_ID[] = L"9ba1a5c7-f17a-4de9-a1f1-6178c8d51224";
static const wchar_t SCOPE_TAIL[] = L" openid offline_access profile";
static const wchar_t REDIRECT_PREFIX[] =
    L"ms-appx-web://Microsoft.AAD.BrokerPlugin/";
static const wchar_t MGR_CLASS[] =
    L"Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager";
static const wchar_t REQFAC_CLASS[] =
    L"Windows.Security.Authentication.Web.Core.WebTokenRequest";

/* ---- vtables (slots per the C# declarations; see file head) -------------- */
typedef struct {
    void *qi, *addref, *rel, *getiids, *getruntimeclassname, *gettrustlevel;
    /* 6 */ int (WINAPI *GetTokenSilentlyAsync)(void *self, void *request,
                                                void **op);
    void *slot7, *slot8, *slot9, *slot10, *slot11;
    /* 12 */ int (WINAPI *FindAccountProviderWithAuthorityAsync)(
        void *self, void *web_account_provider_id, void *authority, void **op);
} wam_vt_mgr;

typedef struct {
    void *qi, *addref, *rel, *getiids, *getruntimeclassname, *gettrustlevel;
    /* 6 */ int (WINAPI *Create)(void *self, void *provider, void *scope,
                                 void *client_id, void **request);
} wam_vt_reqfac;

typedef struct {
    void *qi, *addref, *rel, *getiids, *getruntimeclassname, *gettrustlevel;
    /* 6 */ int (WINAPI *get_WebAccountProvider)(void *self, void **provider);
    /* 7 */ int (WINAPI *get_Scope)(void *self, void **hstr);
    /* 8 */ int (WINAPI *get_ClientId)(void *self, void **hstr);
    /* 9 */ int (WINAPI *get_PromptType)(void *self, int *prompt_type);
    /* 10 */ int (WINAPI *get_Properties)(void *self, void **map);
} wam_vt_req;

typedef struct {
    void *qi, *addref, *rel, *getiids, *getruntimeclassname, *gettrustlevel;
    /* 6 */ int (WINAPI *Lookup)(void *self, void *key, void **value);
    /* 7 */ int (WINAPI *get_Size)(void *self, unsigned int *size);
    /* 8 */ int (WINAPI *HasKey)(void *self, void *key, int *found);
    /* 9 */ int (WINAPI *GetView)(void *self, void **view);
    /* 10 */ int (WINAPI *Insert)(void *self, void *key, void *value,
                                  int *replaced);
} wam_vt_map;

/* IAsyncOperation<T>: completion + result only; IAsyncInfo is a separate
 * QI'd interface (see wam_vt_asyncinfo) — windows.foundation.h ABI. */
typedef struct {
    void *qi, *addref, *rel, *getiids, *getruntimeclassname, *gettrustlevel;
    /* 6 */ int (WINAPI *put_Completed)(void *self, void *handler,
                                        void **cookie);
    /* 7 */ int (WINAPI *get_Completed)(void *self, void **handler);
    /* 8 */ int (WINAPI *GetResults)(void *self, void **results);
} wam_vt_asyncop;

/* QI'd IAsyncInfo (asyncinfo.h): status/error polling happens here */
typedef struct {
    void *qi, *addref, *rel, *getiids, *getruntimeclassname, *gettrustlevel;
    /* 6 */ int (WINAPI *get_Id)(void *self, unsigned int *id);
    /* 7 */ int (WINAPI *get_Status)(void *self, int *status);
    /* 8 */ int (WINAPI *get_ErrorCode)(void *self, unsigned int *error_code);
    /* 9 */ int (WINAPI *Cancel)(void *self);
    /* 10 */ int (WINAPI *Close)(void *self);
} wam_vt_asyncinfo;

typedef struct {
    void *qi, *addref, *rel, *getiids, *getruntimeclassname, *gettrustlevel;
    /* 6 */ int (WINAPI *get_ResponseData)(void *self, void **vector);
    /* 7 */ int (WINAPI *get_ResponseStatus)(void *self, int *status);
    /* 8 */ int (WINAPI *get_ResponseError)(void *self, void **error);
} wam_vt_result;

typedef struct {
    void *qi, *addref, *rel, *getiids, *getruntimeclassname, *gettrustlevel;
    /* 6 */ int (WINAPI *GetAt)(void *self, unsigned int index, void **item);
    /* 7 */ int (WINAPI *get_Size)(void *self, unsigned int *size);
} wam_vt_vecview;

typedef struct {
    void *qi, *addref, *rel, *getiids, *getruntimeclassname, *gettrustlevel;
    /* 6 */ int (WINAPI *get_Token)(void *self, void **hstr);
    /* 7 */ int (WINAPI *get_ProviderError)(void *self, void **error);
    /* 8 */ int (WINAPI *get_WebAccount)(void *self, void **account);
} wam_vt_tokenresp;

typedef struct {
    void *qi, *addref, *rel, *getiids, *getruntimeclassname, *gettrustlevel;
    /* 6 */ int (WINAPI *get_ErrorCode)(void *self, unsigned int *code);
    /* 7 */ int (WINAPI *get_ErrorMessage)(void *self, void **hstr);
} wam_vt_proverr;

/* ---- helpers -------------------------------------------------------------- */
#define VT(obj, type) ((type *)(*(void **)(obj)))

/* release via the shared IUnknown slot; NULL-tolerant */
static void rel(void *obj)
{
    if (obj) {
        int (WINAPI *rl)(void *) =
            (int (WINAPI *)(void *))VT(obj, wam_vt_asyncinfo)->rel;
        (void)rl(obj);
    }
}

static int hstr(const wchar_t *s, void **out)
{
    return WindowsCreateString(s, (unsigned int)str_wlen(s), out);
}

static void hstr_free(void *h)
{
    if (h)
        WindowsDeleteString(h);
}

/* Poll an IAsyncOperation to Completed. 0 on completion, else the failing
 * HRESULT (QI error, the op's ErrorCode on AS_ERROR, WAM_EFAIL on
 * cancel/timeout). Status lives on the QI'd IAsyncInfo, not the op vtable. */
static int await(void *op)
{
    wam_vt_asyncinfo *ai;
    void *info = 0;
    int st = AS_STARTED, rc;
    unsigned int elapsed = 0, ec = 0;
    int (WINAPI *qi)(void *, const wam_guid *, void **) =
        (int (WINAPI *)(void *, const wam_guid *, void **))
            VT(op, wam_vt_asyncop)->qi;
    HRESULT hr = qi(op, &IID_ASYNCINFO, &info);

    if (hr)
        return (int)hr;
    ai = VT(info, wam_vt_asyncinfo);
    for (;;) {
        hr = ai->get_Status(info, &st);
        if (hr) {
            rc = (int)hr;
            goto out;
        }
        if (st == AS_COMPLETED) {
            rc = 0;
            goto out;
        }
        if (st == AS_ERROR) {
            rc = ai->get_ErrorCode(info, &ec) == 0 && ec ? (int)ec
                                                         : (int)WAM_EFAIL;
            goto out;
        }
        if (st == AS_CANCELED) {
            rc = WAM_ECANCELED;
            goto out;
        }
        if (elapsed >= WAM_TIMEOUT_MS) {
            rc = WAM_ETIMEOUT;
            goto out;
        }
        Sleep(50);
        elapsed += 50;
    }
out:
    rel(info);
    return rc;
}

/* Copy an HSTRING to a fresh wide heap block (caller mem_free). */
static int hstr_dup_wide(void *h, wchar_t **out)
{
    unsigned int len = 0;
    const wchar_t *raw;
    wchar_t *cpy;
    unsigned int i;

    raw = WindowsGetStringRawBuffer(h, &len);
    if (!raw)
        return WAM_EFAIL;
    cpy = (wchar_t *)mem_alloc(((size_t)len + 1) * sizeof(wchar_t));
    if (!cpy)
        return WAM_EFAIL;
    for (i = 0; i < len; i++)
        cpy[i] = raw[i];
    cpy[len] = 0;
    *out = cpy;
    return 0;
}

/* The request properties, verbatim from WamTokenProvider.GetTokenSilentlyAsync
 * (wam_compat 2.0 / authority / redirect_uri / correlationId). */
static int set_props(void *request)
{
    wam_vt_map *map;
    void *mobj = 0;
    wchar_t *redirect = 0;
    struct { const wchar_t *k, *v; } kv[4];
    int n = 0, i, rc = 0;

    {
        HRESULT hr = VT(request, wam_vt_req)->get_Properties(request, &mobj);
        if (hr)
            return hr;
    }
    map = VT(mobj, wam_vt_map);

    redirect = str_cat(REDIRECT_PREFIX, CLIENT_ID);
    if (!redirect) {
        rc = WAM_EFAIL;
        goto out;
    }
    kv[n].k = L"wam_compat", kv[n].v = L"2.0", n++;
    kv[n].k = L"authority", kv[n].v = AAD_AUTHORITY, n++;
    kv[n].k = L"redirect_uri", kv[n].v = redirect, n++;
    kv[n].k = L"correlationId", kv[n].v = CORRELATION_ID, n++;

    for (i = 0; i < n && rc == 0; i++) {
        void *hk = 0, *hv = 0;
        int replaced = 0;
        HRESULT hr;
        hr = hstr(kv[i].k, &hk);
        if (!hr)
            hr = hstr(kv[i].v, &hv);
        if (!hr)
            hr = map->Insert(mobj, hk, hv, &replaced);
        hstr_free(hk);
        hstr_free(hv);
        if (hr)
            rc = (int)hr;
    }
out:
    mem_free(redirect);
    rel(mobj);
    return rc;
}

/* The whole silent-token run for one scope. On success *out is a heap wide
 * token; on failure *step / *hr say where (see wam.h). */
static int run(const wchar_t *scope_prefix, wchar_t **out, int *step,
               unsigned int *hrout)
{
    void *mgr = 0, *reqfac = 0, *provider = 0, *request = 0;
    void *op_prov = 0, *op_tok = 0, *result = 0, *vec = 0, *item = 0, *tokh = 0;
    wchar_t *scope = 0;
    int rc, owned = 0;
    HRESULT hr;

    *step = WAM_ROINIT;
    hr = RoInitialize(RO_INIT_MULTITHREADED);
    if (hr == (int)RO_INIT_CHANGED_MODE)
        hr = 0; /* someone else owns the apartment; use it as-is */
    else if (hr == (int)RO_INIT_FALSE)
        hr = 0;
    else if (hr == 0)
        owned = 1;
    if (hr)
        goto fail;

    *step = WAM_FACTORY_MGR;
    {
        void *cls = 0;
        hr = hstr(MGR_CLASS, &cls);
        if (!hr)
            hr = RoGetActivationFactory(cls, &IID_MGR, &mgr);
        hstr_free(cls);
    }
    if (hr)
        goto fail;

    *step = WAM_FACTORY_REQ;
    {
        void *cls = 0;
        hr = hstr(REQFAC_CLASS, &cls);
        if (!hr)
            hr = RoGetActivationFactory(cls, &IID_REQFAC, &reqfac);
        hstr_free(cls);
    }
    if (hr)
        goto fail;

    *step = WAM_FINDPROVIDER;
    {
        void *id = 0, *auth = 0;
        hr = hstr(AAD_PROVIDER_ID, &id);
        if (!hr)
            hr = hstr(AAD_AUTHORITY_ORG, &auth);
        if (!hr)
            hr = VT(mgr, wam_vt_mgr)
                     ->FindAccountProviderWithAuthorityAsync(mgr, id, auth,
                                                             &op_prov);
        hstr_free(id);
        hstr_free(auth);
    }
    if (hr)
        goto fail;
    *step = WAM_PROVIDER_RESULT;
    hr = await(op_prov);
    if (!hr)
        hr = VT(op_prov, wam_vt_asyncop)->GetResults(op_prov, &provider);
    if (hr)
        goto fail;

    *step = WAM_CREATE_REQ;
    scope = str_cat(scope_prefix, SCOPE_TAIL);
    if (!scope) {
        rc = WAM_NOMEM;
        goto fail_nohr;
    }
    {
        void *s = 0, *cid = 0;
        hr = hstr(scope, &s);
        if (!hr)
            hr = hstr(CLIENT_ID, &cid);
        if (!hr)
            hr = VT(reqfac, wam_vt_reqfac)
                     ->Create(reqfac, provider, s, cid, &request);
        hstr_free(s);
        hstr_free(cid);
    }
    if (hr)
        goto fail;

    *step = WAM_PROPS;
    rc = set_props(request); /* hr-shaped */
    if (rc)
        goto fail_nohr;

    *step = WAM_GETTOKEN;
    hr = VT(mgr, wam_vt_mgr)->GetTokenSilentlyAsync(mgr, request, &op_tok);
    if (hr)
        goto fail;
    *step = WAM_TOKEN_RESULT;
    hr = await(op_tok);
    if (!hr)
        hr = VT(op_tok, wam_vt_asyncop)->GetResults(op_tok, &result);
    if (hr)
        goto fail;
    {
        int status = -1;
        hr = VT(result, wam_vt_result)->get_ResponseStatus(result, &status);
        if (!hr && status != 0 /* Success */) {
            /* surface the broker's error code when there is one */
            void *perr = 0;
            unsigned int pec = 0;
            if (VT(result, wam_vt_result)->get_ResponseError(result, &perr) ==
                    0 &&
                perr) {
                if (VT(perr, wam_vt_proverr)->get_ErrorCode(perr, &pec) == 0 &&
                    pec)
                    hr = (int)pec;
                rel(perr);
            }
            if (!hr)
                hr = WAM_EFAIL;
        }
        if (!hr)
            hr = VT(result, wam_vt_result)->get_ResponseData(result, &vec);
        if (!hr)
            hr = VT(vec, wam_vt_vecview)->GetAt(vec, 0, &item);
        if (!hr)
            hr = VT(item, wam_vt_tokenresp)->get_Token(item, &tokh);
    }
    if (hr)
        goto fail;
    rc = hstr_dup_wide(tokh, out);
    if (rc)
        goto fail_nohr;

    rel(mgr), rel(reqfac), rel(provider), rel(request);
    rel(op_prov), rel(op_tok), rel(result), rel(vec), rel(item);
    hstr_free(tokh);
    mem_free(scope);
    if (owned)
        RoUninitialize();
    return WAM_OK;

fail:
    rc = (int)hr;
fail_nohr:
    *hrout = (unsigned)hr;
    rel(mgr), rel(reqfac), rel(provider), rel(request);
    rel(op_prov), rel(op_tok), rel(result), rel(vec), rel(item);
    mem_free(scope);
    if (owned)
        RoUninitialize();
    return rc == 0 ? (int)WAM_EFAIL : rc;
}

int wam_acquire(const wchar_t *scope_prefix, wchar_t **out, int *step,
                unsigned long *hr)
{
    unsigned int h = 0;
    int st = 0, rc;
    wchar_t *tok = 0;

    *out = 0;
    *step = 0;
    *hr = 0;
    rc = run(scope_prefix, &tok, &st, &h);
    if (rc == WAM_OK) {
        *out = tok;
        return WAM_OK;
    }
    *step = st;
    *hr = h;
    return rc;
}
