#ifndef IMEBOF_IMECTX_H
#define IMEBOF_IMECTX_H

#include "bofapi.h"

#define IME_CTX_KEY    "imeCtx"
#define IME_CTX_MAGIC  0x43454D49u /* "IMEC" */
#define IME_CTX_VER    1

#define IME_CTX_FLAG_NONE 0u

typedef struct {
    unsigned int magic;        /* IME_CTX_MAGIC */
    unsigned int ver;          /* IME_CTX_VER */
    wchar_t *enrollment;       /* bearer token, UTF-16 */
    wchar_t *iwurl;            /* IWService base URL, UTF-16, no trailing / */
    wchar_t *devid;            /* Intune device GUID or empty, UTF-16 */
    unsigned int flags;        /* IME_CTX_FLAG_* */
} ime_ctx;

/* Returns the stored context or NULL (caller prints its own hint; the
 * shared "run ime_auth first" nudge lives in ime_ctx_require, ime_api.h). */
static inline ime_ctx *ime_ctx_get(void)
{
    void *p = BeaconGetValue((char *)IME_CTX_KEY);
    if (!p)
        return 0;
    if (((ime_ctx *)p)->magic != IME_CTX_MAGIC ||
        ((ime_ctx *)p)->ver != IME_CTX_VER)
        return 0;
    return (ime_ctx *)p;
}

/* ---- "imeToken" block ------------------------------------------------------- */
#define IME_TOK_KEY    "imeToken"
#define IME_TOK_MAGIC  0x54454D49u /* "IMET" */
#define IME_TOK_VER    2

typedef struct {
    unsigned int magic;  /* IME_TOK_MAGIC */
    unsigned int ver;    /* IME_TOK_VER */
    wchar_t *token;      /* enrollment token, UTF-16 */
    wchar_t *iwurl;      /* IWService endpoint or empty, UTF-16 */
} ime_tok;

static inline ime_tok *ime_tok_get(void)
{
    void *p = BeaconGetValue((char *)IME_TOK_KEY);
    if (!p)
        return 0;
    if (((ime_tok *)p)->magic != IME_TOK_MAGIC ||
        ((ime_tok *)p)->ver != IME_TOK_VER)
        return 0;
    return (ime_tok *)p;
}

#endif /* IMEBOF_IMECTX_H */
