/* wcfpipe.c — WCF NetNamedPipe client */

#include "wcfpipe.h"
#include "bofapi.h"
#include "../common/strutil.h"

/* ---------------------------------------------------------------- imports */
#define GENERIC_READ_  0x80000000u
#define GENERIC_WRITE_ 0x40000000u
#define FILE_MAP_READ_ 0x0004u

extern HANDLE WINAPI OpenFileMappingW(DWORD access, int inherit, const wchar_t *name);
extern void * WINAPI MapViewOfFile(HANDLE h, DWORD access, DWORD hi, DWORD lo, size_t cb);
extern int   WINAPI UnmapViewOfFile(const void *p);
extern int   WINAPI WriteFile(HANDLE h, const void *buf, DWORD len, DWORD *written, void *overlapped);
extern void  WINAPI Sleep(DWORD ms);
extern int   WINAPI SetNamedPipeHandleState(void *h, const DWORD *mode, DWORD *maxc, DWORD *collect);
extern int   WINAPI PeekNamedPipe(void *h, void *buf, DWORD bufsz, DWORD *read, DWORD *avail, DWORD *left);

typedef unsigned long ulong_;

typedef struct { void *lo, *hi; } sec_handle;
typedef struct { ulong_ lo, hi; } sec_ts;
typedef struct { ulong_ cb; ulong_ type; void *pv; } sec_buffer;
typedef struct { ulong_ version; ulong_ cbufs; sec_buffer *bufs; } sec_bdesc;

#define SECBUFFER_EMPTY   0
#define SECBUFFER_DATA    1
#define SECBUFFER_TOKEN   2
#define SECBUFFER_PADDING 7
#define SECBUFFER_STREAM  6

#define SECPKG_CRED_OUTBOUND     2
#define SEC_E_OK                 0
#define SEC_I_CONTINUE_NEEDED    0x00090312u
#define SEC_I_COMPLETE_NEEDED    0x00090313u
#define SEC_I_COMPLETE_AND_CONTINUE 0x00090314u
#define SECPKG_ATTR_STREAM_SIZES 4
#define ISC_REQ_CONFIDENTIALITY 0x10u
#define ISC_REQ_REPLAY_DETECT   0x4u
#define ISC_REQ_SEQUENCE_DETECT 0x8u
#define ISC_REQ_CONNECTION      0x800u

/* SECPKG_ATTR_SIZES (0) — NOT STREAM_SIZES(4): Negotiate returns
 * 0x80090302 for the latter. Layout per sspi.h SecPkgContext_Sizes. */
typedef struct { ulong_ cbMaxToken, cbMaxSignature, cbBlockSize, cbSecurityTrailer; } sec_sizes;

extern ulong_ WINAPI AcquireCredentialsHandleW(const wchar_t *principal,
        const wchar_t *package, ulong_ usage, void *logon, void *authData,
        void *getKeyFn, void *reserved, sec_handle *cred, sec_ts *expiry);
extern ulong_ WINAPI FreeCredentialsHandle(sec_handle *cred);
extern ulong_ WINAPI InitializeSecurityContextW(sec_handle *cred, sec_handle *ctxIn,
        const wchar_t *target, ulong_ ctxReq, ulong_ reserved1, ulong_ targetDataRep,
        sec_bdesc *in, ulong_ reserved2, sec_handle *newCtx, sec_bdesc *out,
        ulong_ *attr, sec_ts *expiry);
extern ulong_ WINAPI QueryContextAttributesW(sec_handle *ctx, ulong_ attr, void *buf);
extern ulong_ WINAPI EncryptMessage(sec_handle *ctx, ulong_ *quality, sec_bdesc *msg, ulong_ seq);
extern ulong_ WINAPI DecryptMessage(sec_handle *ctx, sec_bdesc *msg, ulong_ seq, ulong_ *qop);
extern ulong_ WINAPI CompleteAuthToken(sec_handle *ctx, sec_bdesc *token);
extern ulong_ WINAPI DeleteSecurityContext(sec_handle *ctx);

#include "print.h"

/* base64 (standard alphabet, padded) */
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int b64_len(int n) { return ((n + 2) / 3) * 4; }
static void b64_enc(const unsigned char *in, int n, char *out)
{
    int i, o = 0;
    for (i = 0; i < n; i += 3) {
        int rem = n - i > 3 ? 3 : n - i;
        unsigned v = (unsigned)in[i] << 16;
        if (rem > 1) v |= (unsigned)in[i + 1] << 8;
        if (rem > 2) v |= in[i + 2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = rem > 1 ? B64[(v >> 6) & 63] : '=';
        out[o++] = rem > 2 ? B64[v & 63] : '=';
    }
}

/* ---------------------------------------------------------------- resolve */
/* section name: <scope>\net.pipe:E<b64("net.pipe://"+HOST+"'+path")>
 * host variants per PipeConnectionInitiator; scope Global then Local. */
static const char *IME_VIA =
    "net.pipe://localhost/IntuneManagementExtension/StatusService/";

static int try_section(const char *host, const char *scope, wchar_t *pipeW)
{
    char plain[160];
    char b64[256];
    char name[300];
    wchar_t wname[300];
    unsigned char *view;
    HANDLE h;
    int plainlen, blen, i;
    unsigned char guid[16];

    /* "net.pipe://" + <host variant> + PATHUPPER (host comes in as param:
     * the StrongWildcard "+" registration is the one that hits) */
    {
        static const char PATHUPPER[] = "/INTUNEMANAGEMENTEXTENSION/STATUSSERVICE/";
        const char *sch = "net.pipe://";
        const char *path = PATHUPPER;
        int k = 0;
        while (*sch) plain[k++] = *sch++;
        while (*host) { char c = *host++; if (c >= 'a' && c <= 'z') c -= 32; plain[k++] = c; }
        while (*path) plain[k++] = *path++;
        plain[k] = 0;
        plainlen = k;
    }
    blen = b64_len(plainlen);
    b64_enc((const unsigned char *)plain, plainlen, b64);
    b64[blen] = 0;

    /* name = <scope>\net.pipe:E<b64> */
    {
        const char *s = scope;
        int k = 0;
        while (*s) name[k++] = *s++;
        s = "net.pipe:E";
        while (*s) name[k++] = *s++;
        for (i = 0; i < blen; i++) name[k++] = b64[i];
        name[k] = 0;
    }
    /* widen (ASCII) */
    for (i = 0; name[i]; i++) wname[i] = (wchar_t)name[i];
    wname[i] = 0;

    h = OpenFileMappingW(FILE_MAP_READ_, 0, wname);
    if (!h)
        return 0;
    view = (unsigned char *)MapViewOfFile(h, FILE_MAP_READ_, 0, 0, 32);
    if (!view) { CloseHandle(h); return 0; }
    if (view[0] != 1) { UnmapViewOfFile(view); CloseHandle(h); return 0; }
    for (i = 0; i < 16; i++) guid[i] = view[4 + i];
    UnmapViewOfFile(view);
    CloseHandle(h);

    /* \\.\pipe\{Data1-Data2-Data3-Data4..} with the standard GUID string
     * field swapping (Data1/2/3 rendered from LE storage, hex pairs 8..15) */
    {
        static const char HEX[] = "0123456789abcdef";
        const char pre[] = {'\\','\\','.','\\','p','i','p','e','\\'};
        int k = 0, j;
        for (j = 0; j < 9; j++) pipeW[k++] = (wchar_t)pre[j];
        for (j = 3; j >= 0; j--) { pipeW[k++] = HEX[guid[j] >> 4]; pipeW[k++] = HEX[guid[j] & 15]; }
        pipeW[k++] = '-';
        for (j = 5; j >= 4; j--) { pipeW[k++] = HEX[guid[j] >> 4]; pipeW[k++] = HEX[guid[j] & 15]; }
        pipeW[k++] = '-';
        for (j = 7; j >= 6; j--) { pipeW[k++] = HEX[guid[j] >> 4]; pipeW[k++] = HEX[guid[j] & 15]; }
        pipeW[k++] = '-';
        for (j = 8; j < 10; j++) { pipeW[k++] = HEX[guid[j] >> 4]; pipeW[k++] = HEX[guid[j] & 15]; }
        pipeW[k++] = '-';
        for (j = 10; j < 16; j++) { pipeW[k++] = HEX[guid[j] >> 4]; pipeW[k++] = HEX[guid[j] & 15]; }
        pipeW[k] = 0;
    }
    return 1;
}

static int resolve_pipe(wchar_t *pipeW)
{
    static const char *hosts[] = {"+", "LOCALHOST", "*"};
    static const char *scopes[] = {"Global\\", "Local\\"};
    int h, s;
    for (h = 0; h < 3; h++)
        for (s = 0; s < 2; s++)
            if (try_section(hosts[h], scopes[s], pipeW)) return 1;
    return 0;
}

/* ------------------------------------------------------------- connection */
typedef struct {
    HANDLE h;
    unsigned char *buf;
    int cap, len, pos;
    int eof;
} conn;

static int conn_fill(conn *c)
{
    DWORD n = 0;
    if (c->pos >= c->len) { c->pos = c->len = 0; }
    if (!ReadFile(c->h, c->buf + c->len, c->cap - c->len, &n, 0)) { c->eof = 1; return 0; }
    if (n == 0) { c->eof = 1; return 0; }
    c->len += (int)n;
    return 1;
}

static int conn_read(conn *c, void *dst, int n)
{
    unsigned char *d = (unsigned char *)dst;
    int got = 0;
    while (got < n) {
        int avail = c->len - c->pos;
        if (avail <= 0) { if (!conn_fill(c)) return got; avail = c->len - c->pos; }
        while (avail > 0 && got < n) { d[got++] = c->buf[c->pos++]; avail--; }
    }
    return got;
}

static int conn_write(conn *c, const void *b, int n)
{
    DWORD w = 0;
    if (!WriteFile(c->h, b, (DWORD)n, &w, 0)) {
        internal_printf("[wcf] wr fail n=%d w=%lu gle=%d\n", n, (unsigned long)w, (int)GetLastError());
        return 0;
    }
    return (int)w == n;
}

/* read one 5B-framed record; returns malloc'd payload, len in *len, id in *id.
 * len 0 is legal (e.g. HandshakeDone). */
static unsigned char *read_frame_id(conn *c, int *len, unsigned char *id)
{
    unsigned char hdr[5];
    int plen;
    unsigned char *payload;
    if (conn_read(c, hdr, 5) != 5) return 0;
    if (id) *id = hdr[0];
    plen = (hdr[3] << 8) | hdr[4];
    if (plen < 0 || plen > 65535) return 0;
    payload = (unsigned char *)LocalAlloc(0, plen + 1);
    if (!payload) return 0;
    if (plen && conn_read(c, payload, plen) != plen) { LocalFree(payload); return 0; }
    *len = plen;
    return payload;
}

static int write_frame(conn *c, unsigned char id, const unsigned char *payload, int len)
{
    unsigned char hdr[5];
    hdr[0] = id; hdr[1] = 1; hdr[2] = 0;
    hdr[3] = (unsigned char)(len >> 8); hdr[4] = (unsigned char)(len & 0xff);
    if (!conn_write(c, hdr, 5)) return 0;
    if (len && !conn_write(c, payload, len)) return 0;
    return 1;
}

/* ------------------------------------------------------------------ sspi */
typedef struct {
    sec_handle cred;
    sec_handle ctx;
    int have_ctx;
    sec_sizes sizes;
} sspi;

static int sspi_init(sspi *s)
{
    sec_ts exp;
    ulong_ rc;
    const wchar_t pkg[] = L"Negotiate";
    rc = AcquireCredentialsHandleW(0, pkg, SECPKG_CRED_OUTBOUND,
                                   0, 0, 0, 0, &s->cred, &exp);
    if (rc != 0) internal_printf("[wcf] ACH %d\n",(int)rc);
    s->have_ctx = 0;
    return rc == 0;
}

/* Perform the NegotateStream handshake as the CLIENT. Returns 0 ok. */
static int sspi_handshake(sspi *s, conn *c)
{
    unsigned char outbuf[16384];
    unsigned char inbuf[16384];
    ulong_ rc;
    sec_buffer outb[2], inb[2];
    sec_bdesc outd, ind;
    ulong_ attr;
    sec_ts exp;
    int first = 1;
    unsigned long rdseq = 0, wrseq = 0;

    for (;;) {
        /* produce a token (first call has no input) */
        outb[0].cb = sizeof(outbuf); outb[0].type = SECBUFFER_TOKEN; outb[0].pv = outbuf;
        outb[1].cb = 0; outb[1].type = SECBUFFER_EMPTY;  outb[1].pv = 0;
        outd.version = 0; outd.cbufs = 2; outd.bufs = outb;

        ind.version = 0; ind.cbufs = 2; ind.bufs = inb;
        if (first) {
            inb[0].cb = 0; inb[0].type = SECBUFFER_EMPTY; inb[0].pv = 0;
        } else {
            /* inbuf holds the last server token */
            inb[0].cb = (ulong_)s->have_ctx ? inb[0].cb : 0;
        }
        rc = InitializeSecurityContextW(&s->cred, first ? 0 : &s->ctx, 0,
                ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT |
                ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONNECTION,
                0, 0x10 /*UNICODE*/, &ind, 0, &s->ctx, &outd,
                &attr, &exp);
        if (rc != SEC_E_OK && rc != SEC_I_CONTINUE_NEEDED &&
            rc != SEC_I_COMPLETE_NEEDED && rc != SEC_I_COMPLETE_AND_CONTINUE) {
            internal_printf("[wcf] ISC failed 0x%x iter=%d out=%d\n",(int)rc,first?(int)1:(int)0,(int)outb[0].cb);
            { char msg[160]; extern int WINAPI FormatMessageW(unsigned f, void *s, unsigned c, unsigned l, char *b, unsigned n, void *a);
              msg[0]=0; FormatMessageW(0x1000,0,(unsigned)rc,0,(char*)msg,150,0);
              { char narrow[80]; int ni=0; for (int wj=0; msg[wj] && ni<78; wj+=2) narrow[ni++]=msg[wj];
                narrow[ni]=0; internal_printf("[wcf]   %s\n",narrow); } }
            return 1;
        }
        if (!s->have_ctx) s->have_ctx = 1;
        if (outb[0].cb > 0) {

            if (!write_frame(c, 0x16, (unsigned char *)outbuf, (int)outb[0].cb)) {
                internal_printf("[wcf] token write failed\n");
                return 1;
            }
        }
        if (rc == SEC_I_COMPLETE_NEEDED || rc == SEC_I_COMPLETE_AND_CONTINUE) {
            sec_bdesc d; d.version = 0; d.cbufs = 0; d.bufs = 0;
            CompleteAuthToken(&s->ctx, &d);
        }
        if (rc == SEC_E_OK || rc == SEC_I_COMPLETE_NEEDED) break;

        first = 0;
        /* next server token */
        {
            int len = 0;
            unsigned char fid = 0;
            unsigned char *p = read_frame_id(c, &len, &fid);
            int body;
            if (!p) { internal_printf("[wcf] hs read fail eof=%d len=%d gle=%d\n",c->eof,c->len,(int)GetLastError()); return 1; }
            body = len;
            if (body > (int)sizeof(inbuf)) body = sizeof(inbuf);
            for (int i = 0; i < body; i++) inbuf[i] = p[i];
            LocalFree(p);
            inb[0].cb = body; inb[0].type = SECBUFFER_TOKEN; inb[0].pv = inbuf;
            inb[1].cb = 0; inb[1].type = SECBUFFER_EMPTY; inb[1].pv = 0;
        }
    }
    /* the server may end the auth phase with a 5B-framed HandshakeDone
     * (0x14); the netfx agent does not always send one, so only drain
     * frames already queued (never block here) */
    for (;;) {
        DWORD avail = 0;
        unsigned char id = 0;
        int l2 = 0;
        unsigned char *p2;
        if (!PeekNamedPipe(c->h, 0, 0, 0, &avail, 0) || avail < 5) break;
        p2 = read_frame_id(c, &l2, &id);
        if (!p2) break;
        LocalFree(p2);
    }
    {
        ulong_ rc2 = QueryContextAttributesW(&s->ctx, 0 /*SECPKG_ATTR_SIZES*/, &s->sizes);
        if (rc2 != 0) {
            s->sizes.cbMaxToken = 0; s->sizes.cbMaxSignature = 16;
            s->sizes.cbBlockSize = 0; s->sizes.cbSecurityTrailer = 16;
        }
    }
    (void)wrseq; (void)rdseq;
    return 0;
}

/* wrap: emit one encrypted record with payload `data`.
 * Buffer recipe per CLR NegotiateAuthenticationPal.Windows.Wrap:
 * TOKEN cb=cbSecurityTrailer, DATA, PADDING cb=cbBlockSize; after
 * EncryptMessage compact to the actual cbs (token shrinks to the sig). */
static int sspi_wrap(sspi *s, conn *c, const unsigned char *data, int len, unsigned seq)
{
    static unsigned char out[4096]; /* 4B ctr + 16B sig + <=470B payload */
    int cap = (int)s->sizes.cbSecurityTrailer;
    /* no padding buffer: the agent's NTLM records are [sig][data] and the
     * QCA BlockSize=1 pad buffer breaks the server's decrypt (empirical) */
    int total = 4 + cap + len;
    sec_buffer b[2];
    sec_bdesc d;
    ulong_ q = 0, rc;

    if (total > (int)sizeof(out)) return 0;
    b[0].cb = (ulong_)cap;      b[0].type = SECBUFFER_TOKEN;   b[0].pv = out + 4;
    b[1].cb = (ulong_)len;      b[1].type = SECBUFFER_DATA;    b[1].pv = out + 4 + cap;
    for (int i = 0; i < len; i++) out[4 + cap + i] = data[i];
    d.version = 0; d.cbufs = 2; d.bufs = b;
    rc = EncryptMessage(&s->ctx, &q, &d, seq);
    if (rc != 0) { internal_printf("[wcf] encrypt failed 0x%x\n",(int)rc); return 0; }
    /* compact: token shrank -> pull data left (backward copy: dst<src) */
    if (b[0].cb != (ulong_)cap)
        for (int i = (int)b[1].cb - 1; i >= 0; i--)
            out[4 + b[0].cb + i] = out[4 + cap + i];
    {
        int body = (int)(b[0].cb + b[1].cb);
        unsigned char prefix[4];
        prefix[0] = (unsigned char)(body & 0xff);
        prefix[1] = (unsigned char)((body >> 8) & 0xff);
        prefix[2] = (unsigned char)((body >> 16) & 0xff);
        prefix[3] = (unsigned char)((body >> 24) & 0xff);
        /* data record = 4B LE count + body; no 5B frame past the handshake
         * (netfx NegotiateStream reads exactly this) */
        if (!conn_write(c, prefix, 4)) return 0;
        return conn_write(c, out + 4, body);
    }
}

/* unwrap one data record (4B LE count + body); returns malloc'd plain payload or 0 */
static unsigned char *sspi_unwrap(sspi *s, conn *c, int *plainlen, unsigned seq)
{
    unsigned char hdr[4];
    int len;
    unsigned char *p;
    sec_buffer b[2];
    sec_bdesc d;
    ulong_ q = 0, rc;
    unsigned char *plain;
    if (conn_read(c, hdr, 4) != 4) { internal_printf("[wcf] unwrap: no hdr eof=%d gle=%d\n",c->eof,(int)GetLastError()); return 0; }
    len = (int)hdr[0] | ((int)hdr[1] << 8) | ((int)hdr[2] << 16) | ((int)hdr[3] << 24);
    if (len <= 0 || len > 65536) { internal_printf("[wcf] unwrap: bad len %d\n",len); return 0; }
    p = (unsigned char *)LocalAlloc(0, len);
    if (!p) return 0;
    if (len < 17) { LocalFree(p); return 0; } /* 16B sig + >=1B payload */
    if (conn_read(c, p, len) != len) { LocalFree(p); return 0; }
    /* netfx DecryptNtlm: TOKEN = 16B sig, DATA = rest, in place */
    b[0].cb = 16;              b[0].type = SECBUFFER_TOKEN;  b[0].pv = p;
    b[1].cb = (ulong_)(len - 16); b[1].type = SECBUFFER_DATA; b[1].pv = p + 16;
    d.version = 0; d.cbufs = 2; d.bufs = b;
    rc = DecryptMessage(&s->ctx, &d, seq, &q);
    if (rc != 0) { LocalFree(p); internal_printf("[wcf] decrypt failed %d len=%d\n",(int)rc,len); return 0; }
    if (b[1].type != SECBUFFER_DATA || b[1].cb == 0) { LocalFree(p); return 0; }
    plain = (unsigned char *)LocalAlloc(0, b[1].cb + 1);
    if (!plain) { LocalFree(p); return 0; }
    for (unsigned i = 0; i < b[1].cb; i++) plain[i] = ((unsigned char *)b[1].pv)[i];
    *plainlen = (int)b[1].cb;
    LocalFree(p);
    return plain;
}

/* -------------------------------------------------------------- envelope */
/* session-binary (msbinsession1) CheckIn request: see wcf_env.h. */
#include "wcf_env.h"

/* ------------------------------------------------------------------ public */
int wcf_checkin(void)
{
    wchar_t pipeW[128];
    conn c;
    sspi s;
    unsigned char pre1[160], pre2[32];
    int pre1len = 0, pre2len = 0, i;
    unsigned char ack[8];
    unsigned char *plain;
    int plainlen = 0;
    unsigned seq = 1; /* NegoState pre-increments: first data seq is 1 */
    int nrec = 0;

    if (!resolve_pipe(pipeW)) {
        internal_printf("[wcf] no IME pipe endpoint found\n");
        return 1;
    }

    c.h = CreateFileW(pipeW, GENERIC_READ_ | GENERIC_WRITE_, 0, 0, OPEN_EXISTING, 0, 0);
    if (c.h == INVALID_HANDLE_VALUE || c.h == 0) {
        internal_printf("[wcf] pipe open failed gle=%d\n",(int)GetLastError());
        return 1;
    }
    {
        DWORD mode = 2; /* PIPE_READMODE_MESSAGE, as CF does */
        if (!SetNamedPipeHandleState(c.h, &mode, 0, 0))
            internal_printf("[wcf] mode set gle=%d\n",(int)GetLastError());
    }
    c.cap = 16384;
    c.buf = (unsigned char *)LocalAlloc(0, c.cap);
    c.len = c.pos = 0;
    c.eof = 0;

    /* framing preamble: version+duplex, via, binary-session encoding, upgrade */
    {
        const unsigned char head[] = {0x00, 0x01, 0x00, 0x01, 0x02};
        const unsigned char enc[] = {0x03, 0x08};
        int vias;
        for (i = 0; i < 5; i++) pre1[pre1len++] = head[i];
        pre1[pre1len++] = 0x02; /* Via */
        vias = 0;
        while (IME_VIA[vias]) vias++;
        pre1[pre1len++] = (unsigned char)vias;
        for (i = 0; i < vias; i++) pre1[pre1len++] = (unsigned char)IME_VIA[i];
        pre1[pre1len++] = enc[0]; pre1[pre1len++] = enc[1];
    }
    {
        const char *up = "application/negotiate";
        int n = 0;
        while (up[n]) n++;
        pre2[pre2len++] = 0x09; /* UpgradeRequest */
        pre2[pre2len++] = (unsigned char)n;
        for (i = 0; i < n; i++) pre2[pre2len++] = (unsigned char)up[i];
    }
    if (!conn_write(&c, pre1, pre1len) || !conn_write(&c, pre2, pre2len)) {
        internal_printf("[wcf] preamble write failed\n");
        return 1;
    }
    /* upgrade response ack */
    if (conn_read(&c, ack, 1) != 1 || ack[0] != 0x0A) {
        internal_printf("[wcf] no upgrade ack (0x%02x)\n",ack[0]);
        return 1;
    }
    if (sspi_init(&s)) {
        if (sspi_handshake(&s, &c)) return 1;
    } else {
        internal_printf("[wcf] credentials failed\n");
        return 1;
    }

    /* PreambleEnd inside the secure stream; expect encrypted PreambleAck */
    {
        unsigned char pe[1]; pe[0] = 0x0C;
        if (!sspi_wrap(&s, &c, pe, 1, seq++)) { internal_printf("[wcf] preamble wrap failed\n"); return 1; }
    }
    plain = sspi_unwrap(&s, &c, &plainlen, 1);
    if (!plain) { internal_printf("[wcf] no preamble ack\n"); return 1; }
    if (plainlen != 1 || plain[0] != 0x0B) {
        internal_printf("[wcf] unexpected preamble ack len=%d b=0x%02x\n",plainlen,plainlen?plain[0]:0);
        LocalFree(plain);
        return 1;
    }
    LocalFree(plain);
    unsigned rseq = 2; /* read ctr independent of ours: server counts its own records */

    /* CheckIn request: SizedEnvelope record 06 varint(len) <session msg>.
     * SessionEncoder.EncodeMessageFrame: 1-byte type + IntEncoder varint. */
    {
        unsigned char msg[3 + ENVMSG_LEN];
        int total = 0, mi;
        msg[total++] = 0x06;
        msg[total++] = 0xD6; msg[total++] = 0x03; /* varint 470 */
        for (mi = 0; mi < ENVMSG_LEN; mi++) msg[total++] = ENVMSG[mi];
        if (!sspi_wrap(&s, &c, msg, total, seq++)) { internal_printf("[wcf] request wrap failed\n"); return 1; }
    }

    /* reply + optional callbacks (SyncComplete et al arrive on the same
     * session); stop at the first idle gap */
    for (;;) {
        DWORD avail = 0;
        int idle;
        plain = sspi_unwrap(&s, &c, &plainlen, rseq++);
        if (!plain) { internal_printf("[wcf] reply read failed\n"); return 1; }
        nrec++; /* 06-framed envelope or bare control; self-delimiting */
        LocalFree(plain);
        for (idle = 0; idle < 8; idle++) {
            Sleep(250);
            if (!PeekNamedPipe(c.h, 0, 0, 0, &avail, 0) || c.eof) break;
            if (avail) break;
        }
        if (!PeekNamedPipe(c.h, 0, 0, 0, &avail, 0) || !avail || c.eof) break;
    }

    /* graceful session end (CF sends End 0x07 on channel close) */
    {
        unsigned char endb[1]; endb[0] = 0x07;
        sspi_wrap(&s, &c, endb, 1, seq++);
    }
    internal_printf("[wcf] checkin complete (%d record(s))\n", nrec);
    return 0;
}
