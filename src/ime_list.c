/* ime_list.c — enumerate the Intune self-service catalogue.
 *
 *   ime_list
 *
 * OPTIONS api-version negotiation, then
 * GET {iw}/Applications?$top=100&$skip=0 + service params.
 * prints  #  GuidKey  Name  Publisher
 */
#include "bofapi.h"
#include "ime_api.h"
#include "ime_util.h"
#include "../common/strutil.h"
#include "http.h"
#include "print.h"

#define GUIDSHOW 38
#define NAMESHOW 44

/* pad-copy `src` into line at *off, space-padded/truncated to width */
static void padcat(char *line, int *off, int cap, const char *src, int width)
{
    int n = 0;
    if (!src)
        src = "";
    while (src[n])
        n++;
    if (n > width)
        n = width;
    if (*off + width >= cap)
        width = cap - 1 - *off; /* clamp hard */
    if (width < 0)
        return;
    {
        int i;
        for (i = 0; i < n; i++)
            line[(*off)++] = src[i];
        for (; i < width; i++)
            line[(*off)++] = ' ';
    }
}

static void appends(char *line, int *off, int cap, const char *src)
{
    while (*src && *off < cap - 1)
        line[(*off)++] = *src++;
}

void go(char *args, int len)
{
    ime_ctx *c;
    wchar_t *ver = 0;
    char *body = 0;
    DWORD status = 0;
    int rc, n = 0;
    json_iter it;
    json_span el;

    (void)args;
    (void)len;
    c = ime_ctx_require();
    if (!c)
        return;
    ime_api_negotiate(c, &ver);

    rc = ime_api_list_apps(c, ver, &body, &status);
    if (rc == HTTP_FAIL || !body) {
        internal_printf("ime_list: request failed (no response)");
        printoutput(CALLBACK_ERROR);
        goto out;
    }
    if (rc != HTTP_OK) {
        ime_http_error("ime_list", status, body);
        goto out;
    }

    it.began = it.pos = it.started = 0;
    {
        char line[256];
        int off;
        char guid[64], name[160], pub[160];
        line[0] = 0;
        off = 0;
        padcat(line, &off, (int)sizeof(line), "#", 3);
        padcat(line, &off, (int)sizeof(line), "GuidKey", GUIDSHOW);
        padcat(line, &off, (int)sizeof(line), "Name", NAMESHOW);
        appends(line, &off, (int)sizeof(line), "Publisher");
        line[off] = 0;
        internal_printf("%s\n", line);

        while (json_array_iter(body, su_len(body), "value", &it, &el)) {
            int gl = ime_json_str(el.p, el.len, "GuidKey", guid, (int)sizeof(guid));
            int nml = ime_json_str(el.p, el.len, "Name", name, (int)sizeof(name));
            int pl = ime_json_str(el.p, el.len, "Publisher", pub, (int)sizeof(pub));
            char num[8];
            int ni = 0;
            n++;
            if (gl < 0)
                guid[0] = 0;
            if (nml < 0)
                name[0] = 0;
            if (pl < 0)
                pub[0] = 0;
            if (n >= 10)
                num[ni++] = (char)('0' + n / 10);
            num[ni++] = (char)('0' + n % 10);
            num[ni] = 0;
            off = 0;
            padcat(line, &off, (int)sizeof(line), num, 3);
            padcat(line, &off, (int)sizeof(line), guid, GUIDSHOW);
            padcat(line, &off, (int)sizeof(line), name, NAMESHOW);
            appends(line, &off, (int)sizeof(line), pub);
            line[off] = 0;
            internal_printf("%s\n", line);
        }
    }
    if (n == 0)
        internal_printf("ime_list: no applications returned\n");
    else
        internal_printf("--- %d application(s)\n", n);
    printoutput(CALLBACK_OUTPUT);

out:
    mem_free(body);
    mem_free(ver);
}
