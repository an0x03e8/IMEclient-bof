/* ime_install.c — resolve an app and POST its Install/Uninstall action
 *
 *   ime_install <install|uninstall> <name-substring|#index|guid>
 */
#include "bofapi.h"
#include "ime_api.h"
#include "ime_util.h"
#include "../common/strutil.h"
#include "http.h"
#include "print.h"

static int elem_str(const json_span *el, const char *key, char *out, int outmax)
{
    int n = ime_json_str(el->p, el->len, key, out, outmax);
    if (n < 0)
        out[0] = 0;
    return n;
}

/* action codes */
enum { ACT_INSTALL = 1, ACT_UNINSTALL = 2 };

int go(char *args, int len)
{
    char *a_act, *a_sel;
    ime_ctx *c;
    wchar_t *ver = 0;
    char *body = 0, *statebody = 0, *postbody = 0;
    DWORD status = 0, st2 = 0;
    int rc, rc2, want = 0, count = 0, idx = -1, found = 0;
    json_iter it;
    json_span el, sel_el, st_el, tgt;
    char guid[64], name[160], pub[160], nav[1024], appid[64];
    int have_state = 0;

    char *cur = args;
    int rem = len;

    /* beacon bof_pack "Z" layout: [u32 byteLen][UTF-16LE] per arg */
    a_act = ime_bof_arg_utf8(&cur, &rem);
    a_sel = ime_bof_arg_utf8(&cur, &rem);
    if (!a_act || !a_act[0] || !a_sel || !a_sel[0]) {
        internal_printf("usage: ime_install <install|uninstall> <name-substring|#|guid>");
        printoutput(CALLBACK_ERROR);
        return 0;
    }
    if (su_ci_eq(a_act, "install"))
        want = ACT_INSTALL;
    else if (su_ci_eq(a_act, "uninstall"))
        want = ACT_UNINSTALL;
    else {
        internal_printf("ime_install: action must be install|uninstall");
        printoutput(CALLBACK_ERROR);
        return 0;
    }

    c = ime_ctx_require();
    if (!c)
        return 0;
    ime_api_negotiate(c, &ver);

    /* --- fresh Applications query (resolution pool) ----------------------- */
    rc = ime_api_list_apps(c, ver, &body, &status);
    if (rc != HTTP_OK || !body) {
        if (rc == HTTP_FAIL) {
            internal_printf("ime_install: applications request failed\n");
            printoutput(CALLBACK_ERROR);
        } else
            ime_http_error("ime_install: applications", status, body);
        goto out;
    }

    it.began = it.pos = it.started = 0;
    while (json_array_iter(body, su_len(body), "value", &it, &el))
        count++;

    if (su_digits(a_sel)) {
        /* numeric = 1-based index, Program.cs ResolveApp */
        int v = 0;
        const char *s = a_sel;
        while (*s)
            v = v * 10 + (*s++ - '0');
        if (v < 1 || v > count) {
            internal_printf("ime_install: index %d out of range 1..%d\n", v, count);
            printoutput(CALLBACK_ERROR);
            goto out;
        }
        idx = v;
    }

    /* pass 1: index or name substring; pass 2 (fallback): exact GUID */
    it.began = it.pos = it.started = 0;
    while (json_array_iter(body, su_len(body), "value", &it, &el)) {
        elem_str(&el, "GuidKey", guid, (int)sizeof(guid));
        elem_str(&el, "Name", name, (int)sizeof(name));
        if (idx > 0) {
            if (++found == idx) {
                sel_el = el;
                goto have;
            }
        } else if (su_ci_nfind(name, 0, su_len(name), a_sel) >= 0) {
            sel_el = el;
            goto have;
        }
    }
    if (idx < 0) {
        it.began = it.pos = it.started = 0;
        while (json_array_iter(body, su_len(body), "value", &it, &el)) {
            elem_str(&el, "GuidKey", guid, (int)sizeof(guid));
            if (su_ci_eq(guid, a_sel)) {
                sel_el = el;
                goto have;
            }
        }
    }
    internal_printf("ime_install: no application matching '%s' (%d listed)\n",
                 a_sel, count);
    printoutput(CALLBACK_ERROR);
    goto out;

have:
    elem_str(&sel_el, "GuidKey", guid, (int)sizeof(guid));
    elem_str(&sel_el, "Name", name, (int)sizeof(name));
    elem_str(&sel_el, "Publisher", pub, (int)sizeof(pub));
    internal_printf("ime_install: %s -> %s\n  %s (%s)%s\n",
                 a_act, want == ACT_INSTALL ? "install" : "uninstall",
                 name, guid, pub[0] ? "  publisher: " : "", pub);

    /* --- ApplicationState via navigation link ---------------------------- */
    if (elem_str(&sel_el, "ApplicationState@odata.navigationLinkUrl", nav,
                 (int)sizeof(nav)) < 0 || !nav[0]) {
        internal_printf("ime_install: no ApplicationState@odata.navigationLinkUrl on entity\n");
        printoutput(CALLBACK_ERROR);
        goto out;
    }
    {
        /* relative link -> {iw}/ prefix (FetchAppState); strip leading / */
        wchar_t *wnav = 0, *wfull = 0, *wfilter = 0, *withfilter;
        const char *rel = nav;
        int npref = su_ci_prefix(nav, su_len(nav), "http");
        if (!npref) {
            if (nav[0] == '/')
                rel++;
        }
        if (utf8_to_utf16(rel, -1, &wnav) < 0 || !wnav) {
            internal_printf("ime_install: nav link conversion failed\n");
        printoutput(CALLBACK_ERROR);
            goto out;
        }
        if (npref) {
            wfull = wnav;
        } else {
            wchar_t *tmp = str_cat(c->iwurl, L"/");
            wfull = str_cat(tmp, wnav);
            mem_free(tmp);
            mem_free(wnav);
            if (!wfull)
                goto out;
        }
        /* $filter=DeviceId eq guid'<devid>' when known (GetApplicationStateWithActionsAsync) */
        if (c->devid && c->devid[0]) {
            wchar_t *f = str_cat(L"$filter=DeviceId%20eq%20guid'", c->devid);
            wfilter = str_cat(f, L"'");
            mem_free(f);
            withfilter = ime_url_append(wfull, wfilter);
            mem_free(wfilter);
            mem_free(wfull);
            wfull = withfilter;
        }
        rc2 = ime_api_get(c, ver, wfull, &statebody, &st2);
        mem_free(wfull);
    }
    if (rc2 != HTTP_OK || !statebody) {
        if (rc2 == HTTP_FAIL) {
            internal_printf("ime_install: state request failed\n");
            printoutput(CALLBACK_ERROR);
        } else
            ime_http_error("ime_install: state", st2, statebody);
        goto out;
    }

    /* state entry with ApplicationId == guid */
    it.began = it.pos = it.started = 0;
    while (json_array_iter(statebody, su_len(statebody), "value", &it, &st_el)) {
        elem_str(&st_el, "ApplicationId", appid, (int)sizeof(appid));
        if (su_ci_eq(appid, guid)) {
            have_state = 1;
            break;
        }
    }
    if (!have_state) {
        internal_printf("ime_install: no ApplicationState entry for %s\n",
                     guid);
        printoutput(CALLBACK_ERROR);
        goto out;
    }

    /* --- action target: faithful ExtractODataActionTarget port ----------- */
    {
        const char *wantName = want == ACT_INSTALL ? "Install" : "Uninstall";
        const char *otherName = want == ACT_INSTALL ? "Uninstall" : "Install";
        json_span other;
        int have_want = ime_odata_action_target(st_el.p, st_el.len, wantName, &tgt);
        int have_other = ime_odata_action_target(st_el.p, st_el.len, otherName, &other);
        wchar_t *wurl;
        char head[208];
        int hn = 0;

        if (!have_want) {
            internal_printf("ime_install: no %s action target on state (Install:%s Uninstall:%s)\n",
                         wantName, have_want ? "yes" : "no",
                         have_other ? "yes" : "no");
            printoutput(CALLBACK_ERROR);
            goto out;
        }
        /* raw quoted body, no unescape - exactly Program.cs (a JSON-escaped
         * \/ stays escaped; observed harmless for IW targets, same as C#) */
        if (utf8_to_utf16(tgt.p, tgt.len, &wurl) < 0 || !wurl) {
            internal_printf("ime_install: target conversion failed\n");
        printoutput(CALLBACK_ERROR);
            goto out;
        }
        /* PostActionAsync shape; body {}, as in the C# client (oid not
         * parsed in v1) */
        rc2 = ime_api_post(c, ver, wurl, "{}", &postbody, &st2);
        mem_free(wurl);
        if (rc2 == HTTP_FAIL || !postbody) {
            internal_printf("ime_install: POST failed (no response)\n");
            printoutput(CALLBACK_ERROR);
            goto out;
        }
        if (rc2 != HTTP_OK) {
            ime_http_error("ime_install: POST", st2, postbody);
            goto out;
        }
        if (postbody)
            while (postbody[hn] && hn < 200)
                head[hn] = postbody[hn], hn++;
        head[hn] = 0;
        internal_printf("ime_install: %s POST -> HTTP %u\n%s",
                     want == ACT_INSTALL ? "install" : "uninstall", st2, head);
        printoutput(CALLBACK_OUTPUT);
    }

out:
    mem_free(postbody);
    mem_free(statebody);
    mem_free(body);
    mem_free(ver);
    return 0;
}
