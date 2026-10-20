/* wam.h — silent AAD token acquisition via the OS WAM broker */
#ifndef IMEBOF_WAM_H
#define IMEBOF_WAM_H

#include "../common/winlean.h"

/* Step tags for diagnostics (wam_step in the result), plus the failing
 * HRESULT in *hr. */
enum {
    WAM_OK = 0,
    WAM_ROINIT = 1,       /* RoInitialize */
    WAM_FACTORY_MGR = 2,  /* activation WebAuthenticationCoreManager */
    WAM_FACTORY_REQ = 3,  /* activation WebTokenRequestFactory */
    WAM_FINDPROVIDER = 4, /* FindAccountProviderWithAuthorityAsync */
    WAM_PROVIDER_RESULT = 5,
    WAM_CREATE_REQ = 6,   /* WebTokenRequestFactory.Create */
    WAM_PROPS = 7,        /* request.Properties / Insert */
    WAM_GETTOKEN = 8,     /* GetTokenSilentlyAsync */
    WAM_TOKEN_RESULT = 9, /* op result / status != Success */
    WAM_NOMEM = 10,
};

#define WAM_TIMEOUT_MS 30000

/* Silent token for `scope_prefix` (e.g. L"https://graph.microsoft.com/.default");
 * " openid offline_access profile" is appended here. Client = Company Portal, provider
 * authority = organizations.
 *
 * Returns WAM_OK and *out = heap NUL-terminated UTF-16 token (caller
 * mem_free's; empty allowed) on success; else a step tag above with the
 * failing HRESULT in *hr (0 when not COM-sourced). */
int wam_acquire(const wchar_t *scope_prefix, wchar_t **out, int *step,
                unsigned long *hr);

#endif