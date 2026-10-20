#include "diag_cli.h"
#include <objbase.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

void cm_cmdkey_cred_free(cm_cmdkey_cred *c)
{
    if (!c) return;
    free(c->target); free(c->type); free(c->user); free(c->persistence); free(c);
}

void cm_vaultcmd_cred_free(cm_vaultcmd_cred *c)
{
    if (!c) return;
    free(c->target); free(c->username); free(c->type);
    free(c->vault_name); free(c->vault_guid); free(c);
}

static wchar_t *capture_wide(const wchar_t *cmd)
{
    char *raw = cm_run_capture(cmd);
    if (!raw) return NULL;
    int wlen = MultiByteToWideChar(CP_OEMCP, 0, raw, -1, NULL, 0);
    wchar_t *w = NULL;
    if (wlen > 0) {
        w = (wchar_t *)malloc((size_t)wlen * sizeof(wchar_t));
        if (w) MultiByteToWideChar(CP_OEMCP, 0, raw, -1, w, wlen);
    }
    free(raw);
    return w;
}

static wchar_t *trimw(wchar_t *s)
{
    while (*s == L' ' || *s == L'\t' || *s == L'\r') s++;
    size_t n = wcslen(s);
    while (n > 0 && (s[n-1] == L' ' || s[n-1] == L'\t' || s[n-1] == L'\r')) s[--n] = L'\0';
    return s;
}

static wchar_t *after_label(wchar_t *line, const wchar_t *prefix)
{
    wchar_t *t = trimw(line);
    size_t pl = wcslen(prefix);
    if (_wcsnicmp(t, prefix, pl) == 0)
        return trimw(t + pl);
    return NULL;
}

void cm_cmdkey_list(cm_vec *out)
{
    wchar_t *text = capture_wide(L"cmdkey.exe /list");
    if (!text) return;

    cm_cmdkey_cred *cur = NULL;
    wchar_t *ctx = NULL;
    for (wchar_t *line = wcstok(text, L"\n", &ctx); line; line = wcstok(NULL, L"\n", &ctx)) {
        wchar_t tmp[1024];
        wcsncpy(tmp, line, 1023); tmp[1023] = L'\0';
        wchar_t *v;
        if ((v = after_label(tmp, L"Target:")) != NULL) {
            if (cur) cm_vec_push(out, cur);
            cur = (cm_cmdkey_cred *)calloc(1, sizeof(cm_cmdkey_cred));
            if (cur) { cur->target = cm_wcsdup(v); cur->type = cm_wcsdup(L"");
                       cur->user = cm_wcsdup(L""); cur->persistence = cm_wcsdup(L""); }
        } else if (cur && (v = after_label(tmp, L"Type:")) != NULL) {
            free(cur->type); cur->type = cm_wcsdup(v);
        } else if (cur && (v = after_label(tmp, L"User:")) != NULL) {
            free(cur->user); cur->user = cm_wcsdup(v);
        } else if (cur && (v = after_label(tmp, L"Persistence:")) != NULL) {
            free(cur->persistence); cur->persistence = cm_wcsdup(v);
        } else if (cur) {
            wchar_t *t = trimw(tmp);
            if (wcsstr(t, L"Saved for this logon only") ||
                wcsstr(t, L"Local machine persistence") ||
                wcsstr(t, L"Enterprise persistence")) {
                free(cur->persistence); cur->persistence = cm_wcsdup(t);
            }
        }
    }
    if (cur) cm_vec_push(out, cur);
    free(text);
}

void cm_vaultcmd_list(cm_vec *out)
{
    wchar_t *listText = capture_wide(L"vaultcmd.exe /list");
    if (!listText) return;

    cm_vec names; cm_vec_init(&names);
    cm_vec guids; cm_vec_init(&guids);
    wchar_t *pendingName = NULL;
    wchar_t *ctx = NULL;
    for (wchar_t *line = wcstok(listText, L"\n", &ctx); line; line = wcstok(NULL, L"\n", &ctx)) {
        wchar_t tmp[1024]; wcsncpy(tmp, line, 1023); tmp[1023] = L'\0';
        wchar_t *v;
        if ((v = after_label(tmp, L"Vault:")) != NULL) {
            free(pendingName); pendingName = cm_wcsdup(v);
        } else {
            wchar_t *t = trimw(tmp);
            wchar_t *gp = NULL;

            if (_wcsnicmp(t, L"Vault Guid:", 11) == 0) gp = trimw(t + 11);
            if (gp && pendingName) {
                cm_vec_push(&names, cm_wcsdup(pendingName));
                cm_vec_push(&guids, cm_wcsdup(gp));
                free(pendingName); pendingName = NULL;
            }
        }
    }
    free(pendingName);
    free(listText);

    for (size_t i = 0; i < names.count; i++) {
        wchar_t cmd[512];
        swprintf(cmd, 512, L"vaultcmd.exe /listcreds:\"%ls\" /all", (wchar_t *)names.items[i]);
        wchar_t *credsText = capture_wide(cmd);
        if (!credsText) continue;

        wchar_t *resource = NULL, *identity = NULL, *schema = NULL;
        wchar_t *c2 = NULL;
        for (wchar_t *line = wcstok(credsText, L"\n", &c2); line; line = wcstok(NULL, L"\n", &c2)) {
            wchar_t tmp[1024]; wcsncpy(tmp, line, 1023); tmp[1023] = L'\0';
            wchar_t *v;
            if ((v = after_label(tmp, L"Credential schema:")) != NULL) {
                free(schema); schema = cm_wcsdup(v);
            } else if ((v = after_label(tmp, L"Resource:")) != NULL) {
                free(resource); resource = cm_wcsdup(v);
            } else if ((v = after_label(tmp, L"Identity:")) != NULL) {
                free(identity); identity = cm_wcsdup(v);
            } else {
                wchar_t *t = trimw(tmp);
                bool boundary = (t[0] == L'\0') || (_wcsnicmp(t, L"Credential schema:", 18) == 0);
                if (boundary && resource && identity) {
                    cm_vaultcmd_cred *vc = (cm_vaultcmd_cred *)calloc(1, sizeof(cm_vaultcmd_cred));
                    if (vc) {
                        vc->target = resource; vc->username = identity;
                        vc->type = schema ? schema : cm_wcsdup(L"");
                        vc->vault_name = cm_wcsdup((wchar_t *)names.items[i]);
                        vc->vault_guid = cm_wcsdup((wchar_t *)guids.items[i]);
                        cm_vec_push(out, vc);
                    }
                    resource = identity = schema = NULL;
                }
            }
        }
        if (resource && identity) {
            cm_vaultcmd_cred *vc = (cm_vaultcmd_cred *)calloc(1, sizeof(cm_vaultcmd_cred));
            if (vc) {
                vc->target = resource; vc->username = identity;
                vc->type = schema ? schema : cm_wcsdup(L"");
                vc->vault_name = cm_wcsdup((wchar_t *)names.items[i]);
                vc->vault_guid = cm_wcsdup((wchar_t *)guids.items[i]);
                cm_vec_push(out, vc);
            }
        } else {
            free(resource); free(identity); free(schema);
        }
        free(credsText);
    }

    cm_vec_free(&names, free);
    cm_vec_free(&guids, free);
}

void cm_get_all_vault_guids(cm_vec *out)
{
    wchar_t *text = capture_wide(L"vaultcmd.exe /list");
    if (!text) return;
    wchar_t *ctx = NULL;
    for (wchar_t *line = wcstok(text, L"\n", &ctx); line; line = wcstok(NULL, L"\n", &ctx)) {
        wchar_t tmp[1024]; wcsncpy(tmp, line, 1023); tmp[1023] = L'\0';
        wchar_t *t = trimw(tmp);
        if (_wcsnicmp(t, L"Vault Guid:", 11) == 0) {
            wchar_t *g = trimw(t + 11);
            GUID guid;

            wchar_t braced[64];
            if (g[0] == L'{') swprintf(braced, 64, L"%ls", g);
            else swprintf(braced, 64, L"{%ls}", g);
            if (CLSIDFromString(braced, &guid) == NOERROR) {
                GUID *copy = (GUID *)malloc(sizeof(GUID));
                if (copy) { *copy = guid; cm_vec_push(out, copy); }
            }
        }
    }
    free(text);
}
