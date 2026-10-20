#include "cred_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifndef CRED_ENUMERATE_ALL_CREDENTIALS
#define CRED_ENUMERATE_ALL_CREDENTIALS 0x1
#endif

void cm_credential_free(cm_credential *c)
{
    if (!c) return;
    free(c->target); free(c->username); free(c->password); free(c->comment);
    free(c);
}

void cm_snapshot_free(cm_snapshot *s)
{
    if (!s) return;
    free(s->target); free(s->username); free(s->comment); free(s->blob); free(s->secret);
    free(s);
}

const wchar_t *cm_credential_type_name(DWORD type)
{
    switch (type) {
        case CM_CRED_GENERIC: return L"Generic";
        case CM_CRED_DOMAIN_PASSWORD: return L"DomainPassword";
        case CM_CRED_DOMAIN_CERTIFICATE: return L"DomainCertificate";
        case CM_CRED_DOMAIN_VISIBLE_PASSWORD: return L"DomainVisiblePassword";
        case CM_CRED_GENERIC_CERTIFICATE: return L"GenericCertificate";
        case CM_CRED_DOMAIN_EXTENDED: return L"DomainExtended";
        default: return L"Unknown";
    }
}

static wchar_t *read_cert_thumbprint(const BYTE *blob, DWORD size)
{
    if (size < sizeof(CERT_CREDENTIAL_INFO)) return NULL;
    const CERT_CREDENTIAL_INFO *ci = (const CERT_CREDENTIAL_INFO *)blob;
    return cm_bytes_to_hex(ci->rgbHashOfCert, 20);
}

wchar_t *cm_read_credential_blob(const CREDENTIALW *cred)
{
    if (!cred || cred->CredentialBlobSize == 0 || !cred->CredentialBlob) return NULL;
    DWORD type = cred->Type;
    if (type == CM_CRED_DOMAIN_CERTIFICATE || type == CM_CRED_GENERIC_CERTIFICATE)
        return read_cert_thumbprint(cred->CredentialBlob, cred->CredentialBlobSize);

    DWORD n = cred->CredentialBlobSize;
    if ((n % 2) != 0) {

        char *b64 = cm_base64_encode(cred->CredentialBlob, n);
        wchar_t *w = cm_utf8_to_wide(b64, -1);
        free(b64);
        return w;
    }
    size_t chars = n / 2;
    wchar_t *w = (wchar_t *)malloc((chars + 1) * sizeof(wchar_t));
    if (!w) return NULL;
    memcpy(w, cred->CredentialBlob, n);
    w[chars] = L'\0';
    cm_trim_trailing_nuls(w);
    return w;
}

static cm_credential *credential_from_struct(const CREDENTIALW *c)
{
    cm_credential *out = (cm_credential *)calloc(1, sizeof(cm_credential));
    if (!out) return NULL;
    out->type = c->Type;

    const wchar_t *uname = c->UserName;
    if ((c->Type == CM_CRED_DOMAIN_CERTIFICATE || c->Type == CM_CRED_GENERIC_CERTIFICATE)
        && c->Comment && c->Comment[0])
        uname = c->Comment;
    out->username = cm_wcsdup(uname ? uname : L"");
    out->password = cm_read_credential_blob(c);
    out->target   = cm_wcsdup(c->TargetName ? c->TargetName : L"");
    out->comment  = cm_wcsdup(c->Comment ? c->Comment : L"");
    out->persist  = c->Persist;
    out->last_written = ((long long)c->LastWritten.dwHighDateTime << 32) | c->LastWritten.dwLowDateTime;
    return out;
}

wchar_t *cm_snapshot_key(const wchar_t *target, DWORD type, const wchar_t *username)
{
    wchar_t tbuf[16];
    swprintf(tbuf, 16, L"%lu", (unsigned long)type);
    const wchar_t *t = target ? target : L"";
    const wchar_t *u = username ? username : L"";
    size_t n = wcslen(t) + wcslen(u) + wcslen(tbuf) + 3;
    wchar_t *key = (wchar_t *)malloc(n * sizeof(wchar_t));
    if (key) swprintf(key, n, L"%ls\x1f%ls\x1f%ls", t, tbuf, u);
    return key;
}

void cm_credential_load_all(cm_vec *out)
{
    static const wchar_t *filters[] = {
        NULL, L"*", L"MicrosoftAccount:*", L"WindowsLive:*", L"LegacyGeneric:*", L"Domain:*"
    };
    cm_vec seen; cm_vec_init(&seen);

    for (int f = 0; f < 6; f++) {
        DWORD count = 0;
        PCREDENTIALW *creds = NULL;
        if (!CredEnumerateW(filters[f], CRED_ENUMERATE_ALL_CREDENTIALS, &count, &creds))
            continue;
        for (DWORD i = 0; i < count; i++) {
            const CREDENTIALW *c = creds[i];
            wchar_t *key = cm_snapshot_key(c->TargetName, c->Type, c->UserName);
            bool dup = false;
            for (size_t k = 0; k < seen.count; k++)
                if (wcscmp((wchar_t *)seen.items[k], key) == 0) { dup = true; break; }
            if (dup) { free(key); continue; }
            cm_vec_push(&seen, key);
            cm_credential *cc = credential_from_struct(c);
            if (cc) cm_vec_push(out, cc);
        }
        CredFree(creds);
    }
    cm_vec_free(&seen, free);
}

bool cm_credential_write(DWORD type, const wchar_t *target, const wchar_t *username,
                         const wchar_t *comment, DWORD persist,
                         const unsigned char *blob, DWORD blobSize, DWORD *win32err)
{
    CREDENTIALW c = {0};
    c.Type = type;
    c.TargetName = (LPWSTR)target;
    c.Comment = (LPWSTR)comment;
    c.Persist = persist;
    c.UserName = (LPWSTR)username;
    c.CredentialBlobSize = blobSize;
    c.CredentialBlob = (LPBYTE)blob;
    SetLastError(0);
    BOOL ok = CredWriteW(&c, 0);
    if (!ok && win32err) *win32err = GetLastError();
    return ok != 0;
}

bool cm_credential_delete(const wchar_t *target, DWORD type, DWORD *win32err)
{
    SetLastError(0);
    BOOL ok = CredDeleteW(target, type, 0);
    if (!ok && win32err) *win32err = GetLastError();
    return ok != 0;
}

wchar_t *cm_marshal_certificate_username(const unsigned char hash20[20], DWORD *win32err)
{
    CERT_CREDENTIAL_INFO ci = {0};
    ci.cbSize = sizeof(ci);
    memcpy(ci.rgbHashOfCert, hash20, 20);
    LPWSTR marshaled = NULL;
    SetLastError(0);
    if (!CredMarshalCredentialW(CertCredential, &ci, &marshaled) || !marshaled) {
        if (win32err) *win32err = GetLastError();
        return NULL;
    }
    wchar_t *copy = cm_wcsdup(marshaled);
    CredFree(marshaled);
    return copy;
}

void cm_capture_snapshots(cm_vec *out)
{
    DWORD count = 0;
    PCREDENTIALW *creds = NULL;
    if (!CredEnumerateW(NULL, CRED_ENUMERATE_ALL_CREDENTIALS, &count, &creds))
        return;
    for (DWORD i = 0; i < count; i++) {
        const CREDENTIALW *c = creds[i];
        cm_snapshot *s = (cm_snapshot *)calloc(1, sizeof(cm_snapshot));
        if (!s) continue;
        s->target = cm_wcsdup(c->TargetName ? c->TargetName : L"");
        s->username = cm_wcsdup(c->UserName ? c->UserName : L"");
        s->comment = cm_wcsdup(c->Comment ? c->Comment : L"");
        s->type = c->Type;
        s->persist = c->Persist;
        s->blob_size = c->CredentialBlobSize;
        if (c->CredentialBlobSize && c->CredentialBlob) {
            s->blob = (unsigned char *)malloc(c->CredentialBlobSize);
            if (s->blob) memcpy(s->blob, c->CredentialBlob, c->CredentialBlobSize);
        }
        s->secret = cm_read_credential_blob(c);
        cm_vec_push(out, s);
    }
    CredFree(creds);
}

bool cm_write_snapshot(const cm_snapshot *s, DWORD *win32err)
{
    return cm_credential_write(s->type, s->target, s->username, s->comment,
                               s->persist, s->blob, s->blob_size, win32err);
}

wchar_t *cm_snapshot_fingerprint(const cm_snapshot *s)
{
    char *b64 = cm_base64_encode(s->blob ? s->blob : (const unsigned char *)"", s->blob_size);
    wchar_t *wb64 = cm_utf8_to_wide(b64 ? b64 : "", -1);
    free(b64);
    const wchar_t *comment = s->comment ? s->comment : L"";
    wchar_t pbuf[16];
    swprintf(pbuf, 16, L"%lu", (unsigned long)s->persist);
    size_t n = wcslen(comment) + wcslen(pbuf) + wcslen(wb64 ? wb64 : L"") + 3;
    wchar_t *fp = (wchar_t *)malloc(n * sizeof(wchar_t));
    if (fp) swprintf(fp, n, L"%ls\x1f%ls\x1f%ls", comment, pbuf, wb64 ? wb64 : L"");
    free(wb64);
    return fp;
}
