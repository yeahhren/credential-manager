#include "cert.h"
#include <wincrypt.h>
#include <stdlib.h>
#include <string.h>

void cm_certinfo_free(cm_certinfo *c)
{
    if (!c) return;
    free(c->thumbprint); free(c->subject); free(c);
}

static long long filetime_ll(const FILETIME *ft)
{
    return ((long long)ft->dwHighDateTime << 32) | ft->dwLowDateTime;
}

static long long now_ll(void)
{
    FILETIME ft; GetSystemTimeAsFileTime(&ft); return filetime_ll(&ft);
}

static int days_until(long long fileTime)
{
    long long diff = fileTime - now_ll();
    return (int)(diff / (10000000LL * 60 * 60 * 24));
}

static cm_certinfo *build_info(PCCERT_CONTEXT ctx)
{
    cm_certinfo *info = (cm_certinfo *)calloc(1, sizeof(cm_certinfo));
    if (!info) return NULL;

    BYTE hash[20]; DWORD hlen = sizeof(hash);
    if (CertGetCertificateContextProperty(ctx, CERT_SHA1_HASH_PROP_ID, hash, &hlen) && hlen == 20)
        info->thumbprint = cm_bytes_to_hex(hash, 20);
    else
        info->thumbprint = cm_wcsdup(L"");

    DWORD slen = CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
    if (slen > 1) {
        info->subject = (wchar_t *)malloc(slen * sizeof(wchar_t));
        if (info->subject)
            CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, info->subject, slen);
    }
    if (!info->subject) info->subject = cm_wcsdup(L"");

    info->not_before = filetime_ll(&ctx->pCertInfo->NotBefore);
    info->not_after  = filetime_ll(&ctx->pCertInfo->NotAfter);
    long long n = now_ll();
    info->is_valid = (n >= info->not_before && n <= info->not_after);
    info->key_size = (int)CertGetPublicKeyLength(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                 &ctx->pCertInfo->SubjectPublicKeyInfo);
    info->expiry_days = days_until(info->not_after);
    info->expiry_status = (info->expiry_days < 0) ? L"Expired"
                        : (info->expiry_days < 30) ? L"Expiring" : L"Valid";

    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0; DWORD spec = 0; BOOL freeKey = FALSE;
    if (CryptAcquireCertificatePrivateKey(ctx, CRYPT_ACQUIRE_SILENT_FLAG, NULL, &hKey, &spec, &freeKey)) {
        info->has_private_key = true;
        if (freeKey) {
            if (spec == CERT_NCRYPT_KEY_SPEC) NCryptFreeObject(hKey);
            else CryptReleaseContext(hKey, 0);
        }
    }
    return info;
}

void cm_cert_enumerate(cm_vec *out)
{
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                     CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
                                     L"MY");
    if (!store) return;
    PCCERT_CONTEXT ctx = NULL;
    while ((ctx = CertEnumCertificatesInStore(store, ctx)) != NULL) {
        cm_certinfo *info = build_info(ctx);
        if (info) cm_vec_push(out, info);
    }
    CertCloseStore(store, 0);
}

wchar_t *cm_cert_normalize_thumbprint(const wchar_t *thumb)
{
    if (!thumb) return cm_wcsdup(L"");
    size_t n = wcslen(thumb);
    wchar_t *out = (wchar_t *)malloc((n + 1) * sizeof(wchar_t));
    if (!out) return NULL;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        wchar_t c = thumb[i];
        if ((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F'))
            out[o++] = (wchar_t)towupper(c);
    }
    out[o] = L'\0';
    return out;
}

cm_certinfo *cm_cert_find(const wchar_t *thumbprint)
{
    wchar_t *norm = cm_cert_normalize_thumbprint(thumbprint);
    cm_certinfo *found = NULL;
    if (norm && wcslen(norm) == 40) {
        cm_vec certs; cm_vec_init(&certs);
        cm_cert_enumerate(&certs);
        for (size_t i = 0; i < certs.count; i++) {
            cm_certinfo *c = (cm_certinfo *)certs.items[i];
            wchar_t *cn = cm_cert_normalize_thumbprint(c->thumbprint);
            if (cn && wcscmp(cn, norm) == 0 && !found) {
                found = c; certs.items[i] = NULL;
            }
            free(cn);
        }
        cm_vec_free(&certs, (void (*)(void *))cm_certinfo_free);
    }
    free(norm);
    return found;
}

bool cm_cert_is_usable(const wchar_t *thumbprint, wchar_t **message_out)
{
    wchar_t *norm = cm_cert_normalize_thumbprint(thumbprint);
    bool usable = false;
    const wchar_t *msg = NULL;
    if (!norm || wcslen(norm) != 40) {
        msg = L"Certificate thumbprint must contain exactly 40 hexadecimal characters.";
    } else {
        cm_certinfo *c = cm_cert_find(norm);
        if (!c) {
            msg = L"The specified certificate was not found in the Current User > Personal store.";
        } else if (!c->has_private_key) {
            msg = L"The selected certificate does not have an accessible private key.";
        } else {
            usable = true;
        }
        if (c) cm_certinfo_free(c);
    }
    if (message_out) *message_out = msg ? cm_wcsdup(msg) : NULL;
    free(norm);
    return usable;
}
