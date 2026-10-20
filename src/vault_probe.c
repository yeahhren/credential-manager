#include "vault_probe.h"
#include "crypto.h"
#include <shlobj.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

void cm_vault_probe_free(cm_vault_probe *p)
{
    if (!p) return;
    free(p->vault_guid); free(p->policy_path); free(p->status); free(p->detail);
    free(p);
}

typedef struct { const unsigned char *p; size_t len; size_t pos; bool ok; } rdr;

static void rd_init(rdr *r, const unsigned char *p, size_t len) { r->p=p; r->len=len; r->pos=0; r->ok=true; }
static uint32_t rd_u32(rdr *r){ if(!r->ok||r->pos+4>r->len){r->ok=false;return 0;} uint32_t v; memcpy(&v,r->p+r->pos,4); r->pos+=4; return v; }
static uint64_t rd_u64(rdr *r){ if(!r->ok||r->pos+8>r->len){r->ok=false;return 0;} uint64_t v; memcpy(&v,r->p+r->pos,8); r->pos+=8; return v; }
static uint8_t  rd_u8 (rdr *r){ if(!r->ok||r->pos+1>r->len){r->ok=false;return 0;} return r->p[r->pos++]; }
static const unsigned char *rd_take(rdr *r, size_t n){ if(!r->ok||r->pos+n>r->len){r->ok=false;return NULL;} const unsigned char *q=r->p+r->pos; r->pos+=n; return q; }
static void rd_skip(rdr *r, size_t n){ if(!r->ok||r->pos+n>r->len){r->ok=false;return;} r->pos+=n; }

static wchar_t *vault_base_path(void)
{
    wchar_t *local = NULL;
    if (SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, NULL, &local) != S_OK || !local)
        return NULL;
    wchar_t buf[MAX_PATH];
    swprintf(buf, MAX_PATH, L"%ls\\Microsoft\\Vault", local);
    CoTaskMemFree(local);
    return cm_wcsdup(buf);
}

static const unsigned char DPAPI_MAGIC[16] = {
    0xD0,0x8C,0x9D,0xDF,0x01,0x15,0xD1,0x11,0x8C,0x7A,0x00,0xC0,0x4F,0xC2,0x97,0xEB
};

static unsigned char *vpol_extract_dpapi_blob(const unsigned char *data, size_t len, size_t *out_len)
{
    rdr r; rd_init(&r, data, len);
    rd_u32(&r);
    rd_skip(&r, 16);
    uint32_t descLen = rd_u32(&r);
    rd_skip(&r, descLen);
    rd_u32(&r); rd_u32(&r); rd_u32(&r);
    uint32_t keySize = rd_u32(&r);
    size_t storeStart = r.pos;
    if (!r.ok) return NULL;
    size_t storeEnd = storeStart + keySize;
    if (storeEnd > len) storeEnd = len;

    for (size_t i = storeStart; i + 16 <= storeEnd; i++) {
        if (memcmp(data + i, DPAPI_MAGIC, 16) == 0) {
            size_t blobStart = (i >= 4) ? i - 4 : i;
            size_t blobLen = storeEnd - blobStart;
            unsigned char *copy = (unsigned char *)malloc(blobLen);
            if (copy) { memcpy(copy, data + blobStart, blobLen); if (out_len) *out_len = blobLen; }
            return copy;
        }
    }
    return NULL;
}

static void add_key_candidates(cm_vec *keys, const unsigned char *blob, size_t len)
{

    size_t sizes[2] = {32, 16};
    for (int s = 0; s < 2; s++) {
        size_t k = sizes[s];
        if (len >= k) {
            unsigned char *key = (unsigned char *)malloc(k);
            if (key) { memcpy(key, blob + len - k, k); cm_vec_push(keys, (void *)((uintptr_t)k));  cm_vec_push(keys, key); }
        }
    }

    for (size_t i = 0; i + 4 <= len; i++) {
        if (blob[i]=='K' && blob[i+1]=='S' && blob[i+2]=='S' && blob[i+3]=='M') {
            size_t after = i + 32;
            for (int s = 0; s < 2; s++) {
                size_t k = sizes[s];
                if (after + k <= len) {
                    unsigned char *key = (unsigned char *)malloc(k);
                    if (key) { memcpy(key, blob + after, k); cm_vec_push(keys, (void *)((uintptr_t)k)); cm_vec_push(keys, key); }
                }
            }
            break;
        }
    }
}

static void free_key_vec(cm_vec *v)
{
    for (size_t i = 1; i < v->count; i += 2) free(v->items[i]);
    cm_vec_free(v, NULL);
}

static bool vpol_build_keys(const unsigned char *policyBytes, size_t policyLen,
                            cm_vec *keysOut, wchar_t **detail)
{
    size_t blobLen = 0;
    unsigned char *dpapiBlob = vpol_extract_dpapi_blob(policyBytes, policyLen, &blobLen);
    if (!dpapiBlob) { if (detail) *detail = cm_wcsdup(L"VPOL header parse failed"); return false; }

    DWORD err = 0; size_t decLen = 0;
    unsigned char *dec = cm_dpapi_unprotect(dpapiBlob, blobLen, &decLen, &err);
    if (!dec) dec = cm_dpapi_unprotect_as_system(dpapiBlob, blobLen, &decLen);
    free(dpapiBlob);
    if (!dec) {

        wchar_t buf[200];
        swprintf(buf, 200, L"Policy.vpol key blob is not openable via live DPAPI "
                           L"(ERROR_INVALID_DATA); needs VaultSvc RPC or offline masterkey.");
        if (detail) *detail = cm_wcsdup(buf);
        return false;
    }

    rdr r; rd_init(&r, dec, decLen);
    rd_u32(&r);
    uint32_t size1 = rd_u32(&r);
    const unsigned char *b1 = rd_take(&r, size1);
    rd_u32(&r);
    uint32_t size2 = rd_u32(&r);
    const unsigned char *b2 = rd_take(&r, size2);

    if (r.ok && b1) add_key_candidates(keysOut, b1, size1);
    if (r.ok && b2) add_key_candidates(keysOut, b2, size2);

    if (keysOut->count == 0) add_key_candidates(keysOut, dec, decLen);

    free(dec);
    if (keysOut->count == 0) { if (detail) *detail = cm_wcsdup(L"No AES key candidates in VPOL"); return false; }
    if (detail) *detail = cm_wcsdup(L"VPOL decrypted; key candidates extracted");
    return true;
}

static bool looks_like_payload(const wchar_t *s)
{
    if (!s || !*s) return false;
    size_t n = wcslen(s), printable = 0;
    for (size_t i = 0; i < n; i++) {
        wchar_t c = s[i];
        if (c >= 32 || c == L'\t' || c == L'\n' || c == L'\r') printable++;
    }
    bool mostly = printable >= (n * 8 / 10) && printable >= 4;
    bool markers = wcsstr(s, L"http") || wcsstr(s, L"Resource") ||
                   wcsstr(s, L"Identity") || wcsstr(s, L"@") || wcsstr(s, L"target=");
    return mostly && markers;
}

static wchar_t *decrypt_attribute(const unsigned char *data, size_t dataLen,
                                  const unsigned char *iv, bool hasIV, cm_vec *keys)
{
    if (dataLen < 16 || (dataLen % 16) != 0) return NULL;
    unsigned char zeroIV[16] = {0};
    const unsigned char *useIV = hasIV ? iv : zeroIV;
    wchar_t *best = NULL;
    for (size_t i = 0; i + 1 < keys->count; i += 2) {
        size_t keylen = (size_t)(uintptr_t)keys->items[i];
        const unsigned char *key = (const unsigned char *)keys->items[i + 1];
        size_t plen = 0;
        unsigned char *plain = cm_aes_cbc_decrypt(key, keylen, useIV, data, dataLen, &plen);
        if (!plain) continue;

        size_t chars = plen / 2;
        wchar_t *w = (wchar_t *)malloc((chars + 1) * sizeof(wchar_t));
        if (w) {
            memcpy(w, plain, chars * 2);
            w[chars] = L'\0';
            cm_trim_trailing_nuls(w);
            if (looks_like_payload(w)) {
                if (!best || wcslen(w) > wcslen(best)) { free(best); best = w; w = NULL; }
            }
            free(w);
        }
        free(plain);
    }
    return best;
}

static int vcrd_decrypt(const unsigned char *fileData, size_t fileLen, cm_vec *keys, cm_vec *payloads)
{
    rdr r; rd_init(&r, fileData, fileLen);
    rd_skip(&r, 16);
    rd_u32(&r);
    rd_u64(&r);
    rd_u32(&r); rd_u32(&r);
    uint32_t fnLen = rd_u32(&r);
    rd_skip(&r, fnLen);
    uint32_t mapLen = rd_u32(&r);
    size_t mapStart = r.pos;
    if (!r.ok) return 0;

    int attrCount = (int)(mapLen / 12);
    int recovered = 0;
    for (int i = 0; i < attrCount; i++) {
        rdr m; rd_init(&m, fileData, fileLen); m.pos = mapStart + (size_t)i * 12;
        rd_u32(&m);
        uint32_t off = rd_u32(&m);
        rd_u32(&m);
        if (!m.ok || off >= fileLen) continue;

        rdr a; rd_init(&a, fileData, fileLen); a.pos = off;
        uint32_t id = rd_u32(&a);
        rd_u32(&a); rd_u32(&a); rd_u32(&a);
        if (id >= 100) rd_u32(&a);
        uint32_t size = rd_u32(&a);
        if (!a.ok || size == 0) continue;
        size_t dataStart = a.pos;
        uint8_t hasIV = rd_u8(&a);
        const unsigned char *iv = NULL; uint32_t ivLen = 0;
        if (hasIV) { ivLen = rd_u32(&a); iv = rd_take(&a, ivLen); }
        if (!a.ok) continue;

        size_t consumed = 1 + (hasIV ? (4 + ivLen) : 0);
        if (consumed > size) continue;
        size_t dataLen = size - consumed;
        const unsigned char *data = rd_take(&a, dataLen);
        if (!a.ok || !data) continue;
        (void)dataStart;

        wchar_t *payload = decrypt_attribute(data, dataLen, iv, hasIV != 0, keys);
        if (payload) { cm_vec_push(payloads, payload); recovered++; }
    }
    return recovered;
}

typedef void (*vault_dir_cb)(const wchar_t *vaultDir, const wchar_t *guid, void *ctx);

static void for_each_vault_dir(vault_dir_cb cb, void *ctx)
{
    wchar_t *base = vault_base_path();
    if (!base) return;
    wchar_t pattern[MAX_PATH];
    swprintf(pattern, MAX_PATH, L"%ls\\*", base);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (fd.cFileName[0] == L'.') continue;
            wchar_t dir[MAX_PATH];
            swprintf(dir, MAX_PATH, L"%ls\\%ls", base, fd.cFileName);
            cb(dir, fd.cFileName, ctx);
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    free(base);
}

static bool load_vault_keys(const wchar_t *vaultDir, cm_vec *keysOut, wchar_t **detail)
{
    wchar_t policy[MAX_PATH];
    swprintf(policy, MAX_PATH, L"%ls\\Policy.vpol", vaultDir);
    size_t plen = 0;
    unsigned char *pbytes = cm_read_file(policy, &plen);
    if (!pbytes) { if (detail) *detail = cm_wcsdup(L"Policy.vpol not found"); return false; }
    bool ok = vpol_build_keys(pbytes, plen, keysOut, detail);
    free(pbytes);
    return ok;
}

static int process_vault_vcrds(const wchar_t *vaultDir, cm_vec *keys,
                               int *fileCount, cm_vec *payloadsOut)
{
    wchar_t pattern[MAX_PATH];
    swprintf(pattern, MAX_PATH, L"%ls\\*.vcrd", vaultDir);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    int decrypted = 0, files = 0;
    if (h != INVALID_HANDLE_VALUE) {
        do {
            files++;
            wchar_t path[MAX_PATH];
            swprintf(path, MAX_PATH, L"%ls\\%ls", vaultDir, fd.cFileName);
            size_t flen = 0;
            unsigned char *fbytes = cm_read_file(path, &flen);
            if (fbytes) {
                cm_vec local; cm_vec_init(&local);
                int rec = vcrd_decrypt(fbytes, flen, keys, payloadsOut ? payloadsOut : &local);
                if (rec > 0) decrypted++;
                if (!payloadsOut) cm_vec_free(&local, free);
                free(fbytes);
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    if (fileCount) *fileCount = files;
    return decrypted;
}

typedef struct { cm_vec *out; } probe_ctx;

static void probe_one(const wchar_t *vaultDir, const wchar_t *guid, void *ctxv)
{
    probe_ctx *ctx = (probe_ctx *)ctxv;
    cm_vault_probe *p = (cm_vault_probe *)calloc(1, sizeof(cm_vault_probe));
    if (!p) return;
    p->vault_guid = cm_wcsdup(guid);
    wchar_t policy[MAX_PATH];
    swprintf(policy, MAX_PATH, L"%ls\\Policy.vpol", vaultDir);
    p->policy_path = cm_wcsdup(policy);

    cm_vec keys; cm_vec_init(&keys);
    wchar_t *detail = NULL;
    if (!load_vault_keys(vaultDir, &keys, &detail)) {
        p->status = cm_wcsdup(detail && wcsstr(detail, L"not found") ? L"NO-POLICY" : L"POLICY-DPAPI-FAIL");
        p->detail = detail ? detail : cm_wcsdup(L"Policy decryption failed");
        free_key_vec(&keys);
        cm_vec_push(ctx->out, p);
        return;
    }
    free(detail);

    int files = 0;
    int decrypted = process_vault_vcrds(vaultDir, &keys, &files, NULL);
    p->credential_file_count = files;
    p->decrypted_credential_count = decrypted;
    if (files == 0) { p->status = cm_wcsdup(L"NO-FILES"); p->detail = cm_wcsdup(L"No .vcrd credential files found"); }
    else if (decrypted > 0) {
        wchar_t buf[128];
        swprintf(buf, 128, L"Recovered %d of %d credential file(s)", decrypted, files);
        p->status = cm_wcsdup(L"DECRYPTED"); p->detail = cm_wcsdup(buf);
    } else {
        p->status = cm_wcsdup(L"DECRYPT-FAILED");
        p->detail = cm_wcsdup(L"Policy.vpol decrypted, but no .vcrd produced a recognizable payload");
    }
    free_key_vec(&keys);
    cm_vec_push(ctx->out, p);
}

void cm_vault_probe_all(cm_vec *out)
{
    probe_ctx ctx = { out };
    for_each_vault_dir(probe_one, &ctx);
}

static void direct_one(const wchar_t *vaultDir, const wchar_t *guid, void *ctxv)
{
    cm_vec *out = (cm_vec *)ctxv;
    cm_vec keys; cm_vec_init(&keys);
    wchar_t *detail = NULL;
    if (!load_vault_keys(vaultDir, &keys, &detail)) { free(detail); free_key_vec(&keys); return; }
    free(detail);

    cm_vec payloads; cm_vec_init(&payloads);
    int files = 0;
    process_vault_vcrds(vaultDir, &keys, &files, &payloads);
    for (size_t i = 0; i < payloads.count; i++) {
        cm_vaultcred *c = (cm_vaultcred *)calloc(1, sizeof(cm_vaultcred));
        if (c) {
            c->friendly_name = cm_wcsdup(L"(decrypted .vcrd)");
            c->authenticator = cm_wcsdup((wchar_t *)payloads.items[i]);
            c->resource = cm_wcsdup(guid);

            cm_vec_push(out, c);
        }
    }
    cm_vec_free(&payloads, free);
    free_key_vec(&keys);
}

void cm_vault_decrypt_direct(cm_vec *out)
{
    for_each_vault_dir(direct_one, out);
}
