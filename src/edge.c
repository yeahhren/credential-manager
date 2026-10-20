#include "edge.h"
#include "crypto.h"
#include <shlobj.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define SQLITE_OK 0
#define SQLITE_ROW 100
#define SQLITE_DONE 101
static const void *SQLITE_TRANSIENT = (const void *)(intptr_t)-1;

typedef int   (*pf_open16)(const void *, void **);
typedef int   (*pf_close)(void *);
typedef int   (*pf_prepare16)(void *, const void *, int, void **, const void **);
typedef int   (*pf_step)(void *);
typedef int   (*pf_finalize)(void *);
typedef int   (*pf_reset)(void *);
typedef const void *(*pf_errmsg16)(void *);
typedef const void *(*pf_column_text16)(void *, int);
typedef const void *(*pf_column_blob)(void *, int);
typedef int   (*pf_column_bytes)(void *, int);
typedef long long (*pf_column_int64)(void *, int);
typedef int   (*pf_bind_int64)(void *, int, long long);
typedef int   (*pf_bind_text16)(void *, int, const void *, int, const void *);
typedef int   (*pf_bind_blob)(void *, int, const void *, int, const void *);

static struct {
    HMODULE lib; bool tried;
    pf_open16 open16; pf_close close; pf_prepare16 prepare16; pf_step step;
    pf_finalize finalize; pf_reset reset; pf_errmsg16 errmsg16;
    pf_column_text16 col_text16; pf_column_blob col_blob; pf_column_bytes col_bytes;
    pf_column_int64 col_int64; pf_bind_int64 bind_int64; pf_bind_text16 bind_text16;
    pf_bind_blob bind_blob;
} sq;

static void load_sqlite(void)
{
    if (sq.tried) return;
    sq.tried = true;
    sq.lib = LoadLibraryW(L"winsqlite3.dll");
    if (!sq.lib) return;
#define L(n,f) sq.n = (f)(void*)GetProcAddress(sq.lib, "sqlite3_" #n)
    L(open16, pf_open16); L(close, pf_close); L(prepare16, pf_prepare16); L(step, pf_step);
    L(finalize, pf_finalize); L(reset, pf_reset); L(errmsg16, pf_errmsg16);
    L(col_text16, pf_column_text16);
    sq.col_blob = (pf_column_blob)(void*)GetProcAddress(sq.lib, "sqlite3_column_blob");
    sq.col_bytes = (pf_column_bytes)(void*)GetProcAddress(sq.lib, "sqlite3_column_bytes");
    sq.col_int64 = (pf_column_int64)(void*)GetProcAddress(sq.lib, "sqlite3_column_int64");
    sq.bind_int64 = (pf_bind_int64)(void*)GetProcAddress(sq.lib, "sqlite3_bind_int64");
    sq.bind_text16 = (pf_bind_text16)(void*)GetProcAddress(sq.lib, "sqlite3_bind_text16");
    sq.bind_blob = (pf_bind_blob)(void*)GetProcAddress(sq.lib, "sqlite3_bind_blob");
#undef L
}

bool cm_edge_available(void) { load_sqlite(); return sq.lib && sq.open16 && sq.prepare16; }

void cm_edge_cred_free(cm_edge_cred *c)
{
    if (!c) return;
    free(c->profile_name); free(c->profile_directory); free(c->profile_path);
    free(c->website); free(c->action_url); free(c->username); free(c->password);
    free(c->last_used); free(c->enc_version);
    free(c);
}

static char *json_find_string(const char *json, const char *key)
{
    if (!json) return NULL;
    size_t klen = strlen(key);
    char needle[128];
    if (klen + 3 >= sizeof(needle)) return NULL;
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return NULL;
    p += strlen(needle);
    while (*p && *p != ':') p++;
    if (*p != ':') return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '"') return NULL;
    p++;
    const char *start = p;
    while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; }
    size_t n = (size_t)(p - start);
    char *out = (char *)malloc(n + 1);
    if (out) { memcpy(out, start, n); out[n] = '\0'; }
    return out;
}

static unsigned char *extract_elevation_key(const unsigned char *data, size_t len, size_t *out_len)
{
    if (!data || len < 8) return NULL;
    uint32_t validationLen; memcpy(&validationLen, data, 4);
    size_t keyOffset = 4 + validationLen;
    if (len < keyOffset + 4) return NULL;
    uint32_t keyLen; memcpy(&keyLen, data + keyOffset, 4);
    size_t keyStart = keyOffset + 4;
    if (len < keyStart + keyLen || keyLen != 32) return NULL;
    unsigned char *key = (unsigned char *)malloc(keyLen);
    if (key) { memcpy(key, data + keyStart, keyLen); if (out_len) *out_len = keyLen; }
    return key;
}

typedef struct {
    unsigned char *master_key; size_t master_len; wchar_t *master_err;
    unsigned char *appbound_key; size_t appbound_len; wchar_t *appbound_err;
} local_state;

static void local_state_free(local_state *s)
{
    free(s->master_key); free(s->appbound_key); free(s->master_err); free(s->appbound_err);
}

static unsigned char *decode_master_key(const char *b64, size_t *out_len, wchar_t **err)
{
    size_t rawLen = 0;
    unsigned char *raw = cm_base64_decode(b64, &rawLen);
    if (!raw || rawLen < 6 || memcmp(raw, "DPAPI", 5) != 0) {
        if (err) *err = cm_wcsdup(L"encrypted_key missing DPAPI prefix");
        free(raw); return NULL;
    }
    DWORD e = 0;
    unsigned char *key = cm_dpapi_unprotect(raw + 5, rawLen - 5, out_len, &e);
    free(raw);
    if (!key && err) { wchar_t b[64]; swprintf(b,64,L"DPAPI failed (Win32 %lu)",(unsigned long)e); *err = cm_wcsdup(b); }
    return key;
}

static unsigned char *decode_appbound_key(const char *b64, size_t *out_len, wchar_t **err)
{
    size_t rawLen = 0;
    unsigned char *raw = cm_base64_decode(b64, &rawLen);
    if (!raw || rawLen == 0) { if (err) *err = cm_wcsdup(L"app_bound_encrypted_key empty"); free(raw); return NULL; }
    const unsigned char *appb = raw; size_t appbLen = rawLen;
    if (rawLen > 4 && memcmp(raw, "APPB", 4) == 0) { appb = raw + 4; appbLen = rawLen - 4; }

    size_t sysLen = 0;
    unsigned char *sysDec = cm_dpapi_unprotect_as_system(appb, appbLen, &sysLen);
    if (!sysDec) { if (err) *err = cm_wcsdup(L"SYSTEM-level DPAPI unprotect failed (run elevated)"); free(raw); return NULL; }
    size_t userLen = 0;
    unsigned char *userDec = cm_dpapi_unprotect(sysDec, sysLen, &userLen, NULL);
    free(sysDec); free(raw);
    if (!userDec) { if (err) *err = cm_wcsdup(L"user DPAPI unprotect failed"); return NULL; }
    unsigned char *key = extract_elevation_key(userDec, userLen, out_len);
    free(userDec);
    if (!key && err) *err = cm_wcsdup(L"elevation key extraction failed");
    return key;
}

static wchar_t *edge_user_data_path(void)
{
    wchar_t *local = NULL;
    if (SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, NULL, &local) != S_OK || !local) return NULL;
    wchar_t buf[MAX_PATH];
    swprintf(buf, MAX_PATH, L"%ls\\Microsoft\\Edge\\User Data", local);
    CoTaskMemFree(local);
    DWORD attr = GetFileAttributesW(buf);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) return NULL;
    return cm_wcsdup(buf);
}

static void load_local_state(const wchar_t *userDataPath, local_state *out, char **rawJsonOut)
{
    memset(out, 0, sizeof(*out));
    wchar_t path[MAX_PATH];
    swprintf(path, MAX_PATH, L"%ls\\Local State", userDataPath);
    size_t len = 0;
    unsigned char *bytes = cm_read_file(path, &len);
    if (!bytes) { out->master_err = cm_wcsdup(L"Local State file not found."); return; }
    char *json = (char *)malloc(len + 1);
    if (!json) { free(bytes); return; }
    memcpy(json, bytes, len); json[len] = '\0'; free(bytes);

    char *ek = json_find_string(json, "encrypted_key");
    if (ek) { out->master_key = decode_master_key(ek, &out->master_len, &out->master_err); free(ek); }
    else out->master_err = cm_wcsdup(L"os_crypt.encrypted_key missing.");

    char *ab = json_find_string(json, "app_bound_encrypted_key");
    if (ab) { out->appbound_key = decode_appbound_key(ab, &out->appbound_len, &out->appbound_err); free(ab); }
    else out->appbound_err = cm_wcsdup(L"os_crypt.app_bound_encrypted_key missing.");

    if (rawJsonOut) *rawJsonOut = json; else free(json);
}

static const wchar_t *enc_version(const unsigned char *blob, size_t len)
{
    if (!blob || len == 0) return L"EMPTY";
    if (len >= 3) {
        if (!memcmp(blob, "v10", 3)) return L"v10";
        if (!memcmp(blob, "v11", 3)) return L"v11";
        if (!memcmp(blob, "v20", 3)) return L"v20";
    }
    return L"dpapi/raw";
}

static wchar_t *decode_password_bytes(const unsigned char *plain, size_t len)
{
    if (!plain || len == 0) return cm_wcsdup(L"");

    char *tmp = (char *)malloc(len + 1);
    if (tmp) { memcpy(tmp, plain, len); tmp[len] = '\0'; }
    wchar_t *w = tmp ? cm_utf8_to_wide(tmp, -1) : NULL;
    free(tmp);
    if (w && !wcschr(w, 0xFFFD) && w[0]) return w;
    free(w);
    if ((len % 2) == 0) {
        size_t chars = len / 2;
        wchar_t *u = (wchar_t *)malloc((chars + 1) * sizeof(wchar_t));
        if (u) { memcpy(u, plain, len); u[chars] = L'\0'; cm_trim_trailing_nuls(u); return u; }
    }
    char *b64 = cm_base64_encode(plain, len);
    wchar_t *r = cm_utf8_to_wide(b64 ? b64 : "", -1);
    free(b64);
    return r;
}

static wchar_t *aes_gcm_password(const unsigned char *blob, size_t len,
                                 const unsigned char *key, size_t keyLen)
{
    if (len < 3 + 12 + 16) return cm_wcsdup(L"[blob too short]");
    const unsigned char *nonce = blob + 3;
    size_t cipherLen = len - 3 - 12 - 16;
    const unsigned char *cipher = blob + 15;
    const unsigned char *tag = blob + 15 + cipherLen;
    size_t plen = 0;
    unsigned char *plain = cm_aes_gcm_decrypt(key, keyLen, nonce, 12, cipher, cipherLen, tag, 16, &plen);
    if (!plain) return cm_wcsdup(L"[decrypt failed]");
    wchar_t *w = decode_password_bytes(plain, plen);
    free(plain);
    return w;
}

static wchar_t *decrypt_password(const unsigned char *blob, size_t len, local_state *ls)
{
    if (!blob || len == 0) return cm_wcsdup(L"");
    const wchar_t *ver = enc_version(blob, len);
    if (!wcscmp(ver, L"v10") || !wcscmp(ver, L"v11")) {
        if (!ls->master_key)
            return cm_wcsdup(ls->master_err ? ls->master_err : L"[Master key unavailable]");
        return aes_gcm_password(blob, len, ls->master_key, ls->master_len);
    }
    if (!wcscmp(ver, L"v20")) {
        if (!ls->appbound_key)
            return cm_wcsdup(ls->appbound_err ? ls->appbound_err : L"[v20 app-bound key unavailable]");
        return aes_gcm_password(blob, len, ls->appbound_key, ls->appbound_len);
    }
    DWORD e = 0; size_t plen = 0;
    unsigned char *plain = cm_dpapi_unprotect(blob, len, &plen, &e);
    if (!plain) return cm_wcsdup(L"[DPAPI decrypt failed]");
    wchar_t *w = decode_password_bytes(plain, plen);
    free(plain);
    return w;
}

static wchar_t *profile_display_name(const char *json, const wchar_t *dir)
{
    if (!json) return cm_wcsdup(dir);
    char *dir8 = cm_wide_to_utf8(dir, -1);
    if (!dir8) return cm_wcsdup(dir);
    char needle[160];
    snprintf(needle, sizeof(needle), "\"%s\"", dir8);
    free(dir8);
    const char *p = strstr(json, needle);
    wchar_t *result = NULL;
    if (p) {
        const char *np = strstr(p, "\"name\"");
        if (np) {
            np += 6;
            while (*np && *np != ':') np++;
            if (*np == ':') { np++; while (*np==' '||*np=='\t') np++;
                if (*np == '"') { np++; const char *s = np; while (*np && *np != '"'){ if(*np=='\\'&&np[1])np++; np++; }
                    result = cm_utf8_to_wide(s, (int)(np - s)); } }
        }
    }
    return result ? result : cm_wcsdup(dir);
}

static void copy_db_with_sidecars(const wchar_t *src, const wchar_t *dst)
{
    CopyFileW(src, dst, FALSE);
    wchar_t s[MAX_PATH], d[MAX_PATH];
    swprintf(s, MAX_PATH, L"%ls-wal", src); swprintf(d, MAX_PATH, L"%ls-wal", dst);
    if (GetFileAttributesW(s) != INVALID_FILE_ATTRIBUTES) CopyFileW(s, d, FALSE);
    swprintf(s, MAX_PATH, L"%ls-shm", src); swprintf(d, MAX_PATH, L"%ls-shm", dst);
    if (GetFileAttributesW(s) != INVALID_FILE_ATTRIBUTES) CopyFileW(s, d, FALSE);
}

static void temp_db_path(wchar_t *out, size_t cap)
{
    wchar_t tmp[MAX_PATH]; GetTempPathW(MAX_PATH, tmp);
    swprintf(out, cap, L"%lscm_edge_%lu_%lu.db", tmp, GetCurrentProcessId(), GetTickCount());
}

static wchar_t *col_text(void *stmt, int i)
{
    const void *p = sq.col_text16(stmt, i);
    return p ? cm_wcsdup((const wchar_t *)p) : cm_wcsdup(L"");
}

static void read_profile(const wchar_t *userDataPath, const wchar_t *dirName,
                         const char *json, local_state *ls, cm_vec *out)
{
    wchar_t loginData[MAX_PATH];
    swprintf(loginData, MAX_PATH, L"%ls\\%ls\\Login Data", userDataPath, dirName);
    if (GetFileAttributesW(loginData) == INVALID_FILE_ATTRIBUTES) return;

    wchar_t profilePath[MAX_PATH];
    swprintf(profilePath, MAX_PATH, L"%ls\\%ls", userDataPath, dirName);
    wchar_t *display = profile_display_name(json, dirName);

    wchar_t tmp[MAX_PATH]; temp_db_path(tmp, MAX_PATH);
    copy_db_with_sidecars(loginData, tmp);

    void *db = NULL, *stmt = NULL;
    if (sq.open16(tmp, &db) == SQLITE_OK && db) {
        const wchar_t *sql = L"SELECT id, origin_url, action_url, username_value, password_value, date_last_used FROM logins ORDER BY origin_url ASC, username_value ASC";
        if (sq.prepare16(db, sql, -1, &stmt, NULL) == SQLITE_OK && stmt) {
            while (sq.step(stmt) == SQLITE_ROW) {
                cm_edge_cred *c = (cm_edge_cred *)calloc(1, sizeof(cm_edge_cred));
                if (!c) break;
                c->login_id = sq.col_int64(stmt, 0);
                wchar_t *origin = col_text(stmt, 1);
                c->action_url = col_text(stmt, 2);
                c->username = col_text(stmt, 3);
                int blen = sq.col_bytes(stmt, 4);
                const unsigned char *blob = (const unsigned char *)sq.col_blob(stmt, 4);
                long long lastUsed = sq.col_int64(stmt, 5);
                c->profile_name = cm_wcsdup(display);
                c->profile_directory = cm_wcsdup(dirName);
                c->profile_path = cm_wcsdup(profilePath);
                if (origin && origin[0]) { c->website = origin; }
                else { c->website = cm_wcsdup(c->action_url ? c->action_url : L""); free(origin); }
                c->password = decrypt_password(blob, blen > 0 ? (size_t)blen : 0, ls);
                c->last_used = cm_chrome_time_to_string(lastUsed);
                c->enc_version = cm_wcsdup(enc_version(blob, blen > 0 ? (size_t)blen : 0));
                cm_vec_push(out, c);
            }
            sq.finalize(stmt);
        }
        sq.close(db);
    }
    DeleteFileW(tmp);
    wchar_t side[MAX_PATH];
    swprintf(side, MAX_PATH, L"%ls-wal", tmp); DeleteFileW(side);
    swprintf(side, MAX_PATH, L"%ls-shm", tmp); DeleteFileW(side);
    free(display);
}

void cm_edge_load_diagnostics(cm_vec *out)
{
    if (!cm_edge_available()) return;
    wchar_t *userData = edge_user_data_path();
    if (!userData) return;
    char *json = NULL;
    local_state ls; load_local_state(userData, &ls, &json);

    wchar_t pattern[MAX_PATH];
    swprintf(pattern, MAX_PATH, L"%ls\\*", userData);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (_wcsicmp(fd.cFileName, L"Default") != 0 &&
                _wcsnicmp(fd.cFileName, L"Profile ", 8) != 0) continue;
            read_profile(userData, fd.cFileName, json, &ls, out);
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    free(json);
    local_state_free(&ls);
    free(userData);
}

bool cm_edge_is_running(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    bool running = false;
    if (Process32FirstW(snap, &pe)) {
        do { if (_wcsicmp(pe.szExeFile, L"msedge.exe") == 0) { running = true; break; } }
        while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return running;
}

void cm_edge_kill(void)
{
    STARTUPINFOW si = {0}; si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    wchar_t cmd[] = L"taskkill.exe /F /IM msedge.exe /T";
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
}

static unsigned char *encrypt_password_v10(const wchar_t *plain, local_state *ls, size_t *outLen)
{
    if (!ls->master_key) return NULL;
    char *p8 = cm_wide_to_utf8(plain ? plain : L"", -1);
    size_t plainLen = p8 ? strlen(p8) : 0;
    unsigned char nonce[12];
    for (int i = 0; i < 12; i++) nonce[i] = (unsigned char)(rand() ^ (GetTickCount() >> (i & 7)));
    unsigned char *cipher = (unsigned char *)malloc(plainLen ? plainLen : 1);
    unsigned char tag[16];
    bool ok = cm_aes_gcm_encrypt(ls->master_key, ls->master_len, nonce, 12,
                                 (const unsigned char *)(p8 ? p8 : ""), plainLen, cipher, tag);
    free(p8);
    if (!ok) { free(cipher); return NULL; }
    size_t total = 3 + 12 + plainLen + 16;
    unsigned char *out = (unsigned char *)malloc(total);
    if (out) {
        memcpy(out, "v10", 3);
        memcpy(out + 3, nonce, 12);
        memcpy(out + 15, cipher, plainLen);
        memcpy(out + 15 + plainLen, tag, 16);
        if (outLen) *outLen = total;
    }
    free(cipher);
    return out;
}

static bool exec_write(const wchar_t *profilePath, const wchar_t *sql,
                       long long loginId, const wchar_t *username,
                       const unsigned char *pw, size_t pwLen, bool isUpdate, wchar_t **errmsg)
{
    if (!cm_edge_available()) { if (errmsg) *errmsg = cm_wcsdup(L"winsqlite3.dll unavailable"); return false; }
    wchar_t loginData[MAX_PATH];
    swprintf(loginData, MAX_PATH, L"%ls\\Login Data", profilePath);
    void *db = NULL, *stmt = NULL;
    bool ok = false;
    if (sq.open16(loginData, &db) == SQLITE_OK && db) {
        if (sq.prepare16(db, sql, -1, &stmt, NULL) == SQLITE_OK && stmt) {
            if (isUpdate) {
                sq.bind_text16(stmt, 1, username ? username : L"", -1, SQLITE_TRANSIENT);
                sq.bind_blob(stmt, 2, pw ? pw : (const unsigned char *)"", (int)pwLen, SQLITE_TRANSIENT);
                sq.bind_int64(stmt, 3, loginId);
            } else {
                sq.bind_int64(stmt, 1, loginId);
            }
            ok = (sq.step(stmt) == SQLITE_DONE);
            sq.reset(stmt);
            sq.finalize(stmt);
        }
        sq.close(db);
    }
    if (!ok && errmsg) *errmsg = cm_wcsdup(L"SQLite write failed");
    return ok;
}

bool cm_edge_update_credential(long long loginId, const wchar_t *profilePath,
                               const wchar_t *username, const wchar_t *password, wchar_t **errmsg)
{
    if (loginId <= 0 || !profilePath || !profilePath[0]) { if (errmsg) *errmsg = cm_wcsdup(L"invalid target"); return false; }

    wchar_t userData[MAX_PATH]; wcsncpy(userData, profilePath, MAX_PATH - 1); userData[MAX_PATH-1]=0;
    wchar_t *slash = wcsrchr(userData, L'\\'); if (slash) *slash = 0;
    char *json = NULL; local_state ls; load_local_state(userData, &ls, &json); free(json);
    if (!ls.master_key) { if (errmsg) *errmsg = cm_wcsdup(ls.master_err ? ls.master_err : L"Edge master key unavailable."); local_state_free(&ls); return false; }
    size_t pwLen = 0;
    unsigned char *pw = encrypt_password_v10(password, &ls, &pwLen);
    local_state_free(&ls);
    if (!pw) { if (errmsg) *errmsg = cm_wcsdup(L"password encryption failed"); return false; }
    bool ok = exec_write(profilePath, L"UPDATE logins SET username_value = ?1, password_value = ?2 WHERE id = ?3",
                         loginId, username, pw, pwLen, true, errmsg);
    free(pw);
    return ok;
}

bool cm_edge_delete_credential(long long loginId, const wchar_t *profilePath, wchar_t **errmsg)
{
    if (loginId <= 0 || !profilePath || !profilePath[0]) { if (errmsg) *errmsg = cm_wcsdup(L"invalid target"); return false; }
    return exec_write(profilePath, L"DELETE FROM logins WHERE id = ?1", loginId, NULL, NULL, 0, false, errmsg);
}
