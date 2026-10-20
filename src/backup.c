#include "backup.h"
#include "cred_api.h"
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef BOOL (WINAPI *PFN_CredRestore)(LPWSTR, PBYTE, DWORD, DWORD);

static cm_vec g_store;
static bool   g_store_init;

static void imported_free(void *p)
{
    cm_imported_cred *c = (cm_imported_cred *)p;
    if (!c) return;
    free(c->target); free(c->username); free(c->password);
    free(c->type); free(c->comment); free(c->source_file);
    free(c);
}

static void ensure_store(void) { if (!g_store_init) { cm_vec_init(&g_store); g_store_init = true; } }

const cm_vec *cm_imported_store(void) { ensure_store(); return &g_store; }

void cm_imported_clear(void)
{
    ensure_store();
    cm_vec_free(&g_store, imported_free);
    cm_vec_init(&g_store);
}

static PFN_CredRestore load_cred_restore(void)
{
    HMODULE adv = GetModuleHandleW(L"advapi32.dll");
    if (!adv) adv = LoadLibraryW(L"advapi32.dll");
    if (!adv) return NULL;
    PFN_CredRestore fn = (PFN_CredRestore)(void *)GetProcAddress(adv, "CredRestoreCredentialsW");
    if (!fn) fn = (PFN_CredRestore)(void *)GetProcAddress(adv, "CredRestoreCredentials");
    return fn;
}

static cm_import_result make_result(bool ok, int imp, int skip, int total, const wchar_t *msg)
{
    cm_import_result r;
    r.success = ok; r.imported_count = imp; r.skipped_count = skip; r.total_count = total;
    r.message = cm_wcsdup(msg);
    return r;
}

static cm_snapshot *find_by_key(cm_vec *snaps, const wchar_t *key)
{
    for (size_t i = 0; i < snaps->count; i++) {
        cm_snapshot *s = (cm_snapshot *)snaps->items[i];
        wchar_t *k = cm_snapshot_key(s->target, s->type, s->username);
        bool eq = (wcscmp(k, key) == 0);
        free(k);
        if (eq) return s;
    }
    return NULL;
}

cm_import_result cm_backup_import(const wchar_t *filePath, const wchar_t *password, bool allowDuplicates)
{
    ensure_store();
    PFN_CredRestore restore = load_cred_restore();
    if (!restore)
        return make_result(false, 0, 0, 0, L"CredRestoreCredentials is unavailable on this system.");

    const wchar_t *pw = password ? password : L"";
    DWORD pwBytes = (DWORD)((wcslen(pw) + 1) * sizeof(wchar_t));
    BYTE *pwBuf = (BYTE *)malloc(pwBytes);
    if (!pwBuf) return make_result(false, 0, 0, 0, L"Out of memory.");
    memcpy(pwBuf, pw, pwBytes);

    cm_vec before; cm_vec_init(&before);
    cm_capture_snapshots(&before);

    wchar_t *fileCopy = cm_wcsdup(filePath);
    SetLastError(0);
    BOOL ok = restore(fileCopy, pwBuf, pwBytes, 0);
    DWORD err = ok ? 0 : GetLastError();
    free(fileCopy);
    SecureZeroMemory(pwBuf, pwBytes);
    free(pwBuf);

    if (!ok) {
        cm_vec_free(&before, (void (*)(void *))cm_snapshot_free);
        wchar_t msg[128];
        swprintf(msg, 128, L"CRD restore failed (Win32 %lu). The password may be incorrect.", (unsigned long)err);
        return make_result(false, 0, 0, 0, msg);
    }

    cm_vec after; cm_vec_init(&after);
    cm_capture_snapshots(&after);

    int imported = 0, skipped = 0, total = 0;
    for (size_t i = 0; i < after.count; i++) {
        cm_snapshot *a = (cm_snapshot *)after.items[i];
        wchar_t *akey = cm_snapshot_key(a->target, a->type, a->username);
        cm_snapshot *b = find_by_key(&before, akey);
        free(akey);
        bool isNew = (b == NULL);
        bool changed = false;
        if (b) {
            wchar_t *af = cm_snapshot_fingerprint(a);
            wchar_t *bf = cm_snapshot_fingerprint(b);
            changed = (wcscmp(af, bf) != 0);
            free(af); free(bf);
        }
        if (!isNew && !changed) continue;
        total++;

        bool dup = false;
        if (!allowDuplicates) {
            for (size_t j = 0; j < g_store.count; j++) {
                cm_imported_cred *e = (cm_imported_cred *)g_store.items[j];
                if (cm_wcsicmp_safe(e->target, a->target) == 0 &&
                    cm_wcsicmp_safe(e->username, a->username) == 0) { dup = true; break; }
            }
        }
        if (dup) { skipped++; }
        else {
            cm_imported_cred *e = (cm_imported_cred *)calloc(1, sizeof(cm_imported_cred));
            if (e) {
                e->target = cm_wcsdup(a->target);
                e->username = cm_wcsdup(a->username);
                e->password = cm_wcsdup(a->secret ? a->secret : L"");
                e->type = cm_wcsdup(cm_credential_type_name(a->type));
                e->comment = cm_wcsdup(a->comment ? a->comment : L"");
                e->source_file = cm_wcsdup(filePath);
                cm_vec_push(&g_store, e);
                imported++;
            }
        }
    }

    for (size_t i = 0; i < after.count; i++) {
        cm_snapshot *a = (cm_snapshot *)after.items[i];
        wchar_t *akey = cm_snapshot_key(a->target, a->type, a->username);
        cm_snapshot *b = find_by_key(&before, akey);
        free(akey);
        if (!b) {
            DWORD e = 0; cm_credential_delete(a->target, a->type, &e);
        } else {
            wchar_t *af = cm_snapshot_fingerprint(a);
            wchar_t *bf = cm_snapshot_fingerprint(b);
            if (wcscmp(af, bf) != 0) { DWORD e = 0; cm_write_snapshot(b, &e); }
            free(af); free(bf);
        }
    }

    cm_vec_free(&before, (void (*)(void *))cm_snapshot_free);
    cm_vec_free(&after, (void (*)(void *))cm_snapshot_free);

    wchar_t msg[160];
    if (imported > 0) swprintf(msg, 160, L"Imported %d credential(s) into session memory only.", imported);
    else wcscpy(msg, L"The backup file was read successfully, but no new credentials were added.");
    return make_result(true, imported, skipped, total, msg);
}

static void write_utf8(HANDLE h, const char *s) { DWORD w; WriteFile(h, s, (DWORD)strlen(s), &w, NULL); }

static void write_csv_field(HANDLE h, const wchar_t *val, bool last)
{
    char *u = cm_wide_to_utf8(val ? val : L"", -1);
    const char *s = u ? u : "";
    bool quote = strpbrk(s, ",\"\r\n") != NULL;
    if (quote) write_utf8(h, "\"");
    for (const char *p = s; *p; p++) { if (*p == '"') write_utf8(h, "\""); char c[2]={*p,0}; write_utf8(h, c); }
    if (quote) write_utf8(h, "\"");
    write_utf8(h, last ? "\r\n" : ",");
    free(u);
}

bool cm_backup_export(const wchar_t *outputPath, const wchar_t *format)
{
    ensure_store();
    if (g_store.count == 0) return false;
    HANDLE h = CreateFileW(outputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool json = (cm_wcsicmp_safe(format, L"JSON") == 0);

    if (json) {
        write_utf8(h, "[\n");
        for (size_t i = 0; i < g_store.count; i++) {
            cm_imported_cred *e = (cm_imported_cred *)g_store.items[i];
            const wchar_t *fields[6]; const char *names[6] =
                {"Target","Username","Password","Type","Comment","SourceFile"};
            fields[0]=e->target; fields[1]=e->username; fields[2]=e->password;
            fields[3]=e->type; fields[4]=e->comment; fields[5]=e->source_file;
            write_utf8(h, "  {");
            for (int f = 0; f < 6; f++) {
                char *v = cm_wide_to_utf8(fields[f] ? fields[f] : L"", -1);
                write_utf8(h, "\""); write_utf8(h, names[f]); write_utf8(h, "\":\"");
                for (const char *p = v ? v : ""; *p; p++) {
                    if (*p == '"' || *p == '\\') { char e2[3]={'\\',*p,0}; write_utf8(h, e2); }
                    else if (*p == '\n') write_utf8(h, "\\n");
                    else if (*p == '\r') write_utf8(h, "\\r");
                    else { char c[2]={*p,0}; write_utf8(h, c); }
                }
                write_utf8(h, f < 5 ? "\"," : "\"");
                free(v);
            }
            write_utf8(h, i + 1 < g_store.count ? "},\n" : "}\n");
        }
        write_utf8(h, "]\n");
    } else {
        write_utf8(h, "Target,Username,Password,Type,Comment,SourceFile\r\n");
        for (size_t i = 0; i < g_store.count; i++) {
            cm_imported_cred *e = (cm_imported_cred *)g_store.items[i];
            write_csv_field(h, e->target, false);
            write_csv_field(h, e->username, false);
            write_csv_field(h, e->password, false);
            write_csv_field(h, e->type, false);
            write_csv_field(h, e->comment, false);
            write_csv_field(h, e->source_file, true);
        }
    }
    CloseHandle(h);
    return true;
}
