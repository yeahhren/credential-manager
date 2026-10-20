#include "vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef enum {
    VET_Boolean = 0, VET_Short = 1, VET_UShort = 2, VET_Int = 3, VET_UInt = 4,
    VET_Double = 5, VET_Guid = 6, VET_String = 7, VET_ByteArray = 8,
    VET_TimeStamp = 9, VET_ProtectedArray = 10, VET_Attribute = 11, VET_Sid = 12
} VAULT_ELEMENT_TYPE;

typedef struct {
    DWORD SchemaElementId;
    DWORD Unknown1;
    DWORD Type;
    DWORD Unknown2;
    union {
        BOOL    boolean;
        SHORT   shortVal;
        WORD    ushortVal;
        int     intVal;
        DWORD   uintVal;
        double  dbl;
        GUID    guid;
        LPWSTR  string;
        struct { DWORD len; BYTE *data; } byteArray;
    } data;
} VAULT_ITEM_ELEMENT;

typedef struct {
    GUID   SchemaId;
    LPWSTR pszCredentialFriendlyName;
    VAULT_ITEM_ELEMENT *pResourceElement;
    VAULT_ITEM_ELEMENT *pIdentityElement;
    VAULT_ITEM_ELEMENT *pAuthenticatorElement;
    VAULT_ITEM_ELEMENT *pPackageSid;
    FILETIME LastModified;
    DWORD  dwFlags;
    DWORD  dwPropertiesCount;
    VAULT_ITEM_ELEMENT *pPropertyElements;
} VAULT_ITEM_WIN8;

typedef int (WINAPI *PFN_VaultOpenVault)(const GUID *, DWORD, void **);
typedef int (WINAPI *PFN_VaultCloseVault)(void *);
typedef int (WINAPI *PFN_VaultEnumerateItems)(void *, DWORD, DWORD *, void **);
typedef int (WINAPI *PFN_VaultGetItem8)(void *, const GUID *, VAULT_ITEM_ELEMENT *,
                                        VAULT_ITEM_ELEMENT *, VAULT_ITEM_ELEMENT *,
                                        HWND, DWORD, VAULT_ITEM_WIN8 **);
typedef int (WINAPI *PFN_VaultCreateItem8)(void *, const GUID *, VAULT_ITEM_ELEMENT *,
                                           VAULT_ITEM_ELEMENT *, VAULT_ITEM_ELEMENT *,
                                           VAULT_ITEM_ELEMENT *, DWORD, HWND, DWORD, void *);
typedef int (WINAPI *PFN_VaultRemoveItem)(void *, const GUID *, VAULT_ITEM_ELEMENT *,
                                          VAULT_ITEM_ELEMENT *, VAULT_ITEM_ELEMENT *, DWORD);
typedef int (WINAPI *PFN_VaultFree)(void *);

static struct {
    HMODULE lib; bool tried;
    PFN_VaultOpenVault       Open;
    PFN_VaultCloseVault      Close;
    PFN_VaultEnumerateItems  Enum;
    PFN_VaultGetItem8        GetItem;
    PFN_VaultCreateItem8     Create;
    PFN_VaultRemoveItem      Remove;
    PFN_VaultFree            Free;
} g;

static void load_vaultcli(void)
{
    if (g.tried) return;
    g.tried = true;
    g.lib = LoadLibraryW(L"vaultcli.dll");
    if (!g.lib) return;
    g.Open   = (PFN_VaultOpenVault)      (void *)GetProcAddress(g.lib, "VaultOpenVault");
    g.Close  = (PFN_VaultCloseVault)     (void *)GetProcAddress(g.lib, "VaultCloseVault");
    g.Enum   = (PFN_VaultEnumerateItems) (void *)GetProcAddress(g.lib, "VaultEnumerateItems");
    g.GetItem= (PFN_VaultGetItem8)       (void *)GetProcAddress(g.lib, "VaultGetItem");
    g.Create = (PFN_VaultCreateItem8)    (void *)GetProcAddress(g.lib, "VaultCreateItem");
    g.Remove = (PFN_VaultRemoveItem)     (void *)GetProcAddress(g.lib, "VaultRemoveItem");
    g.Free   = (PFN_VaultFree)           (void *)GetProcAddress(g.lib, "VaultFree");
}

bool cm_vault_available(void)
{
    load_vaultcli();
    return g.lib && g.Open && g.Enum;
}

void cm_vaultcred_free(cm_vaultcred *c)
{
    if (!c) return;
    free(c->friendly_name); free(c->resource); free(c->identity); free(c->authenticator);
    free(c);
}

struct cm_vault_manager {
    void *handle;
    GUID  guid;
    int   open_hr, enum_hr, reported_count;
    const wchar_t *stage;
};

cm_vault_manager *cm_vault_open(const GUID *schema, int *open_hr)
{
    load_vaultcli();
    if (!g.Open) { if (open_hr) *open_hr = -1; return NULL; }
    cm_vault_manager *m = (cm_vault_manager *)calloc(1, sizeof(*m));
    if (!m) return NULL;
    m->guid = *schema;
    m->stage = L"VaultOpenVault";
    int hr = g.Open(&m->guid, 0, &m->handle);
    m->open_hr = hr;
    if (open_hr) *open_hr = hr;
    if (hr != 0 || !m->handle) { free(m); return NULL; }
    return m;
}

void cm_vault_close(cm_vault_manager *m)
{
    if (!m) return;
    if (m->handle && g.Close) g.Close(m->handle);
    free(m);
}

static wchar_t *element_string(VAULT_ITEM_ELEMENT *e)
{
    if (!e) return NULL;
    if (e->Type == VET_String && e->data.string) return cm_wcsdup(e->data.string);
    return NULL;
}

void cm_vault_enumerate(cm_vault_manager *m, cm_vec *out)
{
    if (!m || !g.Enum) return;
    m->stage = L"VaultEnumerateItems";
    DWORD count = 0; void *items = NULL;
    int hr = g.Enum(m->handle, 0x200, &count, &items);
    m->enum_hr = hr;
    m->reported_count = (int)count;
    if (hr != 0 || !items) return;

    for (DWORD i = 0; i < count; i++) {
        VAULT_ITEM_WIN8 *it = (VAULT_ITEM_WIN8 *)((BYTE *)items + (size_t)i * sizeof(VAULT_ITEM_WIN8));
        cm_vaultcred *c = (cm_vaultcred *)calloc(1, sizeof(cm_vaultcred));
        if (!c) continue;
        c->friendly_name = it->pszCredentialFriendlyName ? cm_wcsdup(it->pszCredentialFriendlyName) : NULL;
        c->resource = element_string(it->pResourceElement);
        c->identity = element_string(it->pIdentityElement);
        c->schema_id = it->SchemaId;
        c->last_modified = ((unsigned long long)it->LastModified.dwHighDateTime << 32) | it->LastModified.dwLowDateTime;

        if (g.GetItem) {
            VAULT_ITEM_WIN8 *full = NULL;
            int ghr = g.GetItem(m->handle, &it->SchemaId, it->pResourceElement,
                                it->pIdentityElement, it->pPackageSid, NULL, 0, &full);
            if (ghr == 0 && full) {
                c->authenticator = element_string(full->pAuthenticatorElement);
                if (!c->resource) c->resource = element_string(full->pResourceElement);
                if (!c->identity) c->identity = element_string(full->pIdentityElement);
                if (g.Free) g.Free(full);
            }
        }
        cm_vec_push(out, c);
    }
    if (g.Free) g.Free(items);
}

static void init_string_element(VAULT_ITEM_ELEMENT *e, DWORD schemaId, const wchar_t *value)
{
    memset(e, 0, sizeof(*e));
    e->SchemaElementId = schemaId;
    e->Type = VET_String;
    e->data.string = (LPWSTR)value;
}

bool cm_vault_create_item(cm_vault_manager *m, const wchar_t *friendly, const wchar_t *resource,
                          const wchar_t *identity, const wchar_t *authenticator, const GUID *schema)
{
    if (!m) return false;
    bool ok = false;
    if (g.Create) {
        VAULT_ITEM_ELEMENT res, idn, aut;
        init_string_element(&res, 1, resource);
        init_string_element(&idn, 2, identity);
        init_string_element(&aut, 3, authenticator);

        int hr = g.Create(m->handle, schema, &res, &idn, &aut, NULL, 0, NULL, 0, NULL);
        ok = (hr == 0);
    }
    if (!ok) {

        DWORD err = 0;
        const unsigned char *blob = NULL; DWORD blobSize = 0;
        if (authenticator && authenticator[0]) {
            blobSize = (DWORD)((wcslen(authenticator) + 1) * sizeof(wchar_t));
            blob = (const unsigned char *)authenticator;
        }
        extern bool cm_credential_write(DWORD, const wchar_t *, const wchar_t *, const wchar_t *,
                                        DWORD, const unsigned char *, DWORD, DWORD *);
        ok = cm_credential_write(1 , resource, identity, friendly,
                                 2 , blob, blobSize, &err);
    }
    return ok;
}

bool cm_vault_delete_item(cm_vault_manager *m, const cm_vaultcred *cred)
{
    if (!m || !cred) return false;
    if (g.Remove) {
        GUID schema = cred->schema_id;
        VAULT_ITEM_ELEMENT res, idn;
        init_string_element(&res, 1, cred->resource);
        init_string_element(&idn, 2, cred->identity);
        int hr = g.Remove(m->handle, &schema,
                          cred->resource ? &res : NULL,
                          cred->identity ? &idn : NULL, NULL, 0);
        if (hr == 0) return true;
    }

    DWORD err = 0;
    extern bool cm_credential_delete(const wchar_t *, DWORD, DWORD *);
    return cm_credential_delete(cred->resource, 1 , &err);
}

wchar_t *cm_vault_last_summary(cm_vault_manager *m)
{
    wchar_t buf[128];
    if (!m) return cm_wcsdup(L"Vault manager unavailable");
    if (m->open_hr != 0)
        swprintf(buf, 128, L"VaultOpenVault HRESULT: 0x%08X", (unsigned)m->open_hr);
    else if (m->enum_hr != 0)
        swprintf(buf, 128, L"VaultEnumerateItems HRESULT: 0x%08X", (unsigned)m->enum_hr);
    else if (m->reported_count == 0)
        return cm_wcsdup(L"VaultEnumerateItems returned zero items");
    else
        swprintf(buf, 128, L"VaultEnumerateItems reported %d item(s)", m->reported_count);
    return cm_wcsdup(buf);
}
