
#ifndef CM_VAULT_H
#define CM_VAULT_H

#include "common.h"
#include "util.h"

typedef struct {
    wchar_t  *friendly_name;
    wchar_t  *resource;
    wchar_t  *identity;
    wchar_t  *authenticator;
    GUID      schema_id;
    unsigned long long last_modified;
} cm_vaultcred;

void cm_vaultcred_free(cm_vaultcred *c);

typedef struct cm_vault_manager cm_vault_manager;

cm_vault_manager *cm_vault_open(const GUID *schema, int *open_hr);
void  cm_vault_close(cm_vault_manager *m);

void  cm_vault_enumerate(cm_vault_manager *m, cm_vec *out);

bool  cm_vault_create_item(cm_vault_manager *m, const wchar_t *friendly, const wchar_t *resource,
                           const wchar_t *identity, const wchar_t *authenticator, const GUID *schema);
bool  cm_vault_delete_item(cm_vault_manager *m, const cm_vaultcred *cred);

wchar_t *cm_vault_last_summary(cm_vault_manager *m);

bool cm_vault_available(void);

#endif
