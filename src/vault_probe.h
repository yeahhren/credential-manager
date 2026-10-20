
#ifndef CM_VAULT_PROBE_H
#define CM_VAULT_PROBE_H

#include "common.h"
#include "util.h"
#include "vault.h"

typedef struct {
    wchar_t  *vault_guid;
    wchar_t  *policy_path;
    int       credential_file_count;
    int       decrypted_credential_count;
    wchar_t  *status;
    wchar_t  *detail;
} cm_vault_probe;

void cm_vault_probe_free(cm_vault_probe *p);

void cm_vault_probe_all(cm_vec *out);

void cm_vault_decrypt_direct(cm_vec *out);

#endif
