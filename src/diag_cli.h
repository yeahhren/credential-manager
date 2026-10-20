
#ifndef CM_DIAG_CLI_H
#define CM_DIAG_CLI_H

#include "common.h"
#include "util.h"

typedef struct {
    wchar_t *target;
    wchar_t *type;
    wchar_t *user;
    wchar_t *persistence;
} cm_cmdkey_cred;

typedef struct {
    wchar_t *target;
    wchar_t *username;
    wchar_t *type;
    wchar_t *vault_name;
    wchar_t *vault_guid;
} cm_vaultcmd_cred;

void cm_cmdkey_cred_free(cm_cmdkey_cred *c);
void cm_vaultcmd_cred_free(cm_vaultcmd_cred *c);

void cm_cmdkey_list(cm_vec *out);
void cm_vaultcmd_list(cm_vec *out);
void cm_get_all_vault_guids(cm_vec *out);

#endif
