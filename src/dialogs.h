
#ifndef CM_DIALOGS_H
#define CM_DIALOGS_H

#include "common.h"
#include "cred_api.h"
#include "vault.h"
#include "edge.h"

bool cm_dlg_property(HWND parent, const cm_credential *existing, const wchar_t *targetType);

bool cm_dlg_edge_property(HWND parent, const cm_edge_cred *cred, wchar_t **outUser, wchar_t **outPass);

bool cm_dlg_vault_property(HWND parent, const cm_vaultcred *existing);

wchar_t *cm_dlg_cert_picker(HWND parent);

wchar_t *cm_dlg_import_password(HWND parent);

#endif
