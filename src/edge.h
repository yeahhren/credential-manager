
#ifndef CM_EDGE_H
#define CM_EDGE_H

#include "common.h"
#include "util.h"

typedef struct {
    long long  login_id;
    wchar_t   *profile_name;
    wchar_t   *profile_directory;
    wchar_t   *profile_path;
    wchar_t   *website;
    wchar_t   *action_url;
    wchar_t   *username;
    wchar_t   *password;
    wchar_t   *last_used;
    wchar_t   *enc_version;
} cm_edge_cred;

void cm_edge_cred_free(cm_edge_cred *c);

void cm_edge_load_diagnostics(cm_vec *out);

bool cm_edge_is_running(void);
void cm_edge_kill(void);

bool cm_edge_update_credential(long long loginId, const wchar_t *profilePath,
                               const wchar_t *username, const wchar_t *password, wchar_t **errmsg);
bool cm_edge_delete_credential(long long loginId, const wchar_t *profilePath, wchar_t **errmsg);

bool cm_edge_available(void);

#endif
