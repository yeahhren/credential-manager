
#ifndef CM_CRED_API_H
#define CM_CRED_API_H

#include "common.h"
#include "util.h"

enum {
    CM_CRED_NONE = 0,
    CM_CRED_GENERIC = 1,
    CM_CRED_DOMAIN_PASSWORD = 2,
    CM_CRED_DOMAIN_CERTIFICATE = 3,
    CM_CRED_DOMAIN_VISIBLE_PASSWORD = 4,
    CM_CRED_GENERIC_CERTIFICATE = 5,
    CM_CRED_DOMAIN_EXTENDED = 6
};

typedef struct {
    wchar_t  *target;
    wchar_t  *username;
    wchar_t  *password;
    wchar_t  *comment;
    DWORD     type;
    DWORD     persist;
    long long last_written;
} cm_credential;

typedef struct {
    wchar_t       *target;
    wchar_t       *username;
    wchar_t       *comment;
    DWORD          type;
    DWORD          persist;
    unsigned char *blob;
    DWORD          blob_size;
    wchar_t       *secret;
} cm_snapshot;

void cm_credential_free(cm_credential *c);
void cm_snapshot_free(cm_snapshot *s);

wchar_t *cm_read_credential_blob(const CREDENTIALW *cred);

void cm_credential_load_all(cm_vec *out);

bool cm_credential_write(DWORD type, const wchar_t *target, const wchar_t *username,
                         const wchar_t *comment, DWORD persist,
                         const unsigned char *blob, DWORD blobSize, DWORD *win32err);

bool cm_credential_delete(const wchar_t *target, DWORD type, DWORD *win32err);

wchar_t *cm_marshal_certificate_username(const unsigned char hash20[20], DWORD *win32err);

void cm_capture_snapshots(cm_vec *out);
bool cm_write_snapshot(const cm_snapshot *s, DWORD *win32err);

wchar_t *cm_snapshot_key(const wchar_t *target, DWORD type, const wchar_t *username);
wchar_t *cm_snapshot_fingerprint(const cm_snapshot *s);

const wchar_t *cm_credential_type_name(DWORD type);

#endif
