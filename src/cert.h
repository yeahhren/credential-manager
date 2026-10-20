
#ifndef CM_CERT_H
#define CM_CERT_H

#include "common.h"
#include "util.h"

typedef struct {
    wchar_t  *thumbprint;
    wchar_t  *subject;
    bool      is_valid;
    long long not_before;
    long long not_after;
    int       key_size;
    int       expiry_days;
    const wchar_t *expiry_status;
    bool      has_private_key;
} cm_certinfo;

void cm_certinfo_free(cm_certinfo *c);

void cm_cert_enumerate(cm_vec *out);

wchar_t *cm_cert_normalize_thumbprint(const wchar_t *thumb);

cm_certinfo *cm_cert_find(const wchar_t *thumbprint);

bool cm_cert_is_usable(const wchar_t *thumbprint, wchar_t **message_out);

#endif
