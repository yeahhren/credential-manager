
#ifndef CM_UTIL_H
#define CM_UTIL_H

#include "common.h"

wchar_t *cm_wcsdup(const wchar_t *s);
wchar_t *cm_utf8_to_wide(const char *utf8, int len);
char    *cm_wide_to_utf8(const wchar_t *w, int len);
int      cm_wcsicmp_safe(const wchar_t *a, const wchar_t *b);
bool     cm_wcs_contains_ci(const wchar_t *hay, const wchar_t *needle);
void     cm_trim_trailing_nuls(wchar_t *s);

char   *cm_base64_encode(const unsigned char *data, size_t len);
unsigned char *cm_base64_decode(const char *b64, size_t *out_len);
wchar_t *cm_bytes_to_hex(const unsigned char *data, size_t len);
bool     cm_hex_to_bytes(const wchar_t *hex, unsigned char *out, size_t out_len);

wchar_t *cm_filetime_to_string(long long fileTimeUtc);
wchar_t *cm_chrome_time_to_string(long long chromeMicros);

unsigned char *cm_read_file(const wchar_t *path, size_t *len);

char *cm_run_capture(const wchar_t *commandLine);

typedef struct {
    void  **items;
    size_t  count;
    size_t  cap;
} cm_vec;

void  cm_vec_init(cm_vec *v);
void  cm_vec_push(cm_vec *v, void *item);
void  cm_vec_free(cm_vec *v, void (*free_item)(void *));

#endif
