
#ifndef CM_CRYPTO_H
#define CM_CRYPTO_H

#include "common.h"

unsigned char *cm_dpapi_unprotect(const unsigned char *data, size_t len, size_t *out_len,
                                  DWORD *win32err);

unsigned char *cm_dpapi_unprotect_as_system(const unsigned char *data, size_t len, size_t *out_len);

unsigned char *cm_aes_gcm_decrypt(const unsigned char *key, size_t keyLen,
                                  const unsigned char *nonce, size_t nonceLen,
                                  const unsigned char *cipher, size_t cipherLen,
                                  const unsigned char *tag, size_t tagLen,
                                  size_t *out_len);

bool cm_aes_gcm_encrypt(const unsigned char *key, size_t keyLen,
                        const unsigned char *nonce, size_t nonceLen,
                        const unsigned char *plain, size_t plainLen,
                        unsigned char *cipherOut, unsigned char tagOut[16]);

unsigned char *cm_aes_cbc_decrypt(const unsigned char *key, size_t keyLen,
                                  const unsigned char *iv,
                                  const unsigned char *data, size_t dataLen,
                                  size_t *out_len);

#endif
