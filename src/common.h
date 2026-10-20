
#ifndef CM_COMMON_H
#define CM_COMMON_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <wincred.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

extern const GUID CM_VAULT_WEB_CREDENTIALS;
extern const GUID CM_VAULT_WINDOWS_CREDENTIALS;

#endif
