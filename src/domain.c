#include "domain.h"
#include "util.h"
#include <lm.h>

wchar_t *cm_domain_get_current(void)
{
    LPWSTR name = NULL;
    NETSETUP_JOIN_STATUS status = NetSetupUnknownStatus;
    wchar_t *result = NULL;
    if (NetGetJoinInformation(NULL, &name, &status) == NERR_Success && name) {
        if (status == NetSetupDomainName && name[0])
            result = cm_wcsdup(name);
    }
    if (name) NetApiBufferFree(name);
    return result ? result : cm_wcsdup(L"WORKGROUP");
}

wchar_t *cm_domain_get_logon_server(void)
{
    LPBYTE buf = NULL;
    wchar_t *result = NULL;
    if (NetWkstaUserGetInfo(NULL, 1, &buf) == NERR_Success && buf) {
        WKSTA_USER_INFO_1 *info = (WKSTA_USER_INFO_1 *)buf;
        if (info->wkui1_logon_server && info->wkui1_logon_server[0])
            result = cm_wcsdup(info->wkui1_logon_server);
    }
    if (buf) NetApiBufferFree(buf);
    return result ? result : cm_wcsdup(L"N/A");
}
