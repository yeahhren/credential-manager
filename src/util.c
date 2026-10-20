#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

const GUID CM_VAULT_WEB_CREDENTIALS =
    {0x4BF4C442,0x9B8A,0x41A0,{0xB3,0x80,0xDD,0x4A,0x70,0x4D,0xDB,0x28}};
const GUID CM_VAULT_WINDOWS_CREDENTIALS =
    {0x77BC582B,0xF0A6,0x4E15,{0x4E,0x80,0x61,0x73,0x6B,0x6F,0x3B,0x29}};

wchar_t *cm_wcsdup(const wchar_t *s)
{
    if (!s) return NULL;
    size_t n = wcslen(s) + 1;
    wchar_t *p = (wchar_t *)malloc(n * sizeof(wchar_t));
    if (p) memcpy(p, s, n * sizeof(wchar_t));
    return p;
}

wchar_t *cm_utf8_to_wide(const char *utf8, int len)
{
    if (!utf8) return NULL;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8, len, NULL, 0);
    if (wlen <= 0) return NULL;

    int alloc = (len < 0) ? wlen : wlen + 1;
    wchar_t *w = (wchar_t *)malloc((size_t)alloc * sizeof(wchar_t));
    if (!w) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, utf8, len, w, wlen);
    w[alloc - 1] = L'\0';
    return w;
}

char *cm_wide_to_utf8(const wchar_t *w, int len)
{
    if (!w) return NULL;
    int blen = WideCharToMultiByte(CP_UTF8, 0, w, len, NULL, 0, NULL, NULL);
    if (blen <= 0) return NULL;
    int alloc = (len < 0) ? blen : blen + 1;
    char *b = (char *)malloc((size_t)alloc);
    if (!b) return NULL;
    WideCharToMultiByte(CP_UTF8, 0, w, len, b, blen, NULL, NULL);
    b[alloc - 1] = '\0';
    return b;
}

int cm_wcsicmp_safe(const wchar_t *a, const wchar_t *b)
{
    if (!a) a = L"";
    if (!b) b = L"";
    return _wcsicmp(a, b);
}

bool cm_wcs_contains_ci(const wchar_t *hay, const wchar_t *needle)
{
    if (!needle || !*needle) return true;
    if (!hay) return false;
    size_t hn = wcslen(hay), nn = wcslen(needle);
    if (nn > hn) return false;
    wchar_t *lhay = (wchar_t *)malloc((hn + 1) * sizeof(wchar_t));
    wchar_t *lned = (wchar_t *)malloc((nn + 1) * sizeof(wchar_t));
    bool found = false;
    if (lhay && lned) {
        for (size_t i = 0; i <= hn; i++) lhay[i] = (wchar_t)towlower(hay[i]);
        for (size_t i = 0; i <= nn; i++) lned[i] = (wchar_t)towlower(needle[i]);
        found = (wcsstr(lhay, lned) != NULL);
    }
    free(lhay); free(lned);
    return found;
}

void cm_trim_trailing_nuls(wchar_t *s)
{
    if (!s) return;
    size_t n = wcslen(s);
    while (n > 0 && s[n - 1] == L'\0') n--;
    s[n] = L'\0';
}

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *cm_base64_encode(const unsigned char *data, size_t len)
{
    size_t olen = 4 * ((len + 2) / 3);
    char *out = (char *)malloc(olen + 1);
    if (!out) return NULL;
    size_t i = 0, o = 0;
    while (i < len) {
        unsigned a = i < len ? data[i++] : 0;
        unsigned b = i < len ? data[i++] : 0;
        unsigned c = i < len ? data[i++] : 0;
        unsigned triple = (a << 16) | (b << 8) | c;
        out[o++] = B64[(triple >> 18) & 0x3F];
        out[o++] = B64[(triple >> 12) & 0x3F];
        out[o++] = B64[(triple >> 6) & 0x3F];
        out[o++] = B64[triple & 0x3F];
    }
    size_t mod = len % 3;
    if (mod >= 1) out[olen - 1] = '=';
    if (mod == 1) out[olen - 2] = '=';
    out[olen] = '\0';
    return out;
}

static int b64val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

unsigned char *cm_base64_decode(const char *b64, size_t *out_len)
{
    if (!b64) return NULL;
    size_t n = strlen(b64);
    unsigned char *out = (unsigned char *)malloc(n / 4 * 3 + 3);
    if (!out) return NULL;
    size_t o = 0; int quad[4], qi = 0;
    for (size_t i = 0; i < n; i++) {
        if (b64[i] == '=' ) break;
        int v = b64val(b64[i]);
        if (v < 0) continue;
        quad[qi++] = v;
        if (qi == 4) {
            out[o++] = (unsigned char)((quad[0] << 2) | (quad[1] >> 4));
            out[o++] = (unsigned char)((quad[1] << 4) | (quad[2] >> 2));
            out[o++] = (unsigned char)((quad[2] << 6) | quad[3]);
            qi = 0;
        }
    }
    if (qi == 2) {
        out[o++] = (unsigned char)((quad[0] << 2) | (quad[1] >> 4));
    } else if (qi == 3) {
        out[o++] = (unsigned char)((quad[0] << 2) | (quad[1] >> 4));
        out[o++] = (unsigned char)((quad[1] << 4) | (quad[2] >> 2));
    }
    if (out_len) *out_len = o;
    return out;
}

wchar_t *cm_bytes_to_hex(const unsigned char *data, size_t len)
{
    wchar_t *out = (wchar_t *)malloc((len * 2 + 1) * sizeof(wchar_t));
    if (!out) return NULL;
    static const wchar_t H[] = L"0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = H[(data[i] >> 4) & 0xF];
        out[i * 2 + 1] = H[data[i] & 0xF];
    }
    out[len * 2] = L'\0';
    return out;
}

static int hexnib(wchar_t c)
{
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'a' && c <= L'f') return c - L'a' + 10;
    if (c >= L'A' && c <= L'F') return c - L'A' + 10;
    return -1;
}

bool cm_hex_to_bytes(const wchar_t *hex, unsigned char *out, size_t out_len)
{
    if (!hex) return false;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hexnib(hex[i * 2]);
        int lo = hexnib(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return true;
}

wchar_t *cm_filetime_to_string(long long fileTimeUtc)
{
    if (fileTimeUtc <= 0) return cm_wcsdup(L"");
    FILETIME ft;
    ft.dwLowDateTime  = (DWORD)(fileTimeUtc & 0xFFFFFFFF);
    ft.dwHighDateTime = (DWORD)((fileTimeUtc >> 32) & 0xFFFFFFFF);
    FILETIME lft; SYSTEMTIME st;
    if (!FileTimeToLocalFileTime(&ft, &lft) || !FileTimeToSystemTime(&lft, &st))
        return cm_wcsdup(L"N/A");
    wchar_t buf[64];
    swprintf(buf, 64, L"%04d-%02d-%02d %02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    return cm_wcsdup(buf);
}

wchar_t *cm_chrome_time_to_string(long long chromeMicros)
{
    if (chromeMicros <= 0) return cm_wcsdup(L"Never");

    long long fileTime = chromeMicros * 10LL;
    return cm_filetime_to_string(fileTime);
}

unsigned char *cm_read_file(const wchar_t *path, size_t *len)
{
    if (len) *len = 0;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (1LL << 30)) {
        CloseHandle(h); return NULL;
    }
    size_t n = (size_t)sz.QuadPart;
    unsigned char *buf = (unsigned char *)malloc(n);
    if (!buf) { CloseHandle(h); return NULL; }
    size_t got = 0;
    while (got < n) {
        DWORD r = 0;
        if (!ReadFile(h, buf + got, (DWORD)(n - got), &r, NULL) || r == 0) break;
        got += r;
    }
    CloseHandle(h);
    if (got != n) { free(buf); return NULL; }
    if (len) *len = n;
    return buf;
}

char *cm_run_capture(const wchar_t *commandLine)
{
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return NULL;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError  = wr;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    wchar_t *cmd = cm_wcsdup(commandLine);
    PROCESS_INFORMATION pi = {0};
    BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    free(cmd);
    CloseHandle(wr);
    if (!ok) { CloseHandle(rd); return NULL; }
    CloseHandle(pi.hThread);

    size_t cap = 8192, used = 0;
    char *out = (char *)malloc(cap);
    if (out) {
        for (;;) {
            if (used + 4096 + 1 > cap) { cap *= 2; char *n = realloc(out, cap); if (!n) break; out = n; }
            DWORD r = 0;
            if (!ReadFile(rd, out + used, 4096, &r, NULL) || r == 0) break;
            used += r;
        }
        if (out) out[used] = '\0';
    }
    WaitForSingleObject(pi.hProcess, 15000);
    CloseHandle(pi.hProcess);
    CloseHandle(rd);
    return out;
}

void cm_vec_init(cm_vec *v) { v->items = NULL; v->count = 0; v->cap = 0; }

void cm_vec_push(cm_vec *v, void *item)
{
    if (v->count == v->cap) {
        size_t nc = v->cap ? v->cap * 2 : 8;
        void **n = (void **)realloc(v->items, nc * sizeof(void *));
        if (!n) return;
        v->items = n; v->cap = nc;
    }
    v->items[v->count++] = item;
}

void cm_vec_free(cm_vec *v, void (*free_item)(void *))
{
    if (free_item) for (size_t i = 0; i < v->count; i++) free_item(v->items[i]);
    free(v->items);
    v->items = NULL; v->count = 0; v->cap = 0;
}
