#include "dialogs.h"
#include "util.h"
#include "cert.h"
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static HFONT g_dlgFont;
static void ensure_font(void)
{
    if (g_dlgFont) return;
    NONCLIENTMETRICSW ncm = { sizeof(ncm) };
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
    g_dlgFont = CreateFontIndirectW(&ncm.lfMessageFont);
}
static void dfont(HWND h) { if (h) SendMessageW(h, WM_SETFONT, (WPARAM)g_dlgFont, TRUE); }

typedef struct { int done; int result; } modal_base;

static int run_modal(HWND dlg, HWND parent, modal_base *base)
{
    EnableWindow(parent, FALSE);
    ShowWindow(dlg, SW_SHOW);
    SetForegroundWindow(dlg);
    MSG m;
    while (!base->done && GetMessageW(&m, NULL, 0, 0) > 0) {
        if (!IsDialogMessageW(dlg, &m)) { TranslateMessage(&m); DispatchMessageW(&m); }
    }
    EnableWindow(parent, TRUE);
    SetForegroundWindow(parent);
    DestroyWindow(dlg);
    return base->result;
}

static HWND make_dialog(HWND parent, const wchar_t *title, int w, int h, WNDPROC proc, void *state)
{
    ensure_font();
    static bool reg = false;
    if (!reg) {
        WNDCLASSEXW wc = { sizeof(wc) };
        wc.lpfnWndProc = DefWindowProcW;
        wc.hInstance = GetModuleHandleW(NULL);
        wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = L"CMDialog";
        RegisterClassExW(&wc);
        reg = true;
    }
    RECT pr; GetWindowRect(parent, &pr);
    int x = pr.left + ((pr.right - pr.left) - w) / 2;
    int y = pr.top + ((pr.bottom - pr.top) - h) / 2;
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"CMDialog", title,
        WS_POPUP | WS_CAPTION | WS_SYSMENU, x, y, w, h, parent, NULL, GetModuleHandleW(NULL), NULL);
    SetWindowLongPtrW(dlg, GWLP_USERDATA, (LONG_PTR)state);
    SetWindowLongPtrW(dlg, GWLP_WNDPROC, (LONG_PTR)proc);
    return dlg;
}

static HWND ctrl(HWND p, const wchar_t *cls, const wchar_t *text, DWORD style, int x, int y, int w, int h, int id)
{
    HWND c = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style,
                             x, y, w, h, p, (HMENU)(INT_PTR)id, GetModuleHandleW(NULL), NULL);
    dfont(c);
    return c;
}
static HWND edit(HWND p, const wchar_t *text, int x, int y, int w, int id, bool password)
{
    DWORD s = ES_AUTOHSCROLL | (password ? ES_PASSWORD : 0);
    return CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | s,
                           x, y, w, 22, p, (HMENU)(INT_PTR)id, GetModuleHandleW(NULL), NULL);
}
static wchar_t *get_text(HWND h)
{
    int n = GetWindowTextLengthW(h);
    wchar_t *s = (wchar_t *)malloc((n + 1) * sizeof(wchar_t));
    if (s) GetWindowTextW(h, s, n + 1);
    return s;
}

typedef struct { modal_base base; HWND edit; wchar_t *password; } pwd_state;

static LRESULT CALLBACK pwd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    pwd_state *st = (pwd_state *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (msg == WM_COMMAND) {
        int id = LOWORD(wp);
        if (id == IDOK) { st->password = get_text(st->edit); st->base.result = 1; st->base.done = 1; }
        else if (id == IDCANCEL) { st->base.result = 0; st->base.done = 1; }
    } else if (msg == WM_CLOSE) { st->base.done = 1; }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

wchar_t *cm_dlg_import_password(HWND parent)
{
    pwd_state st = {0};
    HWND dlg = make_dialog(parent, L"Enter Backup Password", 460, 190, pwd_proc, &st);
    ctrl(dlg, L"STATIC", L"Enter the password used to encrypt this .crd backup file.",
         SS_LEFT, 20, 15, 410, 36, -1);
    st.edit = edit(dlg, L"", 20, 55, 410, 0, true); dfont(st.edit);
    ctrl(dlg, L"BUTTON", L"OK", BS_DEFPUSHBUTTON | WS_TABSTOP, 260, 100, 80, 26, IDOK);
    ctrl(dlg, L"BUTTON", L"Cancel", BS_PUSHBUTTON | WS_TABSTOP, 350, 100, 80, 26, IDCANCEL);
    run_modal(dlg, parent, &st.base);
    if (st.base.result) return st.password;
    free(st.password);
    return NULL;
}

typedef struct { modal_base base; HWND list; cm_vec certs; wchar_t *thumb; } cert_state;

static LRESULT CALLBACK cert_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    cert_state *st = (cert_state *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (msg == WM_COMMAND) {
        int id = LOWORD(wp);
        if (id == IDOK) {
            int sel = (int)SendMessageW(st->list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
            if (sel >= 0) {
                wchar_t buf[128]; ListView_GetItemText(st->list, sel, 1, buf, 128);
                st->thumb = cm_wcsdup(buf);
                st->base.result = 1; st->base.done = 1;
            }
        } else if (id == IDCANCEL) { st->base.done = 1; }
    } else if (msg == WM_NOTIFY) {
        LPNMHDR h = (LPNMHDR)lp;
        if (h->code == NM_DBLCLK) { PostMessageW(hwnd, WM_COMMAND, IDOK, 0); }
    } else if (msg == WM_CLOSE) { st->base.done = 1; }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

wchar_t *cm_dlg_cert_picker(HWND parent)
{
    cert_state st = {0}; cm_vec_init(&st.certs);
    cm_cert_enumerate(&st.certs);
    if (st.certs.count == 0) {
        MessageBoxW(parent, L"No certificates were found in Current User > Personal.",
                    L"Certificate Store", MB_OK | MB_ICONINFORMATION);
        cm_vec_free(&st.certs, (void (*)(void *))cm_certinfo_free);
        return NULL;
    }
    HWND dlg = make_dialog(parent, L"Select Certificate", 760, 380, cert_proc, &st);
    st.list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        10, 10, 724, 290, dlg, NULL, GetModuleHandleW(NULL), NULL);
    ListView_SetExtendedListViewStyle(st.list, LVS_EX_FULLROWSELECT);
    dfont(st.list);
    LVCOLUMNW c = {0}; c.mask = LVCF_TEXT | LVCF_WIDTH;
    const wchar_t *cols[4] = { L"Subject", L"Thumbprint", L"Expires", L"Status" };
    int w[4] = { 300, 230, 110, 80 };
    for (int i = 0; i < 4; i++) { c.pszText = (LPWSTR)cols[i]; c.cx = w[i]; ListView_InsertColumn(st.list, i, &c); }
    for (size_t i = 0; i < st.certs.count; i++) {
        cm_certinfo *ci = (cm_certinfo *)st.certs.items[i];
        LVITEMW it = {0}; it.mask = LVIF_TEXT; it.iItem = (int)i; it.pszText = ci->subject;
        int r = ListView_InsertItem(st.list, &it);
        ListView_SetItemText(st.list, r, 1, ci->thumbprint);
        wchar_t *exp = cm_filetime_to_string(ci->not_after);
        ListView_SetItemText(st.list, r, 2, exp); free(exp);
        ListView_SetItemText(st.list, r, 3, (LPWSTR)ci->expiry_status);
    }
    ctrl(dlg, L"BUTTON", L"OK", BS_DEFPUSHBUTTON | WS_TABSTOP, 490, 310, 75, 26, IDOK);
    ctrl(dlg, L"BUTTON", L"Cancel", BS_PUSHBUTTON | WS_TABSTOP, 660, 310, 75, 26, IDCANCEL);
    run_modal(dlg, parent, &st.base);
    cm_vec_free(&st.certs, (void (*)(void *))cm_certinfo_free);
    return st.base.result ? st.thumb : (free(st.thumb), (wchar_t *)NULL);
}

typedef struct { modal_base base; HWND user, pass, show; wchar_t *outUser, *outPass; } edge_state;

static LRESULT CALLBACK edge_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    edge_state *st = (edge_state *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (msg == WM_COMMAND) {
        int id = LOWORD(wp);
        if (id == 100) {
            bool checked = (SendMessageW(st->show, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SendMessageW(st->pass, EM_SETPASSWORDCHAR, checked ? 0 : (WPARAM)L'*', 0);
            InvalidateRect(st->pass, NULL, TRUE);
        } else if (id == IDOK) {
            st->outUser = get_text(st->user); st->outPass = get_text(st->pass);
            st->base.result = 1; st->base.done = 1;
        } else if (id == IDCANCEL) { st->base.done = 1; }
    } else if (msg == WM_CLOSE) { st->base.done = 1; }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

bool cm_dlg_edge_property(HWND parent, const cm_edge_cred *cred, wchar_t **outUser, wchar_t **outPass)
{
    edge_state st = {0};
    HWND dlg = make_dialog(parent, L"Edit Edge Credential", 440, 250, edge_proc, &st);
    ctrl(dlg, L"STATIC", L"Profile:", SS_LEFT, 15, 20, 90, 20, -1);
    HWND prof = edit(dlg, cred->profile_name, 120, 17, 285, -1, false); dfont(prof); SendMessageW(prof, EM_SETREADONLY, TRUE, 0);
    ctrl(dlg, L"STATIC", L"Website:", SS_LEFT, 15, 55, 90, 20, -1);
    HWND web = edit(dlg, cred->website, 120, 52, 285, -1, false); dfont(web); SendMessageW(web, EM_SETREADONLY, TRUE, 0);
    ctrl(dlg, L"STATIC", L"User name:", SS_LEFT, 15, 90, 90, 20, -1);
    st.user = edit(dlg, cred->username, 120, 87, 285, -1, false); dfont(st.user);
    ctrl(dlg, L"STATIC", L"Password:", SS_LEFT, 15, 125, 90, 20, -1);
    st.pass = edit(dlg, cred->password, 120, 122, 285, -1, true); dfont(st.pass);
    st.show = ctrl(dlg, L"BUTTON", L"Show password", BS_AUTOCHECKBOX | WS_TABSTOP, 120, 150, 150, 20, 100);
    ctrl(dlg, L"STATIC", L"Saving writes to the live Edge Login Data DB and stores the password as Chromium v10.",
         SS_LEFT, 15, 175, 390, 30, -1);
    ctrl(dlg, L"BUTTON", L"OK", BS_DEFPUSHBUTTON | WS_TABSTOP, 235, 210, 75, 26, IDOK);
    ctrl(dlg, L"BUTTON", L"Cancel", BS_PUSHBUTTON | WS_TABSTOP, 320, 210, 75, 26, IDCANCEL);
    run_modal(dlg, parent, &st.base);
    if (st.base.result) { *outUser = st.outUser; *outPass = st.outPass; return true; }
    free(st.outUser); free(st.outPass);
    return false;
}

typedef struct {
    modal_base base; const cm_vaultcred *existing;
    HWND friendly, resource, identity, auth, show;
} vault_state;

static LRESULT CALLBACK vault_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    vault_state *st = (vault_state *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (msg == WM_COMMAND) {
        int id = LOWORD(wp);
        if (id == 100) {
            bool checked = (SendMessageW(st->show, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SendMessageW(st->auth, EM_SETPASSWORDCHAR, checked ? 0 : (WPARAM)L'*', 0);
            InvalidateRect(st->auth, NULL, TRUE);
        } else if (id == IDOK) {
            wchar_t *fn = get_text(st->friendly), *res = get_text(st->resource);
            wchar_t *idn = get_text(st->identity), *a = get_text(st->auth);
            if (!fn[0] || !res[0]) {
                MessageBoxW(hwnd, L"Friendly Name and Resource are required.", L"Vault", MB_OK | MB_ICONWARNING);
            } else {
                GUID schema; int hr = 0; bool ok = false;
                if (st->existing) schema = st->existing->schema_id;
                else {
                    extern void cm_get_all_vault_guids(cm_vec *);
                    cm_vec guids; cm_vec_init(&guids); cm_get_all_vault_guids(&guids);
                    if (guids.count > 0) schema = *(GUID *)guids.items[0];
                    else schema = CM_VAULT_WEB_CREDENTIALS;
                    cm_vec_free(&guids, free);
                }
                cm_vault_manager *vm = cm_vault_open(&schema, &hr);
                if (vm) {
                    if (st->existing) cm_vault_delete_item(vm, st->existing);
                    ok = cm_vault_create_item(vm, fn, res, idn, a, &schema);
                    cm_vault_close(vm);
                }
                if (ok) { st->base.result = 1; st->base.done = 1; }
                else MessageBoxW(hwnd, L"Vault operation failed.", L"Vault", MB_OK | MB_ICONERROR);
            }
            free(fn); free(res); free(idn); free(a);
        } else if (id == IDCANCEL) { st->base.done = 1; }
    } else if (msg == WM_CLOSE) { st->base.done = 1; }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

bool cm_dlg_vault_property(HWND parent, const cm_vaultcred *existing)
{
    vault_state st = {0}; st.existing = existing;
    HWND dlg = make_dialog(parent, existing ? L"Vault Item Properties" : L"Add Vault Credential",
                           380, 310, vault_proc, &st);
    ctrl(dlg, L"STATIC", L"Friendly Name:", SS_LEFT, 15, 20, 120, 20, -1);
    st.friendly = edit(dlg, existing ? existing->friendly_name : L"", 145, 17, 200, -1, false); dfont(st.friendly);
    ctrl(dlg, L"STATIC", L"Resource:", SS_LEFT, 15, 50, 120, 20, -1);
    st.resource = edit(dlg, existing ? existing->resource : L"", 145, 47, 200, -1, false); dfont(st.resource);
    ctrl(dlg, L"STATIC", L"Identity:", SS_LEFT, 15, 80, 120, 20, -1);
    st.identity = edit(dlg, existing ? existing->identity : L"", 145, 77, 200, -1, false); dfont(st.identity);
    ctrl(dlg, L"STATIC", L"Authenticator:", SS_LEFT, 15, 110, 120, 20, -1);
    st.auth = edit(dlg, existing ? existing->authenticator : L"", 145, 107, 200, -1, true); dfont(st.auth);
    st.show = ctrl(dlg, L"BUTTON", L"Show secret", BS_AUTOCHECKBOX | WS_TABSTOP, 145, 133, 150, 20, 100);
    ctrl(dlg, L"BUTTON", L"OK", BS_DEFPUSHBUTTON | WS_TABSTOP, 180, 230, 80, 26, IDOK);
    ctrl(dlg, L"BUTTON", L"Cancel", BS_PUSHBUTTON | WS_TABSTOP, 270, 230, 80, 26, IDCANCEL);
    run_modal(dlg, parent, &st.base);
    return st.base.result != 0;
}

typedef struct {
    modal_base base;
    const cm_credential *existing;
    const wchar_t *target_type;
    HWND combo, target, user, pass, browse, show, help;
} prop_state;

static bool prop_is_cert(prop_state *st)
{
    if (st->existing) return st->existing->type == CM_CRED_DOMAIN_CERTIFICATE || st->existing->type == CM_CRED_GENERIC_CERTIFICATE;
    if (st->combo) return SendMessageW(st->combo, CB_GETCURSEL, 0, 0) == 1;
    return false;
}

static void prop_update_labels(HWND hwnd, prop_state *st)
{
    bool cert = prop_is_cert(st);
    SetWindowTextW(GetDlgItem(hwnd, 201), cert ? L"Thumbprint:" : L"Password:");
    ShowWindow(st->browse, cert ? SW_SHOW : SW_HIDE);
    ShowWindow(st->show, cert ? SW_HIDE : SW_SHOW);
    SendMessageW(st->pass, EM_SETPASSWORDCHAR, cert ? 0 : (WPARAM)L'*', 0);
    InvalidateRect(st->pass, NULL, TRUE);
    SetWindowTextW(st->help, cert
        ? L"Select a certificate from Current User > Personal or paste its SHA-1 thumbprint."
        : L"Make sure the user name and password can be used to access the location.");
}

static bool prop_save(HWND hwnd, prop_state *st)
{
    wchar_t *target = get_text(st->target);
    wchar_t *user = get_text(st->user);
    wchar_t *pass = get_text(st->pass);
    bool cert = prop_is_cert(st);
    bool ok = false;

    if (!target[0] || !user[0]) {
        MessageBoxW(hwnd, L"'Log on to' and 'User name' cannot be blank.", L"Malformed Data", MB_OK | MB_ICONWARNING);
        goto done;
    }

    if (cm_wcsicmp_safe(st->target_type, L"Web") == 0) {
        int hr = 0;
        cm_vault_manager *vm = cm_vault_open(&CM_VAULT_WEB_CREDENTIALS, &hr);
        if (vm) {
            GUID g = CM_VAULT_WEB_CREDENTIALS;
            ok = cm_vault_create_item(vm, target, target, user, pass, &g);
            cm_vault_close(vm);
        }
        if (!ok) MessageBoxW(hwnd, L"Windows Web Vault rejected this entry.", L"Vault Storage Error", MB_OK | MB_ICONERROR);
        goto done;
    }

    DWORD type;
    if (st->existing) type = st->existing->type;
    else {
        int sel = st->combo ? (int)SendMessageW(st->combo, CB_GETCURSEL, 0, 0) : 0;
        type = (sel == 1) ? CM_CRED_DOMAIN_CERTIFICATE : (sel == 2) ? CM_CRED_GENERIC : CM_CRED_DOMAIN_PASSWORD;
    }

    if (st->existing && !cert && wcscmp(pass, L"************") == 0) { ok = true; goto done; }

    DWORD err = 0;
    if (cert) {
        wchar_t *norm = cm_cert_normalize_thumbprint(pass);
        if (!norm || wcslen(norm) != 40) {
            MessageBoxW(hwnd, L"Certificate thumbprints must be 40 hex characters.", L"Malformed Data", MB_OK | MB_ICONWARNING);
            free(norm); goto done;
        }
        wchar_t *msg = NULL;
        if (!cm_cert_is_usable(norm, &msg)) {
            MessageBoxW(hwnd, msg ? msg : L"The certificate is not usable.", L"Certificate", MB_OK | MB_ICONWARNING);
            free(msg); free(norm); goto done;
        }
        free(msg);
        unsigned char hash[20]; cm_hex_to_bytes(norm, hash, 20);
        unsigned char blob[24];
        unsigned int size = 24; memcpy(blob, &size, 4); memcpy(blob + 4, hash, 20);
        wchar_t *marshaled = cm_marshal_certificate_username(hash, &err);
        if (marshaled) {
            ok = cm_credential_write(type, target, marshaled, user , 2, blob, 24, &err);
            free(marshaled);
        }
        free(norm);
    } else {
        const unsigned char *blob = (const unsigned char *)pass;
        DWORD blobSize = pass[0] ? (DWORD)(wcslen(pass) * sizeof(wchar_t)) : 0;
        ok = cm_credential_write(type, target, user, NULL, 2, blob, blobSize, &err);
    }
    if (!ok) {
        wchar_t m[160]; swprintf(m, 160, L"Windows credential write failed (error %lu).", (unsigned long)err);
        MessageBoxW(hwnd, m, L"API Error", MB_OK | MB_ICONERROR);
    }
done:
    free(target); free(user); free(pass);
    return ok;
}

static LRESULT CALLBACK prop_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    prop_state *st = (prop_state *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (msg == WM_COMMAND) {
        int id = LOWORD(wp), code = HIWORD(wp);
        if (id == 300 && code == CBN_SELCHANGE) { prop_update_labels(hwnd, st); }
        else if (id == 100) {
            bool checked = (SendMessageW(st->show, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SendMessageW(st->pass, EM_SETPASSWORDCHAR, checked ? 0 : (WPARAM)L'*', 0);
            InvalidateRect(st->pass, NULL, TRUE);
        } else if (id == 101) {
            wchar_t *t = cm_dlg_cert_picker(hwnd);
            if (t) { SetWindowTextW(st->pass, t); free(t); }
        } else if (id == IDOK) {
            if (prop_save(hwnd, st)) { st->base.result = 1; st->base.done = 1; }
        } else if (id == IDCANCEL) { st->base.done = 1; }
    } else if (msg == WM_CLOSE) { st->base.done = 1; }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

bool cm_dlg_property(HWND parent, const cm_credential *existing, const wchar_t *targetType)
{
    prop_state st = {0}; st.existing = existing; st.target_type = targetType;
    bool web = (cm_wcsicmp_safe(targetType, L"Web") == 0);
    HWND dlg = make_dialog(parent, existing ? L"Logon Information Properties" : L"Add Stored Credential",
                           380, 320, prop_proc, &st);
    int y = 17;
    if (!existing && !web) {
        ctrl(dlg, L"STATIC", L"Credential Type:", SS_LEFT, 15, 20, 120, 20, -1);
        st.combo = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
                                   145, 17, 200, 200, dlg, (HMENU)(INT_PTR)300, GetModuleHandleW(NULL), NULL);
        dfont(st.combo);
        SendMessageW(st.combo, CB_ADDSTRING, 0, (LPARAM)L"Windows Credential");
        SendMessageW(st.combo, CB_ADDSTRING, 0, (LPARAM)L"Certificate-Based Credential");
        SendMessageW(st.combo, CB_ADDSTRING, 0, (LPARAM)L"Generic Credential");
        int sel = (cm_wcsicmp_safe(targetType, L"Windows_Cert") == 0) ? 1
                : (cm_wcsicmp_safe(targetType, L"Windows_Gen") == 0) ? 2 : 0;
        SendMessageW(st.combo, CB_SETCURSEL, sel, 0);
        y = 52;
    }
    ctrl(dlg, L"STATIC", L"Log on to:", SS_LEFT, 15, y, 120, 20, 200);
    st.target = edit(dlg, existing ? existing->target : L"", 145, y - 3, 200, -1, false); dfont(st.target);
    if (existing) SendMessageW(st.target, EM_SETREADONLY, TRUE, 0);
    ctrl(dlg, L"STATIC", L"User name:", SS_LEFT, 15, y + 30, 120, 20, -1);
    st.user = edit(dlg, existing ? existing->username : L"", 145, y + 27, 200, -1, false); dfont(st.user);
    ctrl(dlg, L"STATIC", L"Password:", SS_LEFT, 15, y + 60, 120, 20, 201);
    {
        const wchar_t *pw = L"";
        if (existing) pw = (existing->password && existing->password[0]) ? existing->password : L"************";
        st.pass = edit(dlg, pw, 145, y + 57, 150, -1, true); dfont(st.pass);
    }
    st.browse = ctrl(dlg, L"BUTTON", L"Browse...", BS_PUSHBUTTON | WS_TABSTOP, 300, y + 56, 65, 24, 101);
    st.show = ctrl(dlg, L"BUTTON", L"Show password", BS_AUTOCHECKBOX | WS_TABSTOP, 145, y + 85, 150, 20, 100);
    st.help = ctrl(dlg, L"STATIC", L"", SS_LEFT, 15, y + 110, 330, 48, -1);
    ShowWindow(st.browse, SW_HIDE);

    ctrl(dlg, L"BUTTON", L"OK", BS_DEFPUSHBUTTON | WS_TABSTOP, 180, 250, 80, 26, IDOK);
    ctrl(dlg, L"BUTTON", L"Cancel", BS_PUSHBUTTON | WS_TABSTOP, 270, 250, 80, 26, IDCANCEL);

    prop_update_labels(dlg, &st);
    run_modal(dlg, parent, &st.base);
    return st.base.result != 0;
}
