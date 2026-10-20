#include "ui.h"
#include "resource.h"
#include "util.h"
#include "cred_api.h"
#include "vault.h"
#include "vault_probe.h"
#include "edge.h"
#include "domain.h"
#include "cert.h"
#include "diag_cli.h"
#include "backup.h"
#include "dialogs.h"
#include <commctrl.h>
#include <shellapi.h>
#include <commdlg.h>
#include <windowsx.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>

static HINSTANCE g_inst;
static HWND g_main, g_tab;
static HWND g_page[4];
static HFONT g_font, g_fontBold;

static HWND g_lvWeb;

static HWND g_lvWinCore, g_lvWinCert, g_lvWinGen;

static HWND g_lvEdge, g_edgeFilter;

static HWND g_diagWin, g_diagPV, g_diagEdge, g_diagVault, g_diagVcmd, g_diagErr, g_diagFilter;
static int  g_diagContentHeight;
static int  g_diagScrollPos;

static HWND g_btnAdd, g_btnRemove, g_btnEdit, g_btnBackup, g_btnRestore, g_btnImport, g_btnClose;

static cm_vec g_webColl;
static cm_vec g_winCoreColl;
static cm_vec g_winCertColl;
static cm_vec g_winGenColl;
static cm_vec g_edgeColl;

static cm_vec g_edgeFiltered;

static HWND g_lastFocused;

HWND cm_main_hwnd(void) { return g_main; }

static void set_font(HWND h) { if (h) SendMessageW(h, WM_SETFONT, (WPARAM)g_font, TRUE); }

static HWND mk_label(HWND parent, const wchar_t *text, int x, int y, int w, int h, bool bold)
{
    HWND l = CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE | SS_LEFT,
                             x, y, w, h, parent, NULL, g_inst, NULL);
    SendMessageW(l, WM_SETFONT, (WPARAM)(bold ? g_fontBold : g_font), TRUE);
    return l;
}

static HWND mk_button(HWND parent, const wchar_t *text, int id, int x, int y, int w, int h)
{
    HWND b = CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                             x, y, w, h, parent, (HMENU)(INT_PTR)id, g_inst, NULL);
    set_font(b);
    return b;
}

static HWND mk_listview(HWND parent, int id, int x, int y, int w, int h)
{
    HWND lv = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                              WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                              x, y, w, h, parent, (HMENU)(INT_PTR)id, g_inst, NULL);
    ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    set_font(lv);
    return lv;
}

static void lv_add_col(HWND lv, int idx, const wchar_t *text, int width)
{
    LVCOLUMNW c = {0};
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = (LPWSTR)text; c.cx = width; c.iSubItem = idx;
    ListView_InsertColumn(lv, idx, &c);
}

static int lv_add_row(HWND lv, const wchar_t *col0)
{
    LVITEMW it = {0};
    it.mask = LVIF_TEXT; it.iItem = ListView_GetItemCount(lv);
    it.pszText = (LPWSTR)(col0 ? col0 : L"");
    return ListView_InsertItem(lv, &it);
}

static void lv_set_sub(HWND lv, int item, int sub, const wchar_t *text)
{
    ListView_SetItemText(lv, item, sub, (LPWSTR)(text ? text : L""));
}

static int lv_selected(HWND lv)
{
    return (int)SendMessageW(lv, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
}

static void load_web_credentials(cm_vec *out)
{
    int hr = 0;
    cm_vault_manager *vm = cm_vault_open(&CM_VAULT_WEB_CREDENTIALS, &hr);
    if (!vm) return;
    cm_vec items; cm_vec_init(&items);
    cm_vault_enumerate(vm, &items);
    for (size_t i = 0; i < items.count; i++) {
        cm_vaultcred *vc = (cm_vaultcred *)items.items[i];
        cm_credential *c = (cm_credential *)calloc(1, sizeof(cm_credential));
        if (c) {
            c->target = cm_wcsdup(vc->resource ? vc->resource : L"");
            c->username = cm_wcsdup(vc->identity ? vc->identity : L"");
            c->password = cm_wcsdup(vc->authenticator ? vc->authenticator : L"");
            c->type = 0;
            cm_vec_push(out, c);
        }
    }
    cm_vec_free(&items, (void (*)(void *))cm_vaultcred_free);
    cm_vault_close(vm);
}

static void diag_clear(void)
{
    ListView_DeleteAllItems(g_diagWin);
    ListView_DeleteAllItems(g_diagPV);
    ListView_DeleteAllItems(g_diagEdge);
    ListView_DeleteAllItems(g_diagVault);
    ListView_DeleteAllItems(g_diagVcmd);
    ListView_DeleteAllItems(g_diagErr);
}

static void diag_err_log(const wchar_t *source, const wchar_t *msg)
{
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t ts[16]; swprintf(ts, 16, L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
    int r = lv_add_row(g_diagErr, ts);
    lv_set_sub(g_diagErr, r, 1, source);
    lv_set_sub(g_diagErr, r, 2, msg);
}

static void diag_populate(void)
{
    diag_clear();

    cm_vec cmd; cm_vec_init(&cmd);
    cm_cmdkey_list(&cmd);
    if (cmd.count == 0) {
        int r = lv_add_row(g_diagWin, L"cmdkey.exe");
        lv_set_sub(g_diagWin, r, 1, L"[No credentials found]");
        lv_set_sub(g_diagWin, r, 4, L"INFO");
    } else {
        for (size_t i = 0; i < cmd.count; i++) {
            cm_cmdkey_cred *c = (cm_cmdkey_cred *)cmd.items[i];
            int r = lv_add_row(g_diagWin, L"cmdkey.exe");
            lv_set_sub(g_diagWin, r, 1, c->target);
            lv_set_sub(g_diagWin, r, 2, c->user);
            lv_set_sub(g_diagWin, r, 3, c->type);
            lv_set_sub(g_diagWin, r, 4, L"OK");
        }
    }
    cm_vec_free(&cmd, (void (*)(void *))cm_cmdkey_cred_free);

    if (g_webColl.count == 0) {
        int r = lv_add_row(g_diagPV, L"PasswordVault");
        lv_set_sub(g_diagPV, r, 1, L"[No web credentials found]");
        lv_set_sub(g_diagPV, r, 3, L"0");
        lv_set_sub(g_diagPV, r, 4, L"INFO");
    } else {
        for (size_t i = 0; i < g_webColl.count; i++) {
            cm_credential *c = (cm_credential *)g_webColl.items[i];
            int r = lv_add_row(g_diagPV, L"PasswordVault");
            lv_set_sub(g_diagPV, r, 1, c->target);
            lv_set_sub(g_diagPV, r, 2, c->username);
            lv_set_sub(g_diagPV, r, 3, L"1");
            lv_set_sub(g_diagPV, r, 4, L"OK");
        }
    }

    if (g_edgeColl.count == 0) {
        int r = lv_add_row(g_diagEdge, L"[No Edge profiles found]");
        lv_set_sub(g_diagEdge, r, 5, L"INFO");
    } else {
        for (size_t i = 0; i < g_edgeColl.count; i++) {
            cm_edge_cred *c = (cm_edge_cred *)g_edgeColl.items[i];
            int r = lv_add_row(g_diagEdge, c->profile_name);
            lv_set_sub(g_diagEdge, r, 1, c->website);
            lv_set_sub(g_diagEdge, r, 2, c->username);
            lv_set_sub(g_diagEdge, r, 3, c->password);
            lv_set_sub(g_diagEdge, r, 4, c->last_used);
            lv_set_sub(g_diagEdge, r, 5, c->enc_version);
            if (c->enc_version && wcscmp(c->enc_version, L"ERROR") == 0)
                diag_err_log(L"Edge Login Data", c->password);
        }
    }

    cm_vec probes; cm_vec_init(&probes);
    cm_vault_probe_all(&probes);
    cm_vec vguids; cm_vec_init(&vguids);
    cm_get_all_vault_guids(&vguids);
    if (vguids.count == 0 && probes.count == 0) {
        int r = lv_add_row(g_diagVault, L"Vault Files");
        lv_set_sub(g_diagVault, r, 1, L"[No vaults found]");
        lv_set_sub(g_diagVault, r, 3, L"0");
        lv_set_sub(g_diagVault, r, 4, L"INFO");
    } else {
        for (size_t v = 0; v < vguids.count; v++) {
            GUID *gid = (GUID *)vguids.items[v];
            wchar_t guidText[64];
            swprintf(guidText, 64, L"%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                     gid->Data1, gid->Data2, gid->Data3,
                     gid->Data4[0], gid->Data4[1], gid->Data4[2], gid->Data4[3],
                     gid->Data4[4], gid->Data4[5], gid->Data4[6], gid->Data4[7]);
            int hr = 0, itemCount = 0;
            wchar_t *summary = NULL;
            cm_vault_manager *vm = cm_vault_open(gid, &hr);
            if (vm) {
                cm_vec items; cm_vec_init(&items);
                cm_vault_enumerate(vm, &items);
                itemCount = (int)items.count;
                summary = cm_vault_last_summary(vm);
                cm_vec_free(&items, (void (*)(void *))cm_vaultcred_free);
                cm_vault_close(vm);
            }

            cm_vault_probe *probe = NULL;
            for (size_t i = 0; i < probes.count; i++) {
                cm_vault_probe *p = (cm_vault_probe *)probes.items[i];
                if (p->vault_guid && _wcsicmp(p->vault_guid, guidText) == 0) { probe = p; break; }
            }
            const wchar_t *status; const wchar_t *detail; int count;
            if (itemCount > 0) { status = L"ENUM-OK"; detail = summary; count = itemCount; }
            else if (probe && probe->decrypted_credential_count > 0) { status = L"FILE-OK"; detail = probe->detail; count = probe->decrypted_credential_count; }
            else { status = probe ? probe->status : L"API-LIMITED"; detail = probe ? probe->detail : (summary ? summary : L""); count = 0; }
            int r = lv_add_row(g_diagVault, L"Vault");
            lv_set_sub(g_diagVault, r, 1, guidText);
            lv_set_sub(g_diagVault, r, 2, detail ? detail : L"");
            wchar_t cnt[16]; swprintf(cnt, 16, L"%d", count);
            lv_set_sub(g_diagVault, r, 3, cnt);
            lv_set_sub(g_diagVault, r, 4, status);
            if (detail && detail[0]) diag_err_log(L"Vault", detail);
            free(summary);
        }
    }
    cm_vec_free(&vguids, free);
    cm_vec_free(&probes, (void (*)(void *))cm_vault_probe_free);

    cm_vec vcmd; cm_vec_init(&vcmd);
    cm_vaultcmd_list(&vcmd);
    if (vcmd.count == 0) {
        int r = lv_add_row(g_diagVcmd, L"vaultcmd.exe");
        lv_set_sub(g_diagVcmd, r, 1, L"[No system-protected credentials]");
        lv_set_sub(g_diagVcmd, r, 4, L"INFO");
    } else {
        for (size_t i = 0; i < vcmd.count; i++) {
            cm_vaultcmd_cred *c = (cm_vaultcmd_cred *)vcmd.items[i];
            int r = lv_add_row(g_diagVcmd, L"vaultcmd.exe");
            lv_set_sub(g_diagVcmd, r, 1, c->vault_name);
            lv_set_sub(g_diagVcmd, r, 2, c->target);
            lv_set_sub(g_diagVcmd, r, 3, c->username);
            lv_set_sub(g_diagVcmd, r, 4, L"CLI-ONLY");
        }
    }
    cm_vec_free(&vcmd, (void (*)(void *))cm_vaultcmd_cred_free);
}

static void edge_refilter(void)
{
    ListView_DeleteAllItems(g_lvEdge);
    g_edgeFiltered.count = 0;
    wchar_t filter[256]; GetWindowTextW(g_edgeFilter, filter, 256);
    for (size_t i = 0; i < g_edgeColl.count; i++) {
        cm_edge_cred *c = (cm_edge_cred *)g_edgeColl.items[i];
        if (filter[0] &&
            !cm_wcs_contains_ci(c->profile_name, filter) &&
            !cm_wcs_contains_ci(c->website, filter) &&
            !cm_wcs_contains_ci(c->username, filter) &&
            !cm_wcs_contains_ci(c->password, filter) &&
            !cm_wcs_contains_ci(c->enc_version, filter))
            continue;
        cm_vec_push(&g_edgeFiltered, c);
        int r = lv_add_row(g_lvEdge, c->profile_name);
        lv_set_sub(g_lvEdge, r, 1, c->website);
        lv_set_sub(g_lvEdge, r, 2, c->username);
        lv_set_sub(g_lvEdge, r, 3, c->password);
        lv_set_sub(g_lvEdge, r, 4, c->last_used);
        lv_set_sub(g_lvEdge, r, 5, c->enc_version);
    }
    if (ListView_GetItemCount(g_lvEdge) == 0) {
        int r = lv_add_row(g_lvEdge, filter[0] ? L"[No Edge entries match the filter]" : L"[No Edge credentials found]");
        lv_set_sub(g_lvEdge, r, 5, L"INFO");
    }
}

static void update_button_states(void);

void cm_refresh_ui(void)
{
    ListView_DeleteAllItems(g_lvWeb);
    ListView_DeleteAllItems(g_lvWinCore);
    ListView_DeleteAllItems(g_lvWinCert);
    ListView_DeleteAllItems(g_lvWinGen);
    ListView_DeleteAllItems(g_lvEdge);

    cm_vec_free(&g_webColl, (void (*)(void *))cm_credential_free);     cm_vec_init(&g_webColl);
    cm_vec_free(&g_winCoreColl, (void (*)(void *))cm_credential_free); cm_vec_init(&g_winCoreColl);
    cm_vec_free(&g_winCertColl, (void (*)(void *))cm_credential_free); cm_vec_init(&g_winCertColl);
    cm_vec_free(&g_winGenColl, (void (*)(void *))cm_credential_free);  cm_vec_init(&g_winGenColl);
    cm_vec_free(&g_edgeColl, (void (*)(void *))cm_edge_cred_free);     cm_vec_init(&g_edgeColl);

    load_web_credentials(&g_webColl);
    for (size_t i = 0; i < g_webColl.count; i++) {
        cm_credential *c = (cm_credential *)g_webColl.items[i];
        int r = lv_add_row(g_lvWeb, c->target);
        lv_set_sub(g_lvWeb, r, 1, c->username);
    }

    cm_vec all; cm_vec_init(&all);
    cm_credential_load_all(&all);
    for (size_t i = 0; i < all.count; i++) {
        cm_credential *c = (cm_credential *)all.items[i];
        cm_credential *copy = (cm_credential *)calloc(1, sizeof(cm_credential));
        copy->target = cm_wcsdup(c->target); copy->username = cm_wcsdup(c->username);
        copy->password = cm_wcsdup(c->password ? c->password : L""); copy->comment = cm_wcsdup(c->comment ? c->comment : L"");
        copy->type = c->type; copy->persist = c->persist; copy->last_written = c->last_written;
        HWND lv; cm_vec *coll;
        if (c->type == CM_CRED_GENERIC) { lv = g_lvWinGen; coll = &g_winGenColl; }
        else if (c->type == CM_CRED_DOMAIN_CERTIFICATE || c->type == CM_CRED_GENERIC_CERTIFICATE) { lv = g_lvWinCert; coll = &g_winCertColl; }
        else { lv = g_lvWinCore; coll = &g_winCoreColl; }
        cm_vec_push(coll, copy);
        int r = lv_add_row(lv, copy->target);
        lv_set_sub(lv, r, 1, copy->username);
    }
    cm_vec_free(&all, (void (*)(void *))cm_credential_free);

    cm_edge_load_diagnostics(&g_edgeColl);
    edge_refilter();

    diag_populate();

    update_button_states();
}

static int current_tab(void) { return (int)SendMessageW(g_tab, TCM_GETCURSEL, 0, 0); }

static void update_button_states(void)
{
    int tab = current_tab();
    ShowWindow(g_btnImport, tab == 3 ? SW_SHOW : SW_HIDE);

    if (tab == 2) {
        EnableWindow(g_btnAdd, FALSE);
        bool sel = (g_lastFocused == g_lvEdge) && lv_selected(g_lvEdge) >= 0;
        EnableWindow(g_btnEdit, sel);
        EnableWindow(g_btnRemove, sel);
        return;
    }
    if (tab == 3) {
        EnableWindow(g_btnAdd, cm_vault_available());
        bool sel = (g_lastFocused == g_diagEdge) && lv_selected(g_diagEdge) >= 0;
        EnableWindow(g_btnEdit, sel);
        EnableWindow(g_btnRemove, sel);
        return;
    }
    EnableWindow(g_btnAdd, TRUE);
    if (tab == 0) g_lastFocused = g_lvWeb;
    if (!g_lastFocused) g_lastFocused = g_lvWeb;
    bool sel = lv_selected(g_lastFocused) >= 0;
    EnableWindow(g_btnEdit, sel);
    EnableWindow(g_btnRemove, sel);
}

static void clear_other_selections(HWND active)
{
    HWND grids[] = { g_lvWinCore, g_lvWinCert, g_lvWinGen };
    for (int i = 0; i < 3; i++)
        if (grids[i] != active)
            ListView_SetItemState(grids[i], -1, 0, LVIS_SELECTED);
    g_lastFocused = active;
    update_button_states();
}

static cm_credential *selected_credential(cm_vec *coll, HWND lv)
{
    int idx = lv_selected(lv);
    if (idx < 0 || (size_t)idx >= coll->count) return NULL;
    return (cm_credential *)coll->items[idx];
}

static void do_add(void)
{
    int tab = current_tab();
    if (tab == 0) { if (cm_dlg_property(g_main, NULL, L"Web")) cm_refresh_ui(); return; }
    if (tab == 1) {
        const wchar_t *type = L"Windows_Core";
        if (g_lastFocused == g_lvWinCert) type = L"Windows_Cert";
        else if (g_lastFocused == g_lvWinGen) type = L"Windows_Gen";
        if (cm_dlg_property(g_main, NULL, type)) cm_refresh_ui();
        return;
    }
    if (tab == 2) {
        MessageBoxW(g_main, L"Creating new Edge logins is not exposed.", L"Microsoft Edge",
                    MB_OK | MB_ICONINFORMATION);
        return;
    }
    if (tab == 3) { if (cm_dlg_vault_property(g_main, NULL)) cm_refresh_ui(); return; }
}

static bool edge_write_preconditions(const wchar_t *verb, const cm_edge_cred *c)
{
    if (!c || c->login_id <= 0 || !c->profile_path || !c->profile_path[0]) {
        MessageBoxW(g_main, L"The selected Edge credential has no writable database row.",
                    L"Edge Diagnostics", MB_OK | MB_ICONWARNING);
        return false;
    }
    bool running = cm_edge_is_running();
    wchar_t msg[512];
    swprintf(msg, 512, L"This writes directly to the live Edge 'Login Data' DB for profile '%ls'.\n\n%ls\nContinue?",
             c->profile_name ? c->profile_name : L"",
             running ? L"Edge is running and will be closed first; unsaved tabs may be lost.\n"
                     : L"Edge is not running, but the live profile DB will be modified.\n");
    if (MessageBoxW(g_main, msg, L"Edge Diagnostics Write Warning", MB_YESNO | MB_ICONWARNING) != IDYES)
        return false;
    if (running) {
        cm_edge_kill();
        Sleep(750);
        if (cm_edge_is_running()) {
            MessageBoxW(g_main, L"Could not close Microsoft Edge.", L"Edge Diagnostics", MB_OK | MB_ICONERROR);
            return false;
        }
    }
    (void)verb;
    return true;
}

static void do_edit(void)
{
    int tab = current_tab();
    if (tab == 2 || (tab == 3 && g_lastFocused == g_diagEdge)) {
        HWND lv = (tab == 2) ? g_lvEdge : g_diagEdge;
        cm_vec *src = (tab == 2) ? &g_edgeFiltered : &g_edgeColl;
        int idx = lv_selected(lv);
        if (idx < 0 || (size_t)idx >= src->count) return;
        cm_edge_cred *c = (cm_edge_cred *)src->items[idx];
        if (!edge_write_preconditions(L"updated", c)) return;
        wchar_t *u = NULL, *p = NULL;
        if (!cm_dlg_edge_property(g_main, c, &u, &p)) return;
        wchar_t *err = NULL;
        if (cm_edge_update_credential(c->login_id, c->profile_path, u, p, &err)) {
            cm_refresh_ui();
            MessageBoxW(g_main, L"The Edge credential was updated.", L"Microsoft Edge", MB_OK | MB_ICONINFORMATION);
        } else {
            MessageBoxW(g_main, err ? err : L"Update failed.", L"Microsoft Edge", MB_OK | MB_ICONERROR);
        }
        free(u); free(p); free(err);
        return;
    }

    cm_vec *coll = NULL; const wchar_t *type = NULL;
    if (g_lastFocused == g_lvWeb) { coll = &g_webColl; type = L"Web"; }
    else if (g_lastFocused == g_lvWinCore) { coll = &g_winCoreColl; type = L"Windows_Core"; }
    else if (g_lastFocused == g_lvWinCert) { coll = &g_winCertColl; type = L"Windows_Cert"; }
    else if (g_lastFocused == g_lvWinGen) { coll = &g_winGenColl; type = L"Windows_Gen"; }
    if (!coll) return;
    cm_credential *c = selected_credential(coll, g_lastFocused);
    if (!c) return;
    if (cm_dlg_property(g_main, c, type)) cm_refresh_ui();
}

static void web_delete(cm_credential *c)
{
    int hr = 0;
    cm_vault_manager *vm = cm_vault_open(&CM_VAULT_WEB_CREDENTIALS, &hr);
    if (!vm) return;
    cm_vaultcred vc = {0};
    vc.resource = c->target; vc.identity = c->username; vc.authenticator = c->password;
    vc.schema_id = CM_VAULT_WEB_CREDENTIALS;
    cm_vault_delete_item(vm, &vc);
    cm_vault_close(vm);
}

static void do_remove(void)
{
    int tab = current_tab();
    if (tab == 2 || (tab == 3 && g_lastFocused == g_diagEdge)) {
        HWND lv = (tab == 2) ? g_lvEdge : g_diagEdge;
        cm_vec *src = (tab == 2) ? &g_edgeFiltered : &g_edgeColl;
        int idx = lv_selected(lv);
        if (idx < 0 || (size_t)idx >= src->count) return;
        cm_edge_cred *c = (cm_edge_cred *)src->items[idx];
        if (!edge_write_preconditions(L"deleted", c)) return;
        wchar_t q[300];
        swprintf(q, 300, L"Remove the Edge credential for '%ls' in profile '%ls'?\n\nThis cannot be undone.",
                 c->website ? c->website : L"", c->profile_name ? c->profile_name : L"");
        if (MessageBoxW(g_main, q, L"Confirm Edge Removal", MB_YESNO | MB_ICONWARNING) != IDYES) return;
        wchar_t *err = NULL;
        if (cm_edge_delete_credential(c->login_id, c->profile_path, &err)) {
            cm_refresh_ui();
            MessageBoxW(g_main, L"The Edge credential was removed.", L"Microsoft Edge", MB_OK | MB_ICONINFORMATION);
        } else {
            MessageBoxW(g_main, err ? err : L"Remove failed.", L"Microsoft Edge", MB_OK | MB_ICONERROR);
        }
        free(err);
        return;
    }

    cm_vec *coll = NULL;
    if (g_lastFocused == g_lvWeb) coll = &g_webColl;
    else if (g_lastFocused == g_lvWinCore) coll = &g_winCoreColl;
    else if (g_lastFocused == g_lvWinCert) coll = &g_winCertColl;
    else if (g_lastFocused == g_lvWinGen) coll = &g_winGenColl;
    if (!coll) return;
    cm_credential *c = selected_credential(coll, g_lastFocused);
    if (!c) return;
    wchar_t q[300];
    swprintf(q, 300, L"Remove credential for '%ls'?", c->target ? c->target : L"");
    if (MessageBoxW(g_main, q, L"Confirm Removal", MB_YESNO) != IDYES) return;
    if (g_lastFocused == g_lvWeb) web_delete(c);
    else { DWORD e = 0; cm_credential_delete(c->target, c->type, &e); }
    cm_refresh_ui();
}

static void do_backup(void)
{
    ShellExecuteW(g_main, L"open", L"rundll32.exe",
                  L"keymgr.dll,PRShowSaveWizardExW", NULL, SW_SHOWNORMAL);
}
static void do_restore(void)
{
    ShellExecuteW(g_main, L"open", L"rundll32.exe",
                  L"keymgr.dll,PRShowRestoreWizardExW", NULL, SW_SHOWNORMAL);
}

static void do_import_crd(void)
{
    if (MessageBoxW(g_main,
        L"Importing a .crd file restores it into the live credential store before this "
        L"tool can inspect it, then rolls it back. If interrupted, credentials could be "
        L"left behind. Continue?",
        L"Unsafe .crd Diagnostic Import", MB_OKCANCEL | MB_ICONWARNING) != IDOK)
        return;

    wchar_t file[MAX_PATH] = L"";
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = g_main;
    ofn.lpstrFilter = L"Credential Backup Files (*.crd)\0*.crd\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = file; ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Import Credential Manager Backup File";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return;

    wchar_t *pw = cm_dlg_import_password(g_main);
    if (!pw) return;
    cm_import_result r = cm_backup_import(file, pw, true);
    SecureZeroMemory(pw, (wcslen(pw) + 1) * sizeof(wchar_t));
    free(pw);
    MessageBoxW(g_main, r.message ? r.message : L"Done.",
                r.success ? L"Import" : L"Import Failed",
                MB_OK | (r.success ? MB_ICONINFORMATION : MB_ICONERROR));
    free(r.message);
    cm_refresh_ui();
}

static void copy_row(HWND lv, int sub )
{
    int idx = lv_selected(lv);
    if (idx < 0) return;
    wchar_t buf[2048]; buf[0] = 0;
    int cols = Header_GetItemCount(ListView_GetHeader(lv));
    if (sub >= 0) {
        ListView_GetItemText(lv, idx, sub, buf, 2048);
    } else {
        for (int c = 0; c < cols; c++) {
            wchar_t cell[512]; ListView_GetItemText(lv, idx, c, cell, 512);
            if (c) wcsncat(buf, L"\t", 2047 - wcslen(buf));
            wcsncat(buf, cell, 2047 - wcslen(buf));
        }
    }
    if (OpenClipboard(g_main)) {
        EmptyClipboard();
        size_t n = (wcslen(buf) + 1) * sizeof(wchar_t);
        HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, n);
        if (h) { memcpy(GlobalLock(h), buf, n); GlobalUnlock(h); SetClipboardData(CF_UNICODETEXT, h); }
        CloseClipboard();
    }
}

static void show_context_menu(HWND lv, int x, int y)
{
    HMENU m = CreatePopupMenu();
    bool edge = (lv == g_diagEdge || lv == g_lvEdge);
    if (edge) {
        AppendMenuW(m, MF_STRING, IDM_COPY_WEBSITE, L"Copy Website");
        AppendMenuW(m, MF_STRING, IDM_COPY_USERNAME, L"Copy Username");
        AppendMenuW(m, MF_STRING, IDM_COPY_PASSWORD, L"Copy Password");
        AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    }
    AppendMenuW(m, MF_STRING, IDM_COPY_FIRST, L"Copy Item (First Column)");
    AppendMenuW(m, MF_STRING, IDM_COPY_ALL, L"Copy Item (All Columns)");
    int cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON, x, y, 0, g_main, NULL);
    DestroyMenu(m);
    switch (cmd) {
        case IDM_COPY_FIRST: copy_row(lv, 0); break;
        case IDM_COPY_ALL: copy_row(lv, -1); break;
        case IDM_COPY_WEBSITE: copy_row(lv, 1); break;
        case IDM_COPY_USERNAME: copy_row(lv, 2); break;
        case IDM_COPY_PASSWORD: copy_row(lv, 3); break;
    }
}

static LRESULT CALLBACK diag_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_VSCROLL) {
        SCROLLINFO si = {0}; si.cbSize = sizeof(si); si.fMask = SIF_ALL;
        GetScrollInfo(hwnd, SB_VERT, &si);
        int old = si.nPos, pos = si.nPos;
        switch (LOWORD(wp)) {
            case SB_LINEUP: pos -= 20; break;
            case SB_LINEDOWN: pos += 20; break;
            case SB_PAGEUP: pos -= si.nPage; break;
            case SB_PAGEDOWN: pos += si.nPage; break;
            case SB_THUMBTRACK: case SB_THUMBPOSITION: pos = si.nTrackPos; break;
        }
        if (pos < 0) pos = 0;
        if (pos > si.nMax - (int)si.nPage) pos = si.nMax - (int)si.nPage;
        if (pos != old) {
            ScrollWindowEx(hwnd, 0, old - pos, NULL, NULL, NULL, NULL, SW_SCROLLCHILDREN | SW_INVALIDATE);
            si.fMask = SIF_POS; si.nPos = pos; SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
            g_diagScrollPos = pos;
        }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

#define TAB_X 12
#define TAB_Y 70
#define TAB_W 540
#define TAB_H 430
#define BTN_X 566
#define BTN_W 100

static HWND make_page(void)
{
    return CreateWindowExW(WS_EX_CONTROLPARENT, L"CMPage", L"",
                           WS_CHILD | WS_CLIPCHILDREN, 0, 0, 10, 10, g_tab, NULL, g_inst, NULL);
}

static void build_tab0(HWND page)
{
    g_lvWeb = mk_listview(page, IDC_LV_WEB, 6, 6, TAB_W - 24, TAB_H - 50);
    lv_add_col(g_lvWeb, 0, L"Resource / Website", 240);
    lv_add_col(g_lvWeb, 1, L"Identity Name", 240);
}

static void build_tab1(HWND page)
{
    int w = TAB_W - 24, h = 110;
    mk_label(page, L"Windows Credentials", 6, 6, w, 16, true);
    g_lvWinCore = mk_listview(page, IDC_LV_WINCORE, 6, 24, w, h);
    lv_add_col(g_lvWinCore, 0, L"Logged on to", 250); lv_add_col(g_lvWinCore, 1, L"User Name", 240);
    mk_label(page, L"Certificate-Based Credentials", 6, 140, w, 16, true);
    g_lvWinCert = mk_listview(page, IDC_LV_WINCERT, 6, 158, w, h);
    lv_add_col(g_lvWinCert, 0, L"Logged on to", 250); lv_add_col(g_lvWinCert, 1, L"User Name", 240);
    mk_label(page, L"Generic Credentials", 6, 274, w, 16, true);
    g_lvWinGen = mk_listview(page, IDC_LV_WINGEN, 6, 292, w, h);
    lv_add_col(g_lvWinGen, 0, L"Logged on to", 250); lv_add_col(g_lvWinGen, 1, L"User Name", 240);
}

static void build_tab2(HWND page)
{
    mk_label(page, L"Passwords are read from Edge's Login Data and written back when edited or removed.",
             6, 6, TAB_W - 24, 32, false);
    mk_label(page, L"Filter:", 6, 44, 40, 20, false);
    g_edgeFilter = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 50, 42, TAB_W - 70, 22,
        page, (HMENU)(INT_PTR)IDC_TXT_EDGEFILTER, g_inst, NULL);
    set_font(g_edgeFilter);
    g_lvEdge = mk_listview(page, IDC_LV_EDGE, 6, 72, TAB_W - 24, TAB_H - 120);
    lv_add_col(g_lvEdge, 0, L"Profile", 90);
    lv_add_col(g_lvEdge, 1, L"Website", 150);
    lv_add_col(g_lvEdge, 2, L"Username", 90);
    lv_add_col(g_lvEdge, 3, L"Password", 110);
    lv_add_col(g_lvEdge, 4, L"Last Used", 90);
    lv_add_col(g_lvEdge, 5, L"Enc", 40);
}

static HWND diag_lv(HWND page, int id, const wchar_t *title, int *y, int cols,
                    const wchar_t *c0, int w0, const wchar_t *c1, int w1,
                    const wchar_t *c2, int w2, const wchar_t *c3, int w3, const wchar_t *c4, int w4)
{
    int w = TAB_W - 40;
    mk_label(page, title, 6, *y, w, 18, true); *y += 20;
    HWND lv = mk_listview(page, id, 6, *y, w, 110); *y += 120;
    const wchar_t *names[5] = { c0, c1, c2, c3, c4 };
    int widths[5] = { w0, w1, w2, w3, w4 };
    for (int i = 0; i < cols; i++) lv_add_col(lv, i, names[i], widths[i]);
    return lv;
}

static void build_tab3(HWND page)
{
    int y = 6;
    g_diagWin = diag_lv(page, IDC_LV_DIAG_WIN, L"Windows Credential Manager (cmdkey.exe / DPAPI)", &y,
                        5, L"Source", 80, L"Target", 170, L"Username", 130, L"Type", 70, L"Status", 70);
    g_diagPV = diag_lv(page, IDC_LV_DIAG_PV, L"PasswordVault / Web Credentials", &y,
                       5, L"Source", 80, L"Resource", 180, L"Username", 150, L"Count", 60, L"Status", 70);
    g_diagEdge = diag_lv(page, IDC_LV_DIAG_EDGE, L"Microsoft Edge (Chromium Login Data)", &y,
                         5, L"Profile", 90, L"Website", 150, L"Username", 90, L"Password", 120, L"Last Used", 90);
    lv_add_col(g_diagEdge, 5, L"Enc", 40);
    g_diagVault = diag_lv(page, IDC_LV_DIAG_VAULT, L"Direct Vault Decryption (Policy.vpol / .vcrd)", &y,
                          5, L"Source", 80, L"Vault GUID", 200, L"Detail", 150, L"Count", 60, L"Status", 90);
    g_diagVcmd = diag_lv(page, IDC_LV_DIAG_VCMD, L"vaultcmd.exe CLI Reference", &y,
                         5, L"Source", 80, L"Vault", 150, L"Target", 150, L"Username", 110, L"Status", 70);
    g_diagErr = diag_lv(page, IDC_LV_DIAG_ERR, L"Error Log", &y,
                        3, L"Timestamp", 90, L"Source", 130, L"Message", 300, L"", 0, L"", 0);
    g_diagContentHeight = y + 10;
}

static void layout_diag_scroll(void)
{
    RECT rc; GetClientRect(g_page[3], &rc);
    SCROLLINFO si = {0}; si.cbSize = sizeof(si); si.fMask = SIF_RANGE | SIF_PAGE;
    si.nMin = 0; si.nMax = g_diagContentHeight; si.nPage = rc.bottom;
    SetScrollInfo(g_page[3], SB_VERT, &si, TRUE);
}

static void select_tab(int idx)
{
    for (int i = 0; i < 4; i++) ShowWindow(g_page[i], i == idx ? SW_SHOW : SW_HIDE);
    if (idx == 0) g_lastFocused = g_lvWeb;
    else if (idx == 1) g_lastFocused = g_lvWinCore;
    else if (idx == 2) g_lastFocused = g_lvEdge;
    update_button_states();
}

static void position_pages(void)
{
    RECT rc; GetClientRect(g_tab, &rc);
    TabCtrl_AdjustRect(g_tab, FALSE, &rc);
    for (int i = 0; i < 4; i++)
        SetWindowPos(g_page[i], NULL, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
                     SWP_NOZORDER);
    layout_diag_scroll();
}

static HWND notify_listview(LPARAM lp)
{
    LPNMHDR h = (LPNMHDR)lp;
    return h->hwndFrom;
}

static LRESULT CALLBACK main_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_COMMAND:
        switch (LOWORD(wp)) {
            case IDC_BTN_ADD: do_add(); break;
            case IDC_BTN_EDIT: do_edit(); break;
            case IDC_BTN_REMOVE: do_remove(); break;
            case IDC_BTN_BACKUP: do_backup(); break;
            case IDC_BTN_RESTORE: do_restore(); break;
            case IDC_BTN_IMPORTCRD: do_import_crd(); break;
            case IDC_BTN_CLOSE: DestroyWindow(hwnd); break;
            case IDC_TXT_EDGEFILTER:
                if (HIWORD(wp) == EN_CHANGE) edge_refilter();
                break;
        }
        return 0;

    case WM_NOTIFY: {
        LPNMHDR h = (LPNMHDR)lp;
        if (h->hwndFrom == g_tab && h->code == TCN_SELCHANGE) { select_tab(current_tab()); return 0; }
        if (h->code == LVN_ITEMCHANGED) {
            HWND lv = h->hwndFrom;
            if (lv == g_lvWinCore || lv == g_lvWinCert || lv == g_lvWinGen) {
                if (lv_selected(lv) >= 0) clear_other_selections(lv);
            } else if (lv == g_lvWeb || lv == g_lvEdge || lv == g_diagEdge) {
                if (lv_selected(lv) >= 0) g_lastFocused = lv;
                update_button_states();
            } else {
                update_button_states();
            }
            return 0;
        }
        if (h->code == LVN_KEYDOWN) {
            LPNMLVKEYDOWN kd = (LPNMLVKEYDOWN)lp;
            if (kd->wVKey == 'C' && (GetKeyState(VK_CONTROL) & 0x8000))
                copy_row(h->hwndFrom, -1);
            return 0;
        }
        return 0;
    }

    case WM_CONTEXTMENU: {
        HWND lv = (HWND)wp;
        int x = GET_X_LPARAM(lp), y = GET_Y_LPARAM(lp);
        if (x == -1 && y == -1) { RECT r; GetWindowRect(lv, &r); x = r.left + 20; y = r.top + 20; }

        HWND lists[] = { g_lvWeb, g_lvWinCore, g_lvWinCert, g_lvWinGen, g_lvEdge,
                         g_diagWin, g_diagPV, g_diagEdge, g_diagVault, g_diagVcmd, g_diagErr };
        for (int i = 0; i < 11; i++) if (lists[i] == lv) { show_context_menu(lv, x, y); break; }
        return 0;
    }

    case WM_SIZE:
        position_pages();
        return 0;

    case WM_CLOSE: DestroyWindow(hwnd); return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void register_classes(void)
{
    WNDCLASSEXW wc = {0}; wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = main_proc; wc.hInstance = g_inst;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"CMMain";
    RegisterClassExW(&wc);

    WNDCLASSEXW page = {0}; page.cbSize = sizeof(page);
    page.lpfnWndProc = DefWindowProcW; page.hInstance = g_inst;
    page.hCursor = LoadCursorW(NULL, IDC_ARROW);
    page.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    page.lpszClassName = L"CMPage";
    RegisterClassExW(&page);

    WNDCLASSEXW diag = {0}; diag.cbSize = sizeof(diag);
    diag.lpfnWndProc = diag_proc; diag.hInstance = g_inst;
    diag.hCursor = LoadCursorW(NULL, IDC_ARROW);
    diag.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    diag.lpszClassName = L"CMDiag";
    RegisterClassExW(&diag);
}

int cm_run_app(HINSTANCE hInst)
{
    g_inst = hInst;
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    NONCLIENTMETRICSW ncm = { sizeof(ncm) };
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
    g_font = CreateFontIndirectW(&ncm.lfMessageFont);
    ncm.lfMessageFont.lfWeight = FW_BOLD;
    g_fontBold = CreateFontIndirectW(&ncm.lfMessageFont);

    cm_vec_init(&g_webColl); cm_vec_init(&g_winCoreColl); cm_vec_init(&g_winCertColl);
    cm_vec_init(&g_winGenColl); cm_vec_init(&g_edgeColl); cm_vec_init(&g_edgeFiltered);

    register_classes();

    RECT wr = {0,0, 700, 600};
    AdjustWindowRect(&wr, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE);
    g_main = CreateWindowExW(0, L"CMMain", L"Stored Usernames and Passwords",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, wr.right - wr.left, wr.bottom - wr.top,
        NULL, NULL, g_inst, NULL);

    mk_label(g_main,
        L"Windows can store log-on credentials for servers, websites and programs. When you "
        L"revisit one of those locations, Windows tries to log you on automatically.",
        12, 12, TAB_W, 48, false);

    g_tab = CreateWindowExW(0, WC_TABCONTROLW, L"", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                            TAB_X, TAB_Y, TAB_W, TAB_H, g_main, (HMENU)(INT_PTR)IDC_TAB, g_inst, NULL);
    set_font(g_tab);
    TCITEMW ti = {0}; ti.mask = TCIF_TEXT;
    const wchar_t *tabs[4] = { L"Web Credentials", L"Windows Credentials", L"Microsoft Edge", L"Diagnostics" };
    for (int i = 0; i < 4; i++) { ti.pszText = (LPWSTR)tabs[i]; TabCtrl_InsertItem(g_tab, i, &ti); }

    for (int i = 0; i < 4; i++) {
        if (i == 3) {
            g_page[3] = CreateWindowExW(WS_EX_CONTROLPARENT, L"CMDiag", L"",
                WS_CHILD | WS_CLIPCHILDREN | WS_VSCROLL, 0, 0, 10, 10, g_tab, NULL, g_inst, NULL);
        } else {
            g_page[i] = make_page();
        }
    }
    build_tab0(g_page[0]);
    build_tab1(g_page[1]);
    build_tab2(g_page[2]);
    build_tab3(g_page[3]);

    g_btnAdd = mk_button(g_main, L"&Add...", IDC_BTN_ADD, BTN_X, 70, BTN_W, 26);
    g_btnRemove = mk_button(g_main, L"&Remove", IDC_BTN_REMOVE, BTN_X, 102, BTN_W, 26);
    g_btnEdit = mk_button(g_main, L"&Edit...", IDC_BTN_EDIT, BTN_X, 134, BTN_W, 26);
    g_btnImport = mk_button(g_main, L"&Import .crd", IDC_BTN_IMPORTCRD, BTN_X, 200, BTN_W, 26);
    ShowWindow(g_btnImport, SW_HIDE);

    mk_label(g_main, L"Back up or restore credentials", 12, 512, TAB_W, 16, true);
    mk_label(g_main, L"If you back up stored log-on credentials, you can restore them or transfer them to another computer.",
             12, 532, TAB_W - 10, 32, false);
    g_btnBackup = mk_button(g_main, L"&Back up...", IDC_BTN_BACKUP, 22, 560, BTN_W, 26);
    g_btnRestore = mk_button(g_main, L"Re&store...", IDC_BTN_RESTORE, 440, 560, BTN_W, 26);
    g_btnClose = mk_button(g_main, L"Close", IDC_BTN_CLOSE, BTN_X, 560, BTN_W, 26);

    position_pages();
    select_tab(0);
    TabCtrl_SetCurSel(g_tab, 0);
    cm_refresh_ui();

    ShowWindow(g_main, SW_SHOW);
    UpdateWindow(g_main);

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        if (IsDialogMessageW(g_main, &m)) continue;
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return (int)m.wParam;
}
