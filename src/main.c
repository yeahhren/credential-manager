
#include "common.h"
#include "ui.h"

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrev, PWSTR cmdLine, int showCmd)
{
    (void)hPrev; (void)cmdLine; (void)showCmd;
    return cm_run_app(hInstance);
}
