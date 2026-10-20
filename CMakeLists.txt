cmake_minimum_required(VERSION 3.20)
project(CredentialManager C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_definitions(
        _WIN32_WINNT=0x0A00
        WINVER=0x0A00
        UNICODE
        _UNICODE
)

set(SOURCES
        src/main.c
        src/util.c
        src/crypto.c
        src/cred_api.c
        src/vault.c
        src/vault_probe.c
        src/edge.c
        src/domain.c
        src/cert.c
        src/analysis.c
        src/diag_cli.c
        src/backup.c
        src/ui.c
        src/dialogs.c
        src/app.rc
)

add_executable(CredentialManager WIN32 ${SOURCES})

target_include_directories(CredentialManager PRIVATE src)

target_link_libraries(CredentialManager PRIVATE
        user32
        gdi32
        comctl32
        comdlg32
        advapi32
        crypt32
        bcrypt
        ncrypt
        netapi32
        shell32
        ole32
        shlwapi
)

target_compile_options(CredentialManager PRIVATE -municode)
target_link_options(CredentialManager PRIVATE -municode)
