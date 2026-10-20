# Credential Manager

A credential manager for Windows.

## Build

Requires a MinGW-w64 toolchain, CMake, and Ninja.

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The output is `build/CredentialManager.exe`.

`winsqlite3.dll` and `vaultcli.dll` are resolved at runtime via `LoadLibrary`.