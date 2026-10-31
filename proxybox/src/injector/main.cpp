// pbinject — launch a process suspended, inject the proxy hook DLL, resume.
// It also attaches to an already running (typically suspended) process so a
// 64-bit pbhook can hand a 32-bit child to the matching-arch helper.
//
//   pbinject.exe --dll <path\to\pbhook64.dll> -- <exe> [args...]
//   pbinject.exe --attach <pid> --dll <path\to\pbhook32.dll>
//
// The target inherits this process' environment, so PB_PROXY / PB_LOG must be
// set by the parent (proxybox.exe does it).

#include <windows.h>
#include <string>
#include <cstdio>

#include "../common/sandbox.h"

// CreateProcess quoting: backslashes are literal unless they precede a quote.
// Double them before an embedded quote (plus one to escape it) and before the
// closing quote so a trailing backslash argument survives.
static std::wstring Quote(const std::wstring& s)
{
    if (s.find_first_of(L" \t\"") == std::wstring::npos) return s;
    std::wstring out = L"\"";
    int backslashes = 0;
    for (wchar_t c : s) {
        if (c == L'\\') {
            ++backslashes;
            continue;
        }
        if (c == L'"') {
            out.append((size_t)backslashes * 2 + 1, L'\\');
            out += L'"';
            backslashes = 0;
        } else {
            out.append((size_t)backslashes, L'\\');
            backslashes = 0;
            out += c;
        }
    }
    out.append((size_t)backslashes * 2, L'\\');
    out += L'"';
    return out;
}

static bool InjectDll(HANDLE hp, const std::wstring& dll)
{
    SIZE_T bytes = (dll.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(hp, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return false;

    bool injected = false;
    if (WriteProcessMemory(hp, remote, dll.c_str(), bytes, nullptr)) {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        auto loadLib = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(k32, "LoadLibraryW"));
        if (loadLib) {
            HANDLE th = CreateRemoteThread(hp, nullptr, 0, loadLib, remote, 0, nullptr);
            if (th) {
                DWORD wr = WaitForSingleObject(th, 15000);
                DWORD mod = 0;
                GetExitCodeThread(th, &mod);
                injected = (wr == WAIT_OBJECT_0 && mod != 0);
                CloseHandle(th);
            }
        }
    }
    VirtualFreeEx(hp, remote, 0, MEM_RELEASE);
    return injected;
}

static bool WaitLocalEvent(const wchar_t* name, DWORD timeoutMs)
{
    DWORD start = GetTickCount();
    HANDLE ev = nullptr;
    for (;;) {
        ev = OpenEventW(SYNCHRONIZE, FALSE, name);
        if (ev) break;
        if (GetTickCount() - start >= timeoutMs) return false;
        Sleep(10);
    }
    DWORD elapsed = GetTickCount() - start;
    DWORD wr = WaitForSingleObject(ev, elapsed < timeoutMs ? timeoutMs - elapsed : 0);
    CloseHandle(ev);
    return wr == WAIT_OBJECT_0;
}

int wmain(int argc, wchar_t** argv)
{
    std::wstring dll, exe;
    DWORD attachPid = 0;
    int first = -1;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--dll" && i + 1 < argc) { dll = argv[++i]; }
        else if (a == L"--attach" && i + 1 < argc) { attachPid = (DWORD)wcstoul(argv[++i], nullptr, 10); }
        else if (a == L"--") { first = i + 1; break; }
    }

    if (!dll.empty() && attachPid != 0 && first < 0) {
        HANDLE hp = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                                FALSE, attachPid);
        if (!hp) {
            fwprintf(stderr, L"OpenProcess %lu failed: %lu\n",
                     (unsigned long)attachPid, GetLastError());
            return 4;
        }
        bool ok = InjectDll(hp, dll);
        CloseHandle(hp);
        if (!ok) fwprintf(stderr, L"attach injection failed (error %lu)\n", GetLastError());
        return ok ? 0 : 4;
    }

    if (dll.empty() || first < 0 || first >= argc) {
        fwprintf(stderr, L"usage: pbinject --dll <dll> -- <exe> [args...]\n"
                         L"       pbinject --attach <pid> --dll <dll>\n");
        return 2;
    }
    exe = argv[first];

    std::wstring cmd = Quote(exe);
    for (int i = first + 1; i < argc; ++i) {
        cmd += L' ';
        cmd += Quote(argv[i]);
    }

    // Seed shell folders while the target is still not started: no race with
    // Chromium's early PathService init, and no loader-lock work in DllMain.
    wchar_t hivePath[MAX_PATH * 4];
    if (GetEnvironmentVariableW(L"PB_HIVE", hivePath, MAX_PATH * 4) > 0)
        pbsandbox::SeedHiveFile(hivePath);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring mutableCmd = cmd;

    // DETACHED_PROCESS: CREATE_NO_WINDOW still makes conhost.exe on Win10; a
    // detached console target gets no console at all (and no conhost). GUI
    // targets ignore it. Never combine with CREATE_NEW_CONSOLE.
    if (!CreateProcessW(exe.c_str(), &mutableCmd[0], nullptr, nullptr, TRUE,
                        CREATE_SUSPENDED | DETACHED_PROCESS, nullptr, nullptr, &si, &pi)) {
        fwprintf(stderr, L"CreateProcess failed: %lu\n", GetLastError());
        return 3;
    }

    HANDLE hp = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                            PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                            FALSE, pi.dwProcessId);
    bool injected = hp && InjectDll(hp, dll);
    if (hp) CloseHandle(hp);

    if (!injected) {
        fwprintf(stderr, L"injection failed (error %lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 4);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 4;
    }

    // Wait for the sandbox to arm before resuming: registry redirect, shell
    // folder hooks, then the proxy hooks. Without it Chromium may query its
    // userData path before the hooks exist and all copies share one profile.
    wchar_t evName[64];
    swprintf(evName, 64, L"Local\\pbready_%lu", (unsigned long)pi.dwProcessId);
    HANDLE ready = nullptr;
    for (int i = 0; i < 200 && !ready; ++i) {
        ready = OpenEventW(SYNCHRONIZE, FALSE, evName);
        if (!ready) Sleep(10);
    }
    if (ready) {
        WaitForSingleObject(ready, 3000);
        CloseHandle(ready);
    }

    // Sandbox is ready but proxy hooks arm later (a slow SOCKS5 UDP associate
    // can take seconds). Gate on pbarm so the first TCP packet cannot go direct.
    swprintf(evName, 64, L"Local\\pbarm_%lu", (unsigned long)pi.dwProcessId);
    if (!WaitLocalEvent(evName, 5000))
        fwprintf(stderr, L"proxy arm timeout or event missing (pid %lu)\n",
                 (unsigned long)pi.dwProcessId);
    Sleep(50);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    return (int)code;
}
