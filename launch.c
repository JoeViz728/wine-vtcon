/* Start a console program with vtcon.dll translating its ANSI output.
 *
 * The DLL is loaded before the target's entry point runs, so the first
 * paint already goes through the translator. Keys stay on the real console.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static void note(const char *fmt, ...) {
    char env[8];
    char buf[480];
    va_list ap;
    DWORD n, wrote;
    HANDLE h;
    if (!GetEnvironmentVariableA("VTCON_DEBUG", env, sizeof env))
        return;
    va_start(ap, fmt);
    n = (DWORD)vsnprintf(buf, sizeof buf - 2, fmt, ap);
    va_end(ap);
    if (n >= sizeof buf - 2)
        n = (DWORD)(sizeof buf - 3);
    buf[n++] = '\n';
    h = CreateFileA("Z:\\tmp\\vtcon-launch.log", FILE_APPEND_DATA,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return;
    WriteFile(h, buf, n, &wrote, NULL);
    CloseHandle(h);
}

static int poke(HANDLE proc, void *addr, const void *src, SIZE_T n) {
    DWORD old = 0;
    if (!VirtualProtectEx(proc, addr, n, PAGE_EXECUTE_READWRITE, &old))
        return 0;
    if (!WriteProcessMemory(proc, addr, src, n, NULL))
        return 0;
    VirtualProtectEx(proc, addr, n, old, &old);
    FlushInstructionCache(proc, addr, n);
    return 1;
}

static void choose_font(HANDLE h) {
    CONSOLE_FONT_INFOEX info;
    /* FreeMono is the monospace face on this system that covers braille.
     * DejaVu Sans Mono draws the UI frame and then leaves the logo as boxes. */
    static const WCHAR *faces[] = {
        L"FreeMono", L"DejaVu Sans Mono", L"Liberation Mono", L"Consolas", L"Courier New"
    };
    int i;
    memset(&info, 0, sizeof info);
    info.cbSize = sizeof info;
    info.dwFontSize.Y = 16;
    info.FontFamily = FF_DONTCARE;
    info.FontWeight = FW_NORMAL;
    for (i = 0; i < 5; i++) {
        wcsncpy(info.FaceName, faces[i], LF_FACESIZE - 1);
        if (SetCurrentConsoleFontEx(h, FALSE, &info))
            return;
    }
}

static void fit_console(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD largest = GetLargestConsoleWindowSize(h);
    choose_font(h);
    SHORT cols = 100, rows = 32;
    SMALL_RECT tiny = {0, 0, 1, 1};
    SMALL_RECT win;
    COORD buf;
    if (largest.X > 0 && cols > largest.X)
        cols = largest.X;
    if (largest.Y > 0 && rows > largest.Y)
        rows = largest.Y;
    if (cols < 40)
        cols = 80;
    if (rows < 16)
        rows = 28;
    SetConsoleWindowInfo(h, TRUE, &tiny);
    buf.X = cols;
    buf.Y = rows;
    SetConsoleScreenBufferSize(h, buf);
    win.Left = 0;
    win.Top = 0;
    win.Right = (SHORT)(cols - 1);
    win.Bottom = (SHORT)(rows - 1);
    SetConsoleWindowInfo(h, TRUE, &win);
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
}

static int read_mem(HANDLE proc, const void *addr, void *dst, SIZE_T n) {
    SIZE_T got = 0;
    return ReadProcessMemory(proc, addr, dst, n, &got) && got == n;
}

static void *peb_field(HANDLE proc, HANDLE *out_err) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG ret = 0;
    NTSTATUS st;
    typedef NTSTATUS (NTAPI *ntqip_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    ntqip_fn ntqip = (ntqip_fn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                             "NtQueryInformationProcess");
    unsigned char peb[0x20];
    (void)out_err;
    if (!ntqip)
        return NULL;
    memset(&pbi, 0, sizeof pbi);
    st = ntqip(proc, 0, &pbi, sizeof pbi, &ret);
    if (st < 0 || !pbi.PebBaseAddress)
        return NULL;
    if (!read_mem(proc, pbi.PebBaseAddress, peb, sizeof peb))
        return NULL;
    return *(void **)(peb + 0x10);
}

static void *entry_point(HANDLE proc, void *image) {
    unsigned char dos[0x40];
    unsigned char pe[0x120];
    LONG lfanew;
    DWORD entry;
    if (!read_mem(proc, image, dos, sizeof dos))
        return NULL;
    lfanew = *(LONG *)(dos + 0x3C);
    if (!read_mem(proc, (char *)image + lfanew, pe, sizeof pe))
        return NULL;
    entry = *(DWORD *)(pe + 24 + 16);
    return (char *)image + entry;
}

static void *remote_export(HANDLE proc, void *base, const char *name) {
    unsigned char dos[0x40];
    unsigned char pe[0x120];
    LONG lfanew;
    DWORD exp_rva, exp_size;
    unsigned char exp[40];
    DWORD nnames, funcs, names, ords;
    DWORD i;
    if (!read_mem(proc, base, dos, sizeof dos))
        return NULL;
    lfanew = *(LONG *)(dos + 0x3C);
    if (!read_mem(proc, (char *)base + lfanew, pe, sizeof pe))
        return NULL;
    /* PE32+ export directory is data directory 0, optional header + 112. */
    exp_rva = *(DWORD *)(pe + 24 + 112);
    exp_size = *(DWORD *)(pe + 24 + 116);
    (void)exp_size;
    if (!exp_rva || !read_mem(proc, (char *)base + exp_rva, exp, sizeof exp))
        return NULL;
    nnames = *(DWORD *)(exp + 24);
    funcs = *(DWORD *)(exp + 28);
    names = *(DWORD *)(exp + 32);
    ords = *(DWORD *)(exp + 36);
    for (i = 0; i < nnames && i < 4096; i++) {
        DWORD nrva = 0, rva = 0;
        WORD ord = 0;
        char nm[64];
        SIZE_T k;
        if (!read_mem(proc, (char *)base + names + i * 4, &nrva, 4))
            return NULL;
        memset(nm, 0, sizeof nm);
        if (!read_mem(proc, (char *)base + nrva, nm, sizeof nm - 1))
            continue;
        for (k = 0; nm[k] && name[k]; k++) {
            if (nm[k] != name[k])
                break;
        }
        if (nm[k] || name[k])
            continue;
        if (!read_mem(proc, (char *)base + ords + i * 2, &ord, 2))
            return NULL;
        if (!read_mem(proc, (char *)base + funcs + ord * 4, &rva, 4))
            return NULL;
        return (char *)base + rva;
    }
    return NULL;
}

static void *find_module(HANDLE proc, const WCHAR *want) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG ret = 0;
    typedef NTSTATUS (NTAPI *ntqip_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    ntqip_fn ntqip = (ntqip_fn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                             "NtQueryInformationProcess");
    unsigned char peb[0x20];
    void *ldr;
    unsigned char ldrdata[0x20];
    void *head, *cur;
    int guard = 0;
    if (!ntqip)
        return NULL;
    memset(&pbi, 0, sizeof pbi);
    if (ntqip(proc, 0, &pbi, sizeof pbi, &ret) < 0 || !pbi.PebBaseAddress)
        return NULL;
    if (!read_mem(proc, pbi.PebBaseAddress, peb, sizeof peb))
        return NULL;
    ldr = *(void **)(peb + 0x18);
    if (!ldr || !read_mem(proc, ldr, ldrdata, sizeof ldrdata))
        return NULL;
    head = (char *)ldr + 0x10;
    cur = *(void **)(ldrdata + 0x10);
    while (cur && cur != head && guard++ < 256) {
        unsigned char ent[0x70];
        USHORT len;
        void *buf;
        WCHAR name[40];
        void *next;
        if (!read_mem(proc, cur, ent, sizeof ent))
            return NULL;
        next = *(void **)ent;
        len = *(USHORT *)(ent + 0x58);
        buf = *(void **)(ent + 0x60);
        memset(name, 0, sizeof name);
        if (buf && len && len < sizeof name)
            read_mem(proc, buf, name, len);
        if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, name, -1, want, -1) == CSTR_EQUAL)
            return *(void **)(ent + 0x30);
        cur = next;
    }
    return NULL;
}

static int wait_at_entry(HANDLE thread, void *entry, HANDLE proc, void **k32) {
    int i;
    __attribute__((aligned(16))) CONTEXT ctx;
    for (i = 0; i < 1000; i++) {
        if (SuspendThread(thread) == (DWORD)-1)
            return 0;
        memset(&ctx, 0, sizeof ctx);
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(thread, &ctx)) {
            ResumeThread(thread);
            return 0;
        }
        if ((void *)(uintptr_t)ctx.Rip == entry) {
            void *mod = find_module(proc, L"kernel32.dll");
            if (mod) {
                *k32 = mod;
                return 1; /* left suspended */
            }
        }
        ResumeThread(thread);
        Sleep(20);
    }
    return 0;
}

static int inject(HANDLE proc, void *loadlib, const WCHAR *dll) {
    SIZE_T bytes = (wcslen(dll) + 1) * sizeof(WCHAR);
    void *remote;
    HANDLE th;
    DWORD code = 0;
    remote = VirtualAllocEx(proc, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote)
        return 0;
    if (!WriteProcessMemory(proc, remote, dll, bytes, NULL))
        return 0;
    th = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)loadlib, remote, 0, NULL);
    if (!th)
        return 0;
    WaitForSingleObject(th, 15000);
    GetExitCodeThread(th, &code);
    CloseHandle(th);
    return code != 0;
}

/* CommandLineToArgvW quoting. The buffer CreateProcess receives has to be writable. */
static int append_quoted(WCHAR *dst, int used, int cap, const WCHAR *arg) {
    const WCHAR *p;
    int quotes = 0;

    if (!arg || !*arg)
        quotes = 1;
    else {
        for (p = arg; *p; p++) {
            if (*p == L' ' || *p == L'\t' || *p == L'"')
                quotes = 1;
        }
    }
    if (!arg)
        arg = L"";
    if (used) {
        if (used >= cap - 1)
            return -1;
        dst[used++] = L' ';
    }
    if (!quotes) {
        for (p = arg; *p; p++) {
            if (used >= cap - 1)
                return -1;
            dst[used++] = *p;
        }
        dst[used] = 0;
        return used;
    }
    if (used >= cap - 1)
        return -1;
    dst[used++] = L'"';
    {
        int bs = 0;
        int k;
        for (p = arg; *p; p++) {
            if (*p == L'\\') {
                bs++;
                continue;
            }
            if (*p == L'"') {
                for (k = 0; k < bs * 2 + 1; k++) {
                    if (used >= cap - 1)
                        return -1;
                    dst[used++] = L'\\';
                }
                bs = 0;
                if (used >= cap - 1)
                    return -1;
                dst[used++] = L'"';
                continue;
            }
            for (k = 0; k < bs; k++) {
                if (used >= cap - 1)
                    return -1;
                dst[used++] = L'\\';
            }
            bs = 0;
            if (used >= cap - 1)
                return -1;
            dst[used++] = *p;
        }
        for (k = 0; k < bs * 2; k++) {
            if (used >= cap - 1)
                return -1;
            dst[used++] = L'\\';
        }
    }
    if (used >= cap - 1)
        return -1;
    dst[used++] = L'"';
    dst[used] = 0;
    return used;
}

static void set_title(const WCHAR *exe) {
    WCHAR title[256];
    WCHAR base[MAX_PATH];
    const WCHAR *slash;
    DWORD n = GetEnvironmentVariableW(L"VTCON_TITLE", title, 256);

    if (n > 0 && n < 256) {
        SetConsoleTitleW(title);
        return;
    }
    slash = wcsrchr(exe, L'\\');
    if (!slash)
        slash = wcsrchr(exe, L'/');
    slash = slash ? slash + 1 : exe;
    wcsncpy(base, slash, MAX_PATH - 1);
    base[MAX_PATH - 1] = 0;
    /* The i3 rule floats this exact title. Other consoles keep their own name. */
    if (lstrcmpiW(base, L"iw4x-launcher.exe") == 0)
        SetConsoleTitleW(L"IW4x Launcher");
    else
        SetConsoleTitleW(base);
}

static void selftest(void) {
    WCHAR path[MAX_PATH];
    WCHAR *slash;
    const char *frame =
        "\033[?25l\033[2J\033[1;1H"
        "\033[1mWhich IW4x client would you like to play?\033[0m\r\n"
        "\033[7m > IW4x\033[0m\r\n"
        "   IW4x (mm)\r\n"
        "\r\n"
        "IW4x is built around community-hosted dedicated servers.\r\n"
        "\033[38;2;255;180;40mamber line\033[0m\r\n";
    DWORD wrote;
    GetModuleFileNameW(NULL, path, MAX_PATH);
    slash = wcsrchr(path, L'\\');
    if (!slash)
        return;
    wcscpy(slash + 1, L"vtcon.dll");
    SetConsoleTitleW(L"IW4x Launcher");
    fit_console();
    if (!LoadLibraryW(path)) {
        fprintf(stderr, "vtcon selftest: LoadLibrary failed %lu\n", GetLastError());
        return;
    }
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), frame, (DWORD)strlen(frame), &wrote, NULL);
    Sleep(20000);
}

/* Number of processes on this console besides us. -1 if the list cannot
 * be read; the caller must not hang in that case. */
static int console_other_count(void) {
    DWORD stack_ids[32];
    DWORD *ids = stack_ids;
    DWORD cap = 32;
    DWORD n, i, mine;
    int others = 0;
    char list[240];
    int used = 0;

    mine = GetCurrentProcessId();
    n = GetConsoleProcessList(ids, cap);
    if (n == 0)
        return -1;
    if (n > cap) {
        ids = HeapAlloc(GetProcessHeap(), 0, n * sizeof(*ids));
        if (!ids)
            return -1;
        cap = n;
        n = GetConsoleProcessList(ids, cap);
        if (n == 0 || n > cap) {
            HeapFree(GetProcessHeap(), 0, ids);
            return -1;
        }
    }
    list[0] = 0;
    for (i = 0; i < n; i++) {
        if (ids[i] != mine)
            others++;
        if (used < (int)sizeof list - 16)
            used += snprintf(list + used, sizeof list - (size_t)used, "%s%lu",
                             used ? "," : "", ids[i]);
    }
    note("console pids %s mine %lu others %d", list, mine, others);
    if (ids != stack_ids)
        HeapFree(GetProcessHeap(), 0, ids);
    return others;
}

/* Pids spawned by root, including ones whose parent has already exited.
 * The IW4x launcher CreateProcess's iw4x.exe and returns immediately.
 * That game is not on the console list yet when the launcher exits, so a
 * console-only wait lets wineconsole tear the session down and the game
 * goes with it. */
static DWORD seen_pid[4096];
static int seen_pid_n;

static int pid_seen(DWORD pid) {
    int i;
    for (i = 0; i < seen_pid_n; i++)
        if (seen_pid[i] == pid)
            return 1;
    return 0;
}

static void remember_pid(DWORD pid) {
    if (!pid || pid_seen(pid) || seen_pid_n >= 4096)
        return;
    seen_pid[seen_pid_n++] = pid;
}

static int descendant_alive(DWORD root) {
    HANDLE snap;
    PROCESSENTRY32W pe;
    int guard, alive, added;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    alive = 0;
    /* Repeat so a grandchild is found in this snapshot even when its
     * parent is listed after it. */
    for (guard = 0; guard < 8; guard++) {
        added = 0;
        alive = 0;
        pe.dwSize = sizeof pe;
        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID != root &&
                    pid_seen(pe.th32ParentProcessID)) {
                    if (!pid_seen(pe.th32ProcessID)) {
                        remember_pid(pe.th32ProcessID);
                        added = 1;
                    }
                }
                if (pe.th32ProcessID != root && pid_seen(pe.th32ProcessID))
                    alive++;
            } while (Process32NextW(snap, &pe));
        }
        if (!added)
            break;
    }
    CloseHandle(snap);
    note("descendants of %lu alive %d tracked %d", root, alive, seen_pid_n);
    return alive > 0;
}

/* Stay until the direct child's descendants are gone and no other
 * process is attached to this console. Two empty polls cover a child
 * that has been created but is not visible to one snapshot yet. */
static void wait_for_console_clients(DWORD root) {
    int quiet = 0;
    int others, kids;

    seen_pid_n = 0;
    remember_pid(root);
    while (quiet < 2) {
        others = console_other_count();
        if (others < 0) {
            note("GetConsoleProcessList failed %lu", GetLastError());
            others = 0;
        }
        kids = descendant_alive(root);
        if (others > 0 || kids)
            quiet = 0;
        else
            quiet++;
        if (quiet >= 2)
            break;
        Sleep(100);
    }
}

static int launch_target(int argc, WCHAR **argv) {
    const WCHAR *exe = argv[1];
    const WCHAR *app;
    static WCHAR cmdline[32768];
    int used = 0;
    int i;
    WCHAR dll[MAX_PATH];
    WCHAR *slash;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    void *image, *entry, *k32, *loadlib;
    unsigned char saved[2], spin[2] = {0xEB, 0xFE};
    __attribute__((aligned(16))) CONTEXT ctx;
    DWORD code = 1;

    GetModuleFileNameW(NULL, dll, MAX_PATH);
    slash = wcsrchr(dll, L'\\');
    if (!slash) {
        fprintf(stderr, "vtcon: cannot find vtcon.dll next to the launcher\n");
        return 1;
    }
    wcscpy(slash + 1, L"vtcon.dll");
    for (i = 1; i < argc; i++) {
        used = append_quoted(cmdline, used, 32768, argv[i]);
        if (used < 0) {
            fprintf(stderr, "vtcon: command line is too long\n");
            return 1;
        }
    }
    /* A bare name (cmd.exe) is searched. A path is used as given. Cwd is inherited. */
    app = exe;
    if (!wcschr(exe, L'\\') && !wcschr(exe, L'/') && !(exe[0] && exe[1] == L':'))
        app = NULL;
    set_title(exe);
    fit_console();
    note("launch");

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    if (!CreateProcessW(app, cmdline, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "vtcon: CreateProcess failed %lu\n", GetLastError());
        return 1;
    }
    image = peb_field(pi.hProcess, NULL);
    entry = image ? entry_point(pi.hProcess, image) : NULL;
    if (!entry || !read_mem(pi.hProcess, entry, saved, 2) ||
        !poke(pi.hProcess, entry, spin, 2)) {
        note("hold failed image %p entry %p err %lu", image, entry, GetLastError());
        fprintf(stderr, "vtcon: could not hold the new process at its entry\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    note("held at %p", entry);
    ResumeThread(pi.hThread);
    if (!wait_at_entry(pi.hThread, entry, pi.hProcess, &k32)) {
        note("entry not reached");
        fprintf(stderr, "vtcon: target did not reach its entry point\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    note("kernel32 %p", k32);
    loadlib = remote_export(pi.hProcess, k32, "LoadLibraryW");
    note("LoadLibraryW %p", loadlib);
    if (!loadlib || !inject(pi.hProcess, loadlib, dll)) {
        note("inject failed err %lu", GetLastError());
        fprintf(stderr, "vtcon: could not load the translator into the target\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    note("injected");
    if (!poke(pi.hProcess, entry, saved, 2)) {
        note("restore failed");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    memset(&ctx, 0, sizeof ctx);
    ctx.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rip = (DWORD64)(uintptr_t)entry;
    ctx.ContextFlags = CONTEXT_CONTROL;
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    wait_for_console_clients(pi.dwProcessId);
    return (int)code;
}

int wmain(int argc, WCHAR **argv) {
    if (argc >= 2 && wcscmp(argv[1], L"--selftest") == 0) {
        selftest();
        return 0;
    }
    if (argc < 2) {
        fprintf(stderr, "usage: vtcon-launch.exe <program> [arguments...]\n");
        return 2;
    }
    return launch_target(argc, argv);
}
