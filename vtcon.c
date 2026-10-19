/* Translate ANSI written to a Wine console into real console-cell updates.
 *
 * Wine's conhost stores ESC as a glyph. Modern TUIs (FTXUI in
 * iw4x-launcher) paint with VT sequences and read keys with
 * ReadConsoleInput. This hook leaves input alone and applies output
 * with the cell APIs Wine already implements.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef BOOL (WINAPI *write_file_fn)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *write_console_a_fn)(HANDLE, const VOID *, DWORD, LPDWORD, LPVOID);
typedef BOOL (WINAPI *write_console_w_fn)(HANDLE, const VOID *, DWORD, LPDWORD, LPVOID);

typedef BOOL (WINAPI *write_file_ex_fn)(HANDLE, LPCVOID, DWORD, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE);
typedef HRESULT (WINAPI *create_pseudo_fn)(COORD, HANDLE, HANDLE, DWORD, void **);
typedef struct {
    union { LONG Status; void *Pointer; } u;
    ULONG_PTR Information;
} vt_io_status;
typedef LONG (NTAPI *nt_write_file_fn)(HANDLE, HANDLE, void *, void *, vt_io_status *, void *, ULONG, LARGE_INTEGER *, ULONG *);

static write_file_fn orig_WriteFile;
static write_console_a_fn orig_WriteConsoleA;
static write_console_w_fn orig_WriteConsoleW;
static write_file_ex_fn orig_WriteFileEx;
static create_pseudo_fn orig_CreatePseudoConsole;
static nt_write_file_fn orig_NtWriteFile;
static CRITICAL_SECTION vt_lock;
static __thread int vt_depth;
static __thread int nt_depth;

static HANDLE vt_log = INVALID_HANDLE_VALUE;

static void log_line(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    DWORD n, wrote;
    if (vt_log == INVALID_HANDLE_VALUE || !orig_WriteFile)
        return;
    va_start(ap, fmt);
    n = (DWORD)vsnprintf(buf, sizeof buf - 2, fmt, ap);
    va_end(ap);
    if (n >= sizeof buf - 2)
        n = (DWORD)(sizeof buf - 3);
    buf[n++] = '\n';
    /* kernelbase WriteFile reaches NtWriteFile. Hold the syscall hook off
     * so a trace of that hook cannot recurse through this log. */
    nt_depth++;
    orig_WriteFile(vt_log, buf, n, &wrote, NULL);
    nt_depth--;
}

/* --- instruction-length walk, enough for Wine's kernelbase prologues --- */

static int insn_len(const unsigned char *p, int *rip_rel) {
    int i = 0, rex = 0;
    unsigned char op, modrm, mod, rm, sib;
    *rip_rel = 0;
    while (p[i] == 0x66 || p[i] == 0x67 || p[i] == 0xF0 || p[i] == 0xF2 || p[i] == 0xF3 ||
           p[i] == 0x2E || p[i] == 0x36 || p[i] == 0x3E || p[i] == 0x26 || p[i] == 0x64 || p[i] == 0x65)
        i++;
    if (p[i] >= 0x40 && p[i] <= 0x4F) {
        rex = 1;
        i++;
    }
    op = p[i++];
    if (op >= 0x50 && op <= 0x5F)
        return i;
    if (op == 0x90)
        return i;
    if (op != 0x8D && op != 0x89 && op != 0x8B && op != 0x83 && op != 0xFF)
        return -1;
    modrm = p[i++];
    mod = modrm >> 6;
    rm = modrm & 7;
    if (mod != 3 && rm == 4) {
        sib = p[i++];
        if (mod == 0 && (sib & 7) == 5) {
            *rip_rel = 1;
            i += 4;
        }
    }
    if (mod == 0 && rm == 5) {
        *rip_rel = 1;
        i += 4;
    } else if (mod == 1) {
        i += 1;
    } else if (mod == 2) {
        i += 4;
    }
    if (op == 0x83)
        i += 1;
    (void)rex;
    return i;
}

static int steal_len(const unsigned char *p, int *out) {
    int n = 0;
    while (n < 14) {
        int rip = 0;
        int len = insn_len(p + n, &rip);
        if (len <= 0 || rip)
            return 0;
        n += len;
        if (n > 32)
            return 0;
    }
    *out = n;
    return 1;
}

static void *install_hook(void *target, void *detour) {
    unsigned char *code = target;
    int n = 0;
    DWORD old;
    unsigned char *tramp;
    if (!steal_len(code, &n))
        return NULL;
    tramp = VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp)
        return NULL;
    memcpy(tramp, code, n);
    tramp[n + 0] = 0xFF;
    tramp[n + 1] = 0x25;
    tramp[n + 2] = 0x00;
    tramp[n + 3] = 0x00;
    tramp[n + 4] = 0x00;
    tramp[n + 5] = 0x00;
    *(void **)(tramp + n + 6) = code + n;

    if (!VirtualProtect(code, n, PAGE_EXECUTE_READWRITE, &old))
        return NULL;
    code[0] = 0xFF;
    code[1] = 0x25;
    code[2] = 0x00;
    code[3] = 0x00;
    code[4] = 0x00;
    code[5] = 0x00;
    *(void **)(code + 6) = detour;
    for (int i = 14; i < n; i++)
        code[i] = 0x90;
    VirtualProtect(code, n, old, &old);
    FlushInstructionCache(GetCurrentProcess(), code, n);
    return tramp;
}

/* Wine's ntdll syscall stubs are 32 bytes and use an absolute address,
 * which the instruction walker refuses. Copy the whole stub. */
static void *install_syscall_hook(void *target, void *detour) {
    unsigned char *code = target;
    unsigned char *tramp;
    DWORD old;
    if (code[0] != 0x4C || code[1] != 0x8B || code[2] != 0xD1 || code[3] != 0xB8)
        return NULL;
    tramp = VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp)
        return NULL;
    memcpy(tramp, code, 32);
    if (!VirtualProtect(code, 16, PAGE_EXECUTE_READWRITE, &old))
        return NULL;
    code[0] = 0xFF;
    code[1] = 0x25;
    code[2] = 0x00;
    code[3] = 0x00;
    code[4] = 0x00;
    code[5] = 0x00;
    *(void **)(code + 6) = detour;
    code[14] = 0x90;
    code[15] = 0x90;
    VirtualProtect(code, 16, old, &old);
    FlushInstructionCache(GetCurrentProcess(), code, 16);
    return tramp;
}

/* --- screen --- */

static HANDLE vt_out = NULL;
static int vt_cols = 80, vt_rows = 25;
static int vt_origin_x, vt_origin_y;
static int cur_x, cur_y;
static int saved_x, saved_y;
static int fg = -1, bg = -1, bold, inverse;
static int autowrap = 1;
static int cursor_on = 1;
static unsigned utf_cp, utf_first;
static int utf_need;
static CHAR_INFO *alt_buf;
static int alt_on, alt_cols, alt_rows, alt_x, alt_y, alt_fg, alt_bg, alt_bold, alt_inverse;

static int color_index(int r, int g, int b) {
    int bright = (r + g + b) >= 384 || r >= 200 || g >= 200 || b >= 200;
    int idx = 0;
    if (r >= 80) idx |= 1;
    if (g >= 80) idx |= 2;
    if (b >= 80) idx |= 4;
    if (!idx && (r + g + b) > 48)
        idx = 7;
    if (bright)
        idx |= 8;
    return idx;
}

static int color256(int n) {
    static const int cube[] = {0, 95, 135, 175, 215, 255};
    if (n < 0) n = 0;
    if (n > 255) n = 255;
    if (n < 8) return n;
    if (n < 16) return n; /* already bright */
    if (n >= 232) {
        int g = 8 + (n - 232) * 10;
        return color_index(g, g, g);
    }
    n -= 16;
    return color_index(cube[n / 36], cube[(n / 6) % 6], cube[n % 6]);
}

static WORD attr_bits(int idx, int is_bg) {
    static const WORD map[16] = {
        0,
        FOREGROUND_RED,
        FOREGROUND_GREEN,
        FOREGROUND_RED | FOREGROUND_GREEN,
        FOREGROUND_BLUE,
        FOREGROUND_RED | FOREGROUND_BLUE,
        FOREGROUND_GREEN | FOREGROUND_BLUE,
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
        FOREGROUND_INTENSITY,
        FOREGROUND_RED | FOREGROUND_INTENSITY,
        FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    };
    WORD a = map[idx & 15];
    return is_bg ? (WORD)(a << 4) : a;
}

static WORD current_attr(void) {
    int f = fg < 0 ? 7 : fg;
    int b = bg < 0 ? 0 : bg;
    if (bold && f < 8)
        f += 8;
    WORD a = (WORD)(attr_bits(f, 0) | attr_bits(b, 1));
    if (inverse)
        a = (WORD)(((a & 0x0F) << 4) | ((a & 0xF0) >> 4));
    return a;
}

static void refresh_size(void) {
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (!GetConsoleScreenBufferInfo(vt_out, &info))
        return;
    vt_origin_x = info.srWindow.Left;
    vt_origin_y = info.srWindow.Top;
    vt_cols = info.srWindow.Right - info.srWindow.Left + 1;
    vt_rows = info.srWindow.Bottom - info.srWindow.Top + 1;
    if (vt_cols < 1) vt_cols = 1;
    if (vt_rows < 1) vt_rows = 1;
}

static COORD buf_coord(int x, int y) {
    COORD c;
    c.X = (SHORT)(vt_origin_x + x);
    c.Y = (SHORT)(vt_origin_y + y);
    return c;
}

static void clamp_cursor(void) {
    if (cur_x < 0) cur_x = 0;
    if (cur_y < 0) cur_y = 0;
    if (cur_x >= vt_cols) cur_x = vt_cols - 1;
    if (cur_y >= vt_rows) cur_y = vt_rows - 1;
}

static void place_cursor(void) {
    clamp_cursor();
    SetConsoleCursorPosition(vt_out, buf_coord(cur_x, cur_y));
}

static void set_cursor_visible(int on) {
    CONSOLE_CURSOR_INFO ci;
    cursor_on = on;
    if (!GetConsoleCursorInfo(vt_out, &ci))
        return;
    ci.bVisible = on ? TRUE : FALSE;
    SetConsoleCursorInfo(vt_out, &ci);
}

static void fill_rect(int x, int y, int n) {
    DWORD wrote;
    COORD c;
    WORD a;
    if (n <= 0)
        return;
    c = buf_coord(x, y);
    a = current_attr();
    FillConsoleOutputCharacterW(vt_out, L' ', (DWORD)n, c, &wrote);
    FillConsoleOutputAttribute(vt_out, a, (DWORD)n, c, &wrote);
}

static int cell_index(int x, int y) { return y * vt_cols + x; }

static void erase_display(int mode) {
    int from, count;
    refresh_size();
    if (mode == 2 || mode == 3) {
        fill_rect(0, 0, vt_cols * vt_rows);
        return;
    }
    if (mode == 1) {
        fill_rect(0, 0, cell_index(cur_x, cur_y) + 1);
        return;
    }
    from = cell_index(cur_x, cur_y);
    count = vt_cols * vt_rows - from;
    fill_rect(cur_x, cur_y, count);
}

static void erase_line(int mode) {
    refresh_size();
    if (mode == 2) {
        fill_rect(0, cur_y, vt_cols);
        return;
    }
    if (mode == 1) {
        fill_rect(0, cur_y, cur_x + 1);
        return;
    }
    fill_rect(cur_x, cur_y, vt_cols - cur_x);
}

static void scroll_up(int n) {
    SMALL_RECT rect;
    COORD dest;
    CHAR_INFO fill;
    if (n <= 0)
        return;
    refresh_size();
    rect.Left = (SHORT)vt_origin_x;
    rect.Top = (SHORT)(vt_origin_y + n);
    rect.Right = (SHORT)(vt_origin_x + vt_cols - 1);
    rect.Bottom = (SHORT)(vt_origin_y + vt_rows - 1);
    dest = buf_coord(0, 0);
    fill.Char.UnicodeChar = L' ';
    fill.Attributes = current_attr();
    if (rect.Top <= rect.Bottom)
        ScrollConsoleScreenBufferW(vt_out, &rect, NULL, dest, &fill);
    if (n < vt_rows)
        fill_rect(0, vt_rows - n, n * vt_cols);
    else
        fill_rect(0, 0, vt_cols * vt_rows);
}

static void newline(void) {
    refresh_size();
    cur_x = 0;
    if (cur_y + 1 >= vt_rows)
        scroll_up(1);
    else
        cur_y++;
}

static void put_char(wchar_t ch) {
    DWORD wrote;
    WORD a;
    COORD c;
    if (cur_x >= vt_cols) {
        if (!autowrap)
            cur_x = vt_cols - 1;
        else {
            cur_x = 0;
            if (cur_y + 1 >= vt_rows)
                scroll_up(1);
            else
                cur_y++;
        }
    }
    c = buf_coord(cur_x, cur_y);
    a = current_attr();
    WriteConsoleOutputCharacterW(vt_out, &ch, 1, c, &wrote);
    WriteConsoleOutputAttribute(vt_out, &a, 1, c, &wrote);
    cur_x++;
}

static void reset_sgr(void) {
    fg = -1;
    bg = -1;
    bold = 0;
    inverse = 0;
}

static int sgr_color(int *params, int n, int i, int *idx) {
    if (i >= n)
        return i;
    if (params[i] == 5 && i + 1 < n) {
        *idx = color256(params[i + 1]);
        return i + 2;
    }
    if (params[i] == 2 && i + 3 < n) {
        *idx = color_index(params[i + 1], params[i + 2], params[i + 3]);
        return i + 4;
    }
    return i + 1;
}

static void apply_sgr(int *params, int n) {
    int i;
    if (n == 0) {
        reset_sgr();
        return;
    }
    for (i = 0; i < n; i++) {
        int p = params[i];
        if (p == 0) reset_sgr();
        else if (p == 1) bold = 1;
        else if (p == 22) bold = 0;
        else if (p == 7) inverse = 1;
        else if (p == 27) inverse = 0;
        else if (p >= 30 && p <= 37) fg = p - 30;
        else if (p >= 90 && p <= 97) fg = p - 90 + 8;
        else if (p == 39) fg = -1;
        else if (p >= 40 && p <= 47) bg = p - 40;
        else if (p >= 100 && p <= 107) bg = p - 100 + 8;
        else if (p == 49) bg = -1;
        else if (p == 38 || p == 48) {
            int idx = 0;
            int next = sgr_color(params, n, i + 1, &idx);
            if (p == 38) fg = idx;
            else bg = idx;
            i = next - 1;
        }
    }
}

static int param_or(int *params, int n, int i, int def) {
    if (i >= n || params[i] == 0)
        return def;
    return params[i];
}

static void save_alt(void) {
    COORD size, origin;
    SMALL_RECT rect;
    refresh_size();
    free(alt_buf);
    alt_buf = calloc((size_t)vt_cols * (size_t)vt_rows, sizeof(CHAR_INFO));
    if (!alt_buf)
        return;
    size.X = (SHORT)vt_cols;
    size.Y = (SHORT)vt_rows;
    origin.X = 0;
    origin.Y = 0;
    rect.Left = (SHORT)vt_origin_x;
    rect.Top = (SHORT)vt_origin_y;
    rect.Right = (SHORT)(vt_origin_x + vt_cols - 1);
    rect.Bottom = (SHORT)(vt_origin_y + vt_rows - 1);
    ReadConsoleOutputW(vt_out, alt_buf, size, origin, &rect);
    alt_cols = vt_cols;
    alt_rows = vt_rows;
    alt_x = cur_x;
    alt_y = cur_y;
    alt_fg = fg;
    alt_bg = bg;
    alt_bold = bold;
    alt_inverse = inverse;
}

static void restore_alt(void) {
    COORD size, origin;
    SMALL_RECT rect;
    if (!alt_buf)
        return;
    refresh_size();
    size.X = (SHORT)alt_cols;
    size.Y = (SHORT)alt_rows;
    origin.X = 0;
    origin.Y = 0;
    rect.Left = (SHORT)vt_origin_x;
    rect.Top = (SHORT)vt_origin_y;
    rect.Right = (SHORT)(vt_origin_x + alt_cols - 1);
    rect.Bottom = (SHORT)(vt_origin_y + alt_rows - 1);
    WriteConsoleOutputW(vt_out, alt_buf, size, origin, &rect);
    cur_x = alt_x;
    cur_y = alt_y;
    fg = alt_fg;
    bg = alt_bg;
    bold = alt_bold;
    inverse = alt_inverse;
    free(alt_buf);
    alt_buf = NULL;
}

static void set_alt(int on) {
    if (on && !alt_on) {
        save_alt();
        alt_on = 1;
        erase_display(2);
        cur_x = cur_y = 0;
    } else if (!on && alt_on) {
        alt_on = 0;
        restore_alt();
    }
}

static void csi_mode(int priv, int *params, int n, int set) {
    int i;
    if (!n) n = 1, params[0] = 0;
    for (i = 0; i < n; i++) {
        int p = params[i];
        if (priv && p == 25)
            set_cursor_visible(set);
        else if (priv && p == 7)
            autowrap = set;
        else if (priv && (p == 1049 || p == 1047 || p == 47))
            set_alt(set);
        /* mouse, focus, bracketed paste, sync output: nothing to print */
    }
}

static void dispatch_csi(int priv, int *params, int n, int final) {
    int a, b;
    refresh_size();
    switch (final) {
    case 'A':
        cur_y -= param_or(params, n, 0, 1);
        break;
    case 'B':
        cur_y += param_or(params, n, 0, 1);
        break;
    case 'C':
        cur_x += param_or(params, n, 0, 1);
        break;
    case 'D':
        cur_x -= param_or(params, n, 0, 1);
        break;
    case 'E':
        cur_y += param_or(params, n, 0, 1);
        cur_x = 0;
        break;
    case 'F':
        cur_y -= param_or(params, n, 0, 1);
        cur_x = 0;
        break;
    case 'G':
        cur_x = param_or(params, n, 0, 1) - 1;
        break;
    case 'H':
    case 'f':
        a = param_or(params, n, 0, 1);
        b = param_or(params, n, 1, 1);
        cur_y = a - 1;
        cur_x = b - 1;
        break;
    case 'J':
        erase_display(n ? params[0] : 0);
        break;
    case 'K':
        erase_line(n ? params[0] : 0);
        break;
    case 'X':
        fill_rect(cur_x, cur_y, param_or(params, n, 0, 1));
        break;
    case 'm':
        apply_sgr(params, n);
        break;
    case 's':
        saved_x = cur_x;
        saved_y = cur_y;
        break;
    case 'u':
        cur_x = saved_x;
        cur_y = saved_y;
        break;
    case 'h':
        csi_mode(priv, params, n, 1);
        break;
    case 'l':
        csi_mode(priv, params, n, 0);
        break;
    case 'S':
        scroll_up(param_or(params, n, 0, 1));
        break;
    default:
        break;
    }
    clamp_cursor();
}

static void dispatch_esc(unsigned char b) {
    if (b == '7') {
        saved_x = cur_x;
        saved_y = cur_y;
    } else if (b == '8') {
        cur_x = saved_x;
        cur_y = saved_y;
    } else if (b == 'c') {
        reset_sgr();
        cur_x = cur_y = 0;
        set_alt(0);
        erase_display(2);
        set_cursor_visible(1);
    } else if (b == 'D') { /* IND */
        int x = cur_x;
        newline();
        cur_x = x;
    } else if (b == 'E') {
        newline();
    } else if (b == 'M') { /* RI */
        if (cur_y == 0) {
            SMALL_RECT rect;
            COORD dest;
            CHAR_INFO fill;
            refresh_size();
            rect.Left = (SHORT)vt_origin_x;
            rect.Top = (SHORT)vt_origin_y;
            rect.Right = (SHORT)(vt_origin_x + vt_cols - 1);
            rect.Bottom = (SHORT)(vt_origin_y + vt_rows - 2);
            dest = buf_coord(0, 1);
            fill.Char.UnicodeChar = L' ';
            fill.Attributes = current_attr();
            ScrollConsoleScreenBufferW(vt_out, &rect, NULL, dest, &fill);
            fill_rect(0, 0, vt_cols);
        } else {
            cur_y--;
        }
    }
}

enum { ST_NORMAL, ST_ESC, ST_CSI, ST_CSI_NUM, ST_OSC, ST_OSC_ESC, ST_CHARSET, ST_STR, ST_UTF };

static int st = ST_NORMAL;
static int csi_priv, csi_n, csi_cur, csi_any;
static int csi_params[16];

static void csi_reset(void) {
    csi_priv = 0;
    csi_n = 0;
    csi_cur = 0;
    csi_any = 0;
    memset(csi_params, 0, sizeof csi_params);
}

static void feed(unsigned char b);

static void feed_unicode(unsigned code) {
    if (code == 0)
        return;
    if (code > 0xFFFF)
        code = '?';
    put_char((wchar_t)code);
}

static void feed(unsigned char b) {
    switch (st) {
    case ST_UTF:
        if ((b & 0xC0) != 0x80) {
            /* Not a continuation. The lead was a real Latin-1 character. */
            unsigned first = utf_first;
            st = ST_NORMAL;
            utf_need = 0;
            put_char((wchar_t)first);
            feed(b);
            return;
        }
        utf_cp = (utf_cp << 6) | (b & 0x3F);
        if (--utf_need == 0) {
            st = ST_NORMAL;
            feed_unicode(utf_cp);
        }
        return;
    case ST_ESC:
        if (b == '[') {
            st = ST_CSI;
            csi_reset();
        } else if (b == ']') {
            st = ST_OSC;
        } else if (b == 'P' || b == 'X' || b == '^' || b == '_') {
            st = ST_STR;
        } else if (b == '(' || b == ')' || b == '*' || b == '+' || b == '-') {
            st = ST_CHARSET;
        } else {
            dispatch_esc(b);
            st = ST_NORMAL;
        }
        return;
    case ST_CHARSET:
        st = ST_NORMAL;
        return;
    case ST_OSC:
        if (b == 0x07)
            st = ST_NORMAL;
        else if (b == 0x1B)
            st = ST_OSC_ESC;
        else if (b == 0x18 || b == 0x1A)
            st = ST_NORMAL;
        return;
    case ST_OSC_ESC:
        st = ST_NORMAL;
        return;
    case ST_STR:
        if (b == 0x1B)
            st = ST_OSC_ESC;
        else if (b == 0x18 || b == 0x1A || b == 0x07)
            st = ST_NORMAL;
        return;
    case ST_CSI:
    case ST_CSI_NUM:
        if (b == 0x18 || b == 0x1A) {
            st = ST_NORMAL;
            return;
        }
        if (b < 0x20) {
            st = ST_NORMAL;
            feed(b);
            return;
        }
        if (st == ST_CSI && (b == '?' || b == '>' || b == '!')) {
            if (b == '?')
                csi_priv = 1;
            return;
        }
        if (b >= '0' && b <= '9') {
            st = ST_CSI_NUM;
            csi_any = 1;
            csi_cur = csi_cur * 10 + (b - '0');
            if (csi_cur > 9999)
                csi_cur = 9999;
            return;
        }
        if (b == ';') {
            if (csi_n < 16)
                csi_params[csi_n++] = csi_cur;
            csi_cur = 0;
            csi_any = 0;
            st = ST_CSI_NUM;
            return;
        }
        if (b >= 0x20 && b <= 0x2F)
            return;
        if (b >= 0x40 && b <= 0x7E) {
            if (csi_any || csi_n) {
                if (csi_n < 16)
                    csi_params[csi_n++] = csi_cur;
            }
            dispatch_csi(csi_priv, csi_params, csi_n, b);
            st = ST_NORMAL;
            return;
        }
        st = ST_NORMAL;
        return;
    default:
        break;
    }

    if (b == 0x1B) {
        st = ST_ESC;
        return;
    }
    if (b == '\r') {
        cur_x = 0;
        return;
    }
    if (b == '\n') {
        newline();
        return;
    }
    if (b == '\b') {
        if (cur_x > 0)
            cur_x--;
        return;
    }
    if (b == '\t') {
        int next = (cur_x + 8) & ~7;
        if (next >= vt_cols)
            next = vt_cols - 1;
        cur_x = next;
        return;
    }
    if (b == '\a')
        return;
    if (b < 0x20)
        return;
    if (b < 0x80) {
        put_char((wchar_t)b);
        return;
    }
    if ((b & 0xE0) == 0xC0 || (b & 0xF0) == 0xE0 || (b & 0xF8) == 0xF0) {
        utf_first = b;
        if ((b & 0xE0) == 0xC0) {
            utf_cp = b & 0x1F;
            utf_need = 1;
        } else if ((b & 0xF0) == 0xE0) {
            utf_cp = b & 0x0F;
            utf_need = 2;
        } else {
            utf_cp = b & 0x07;
            utf_need = 3;
        }
        st = ST_UTF;
    } else {
        put_char(L'?');
    }
}

static void bind_output(HANDLE h) {
    CONSOLE_SCREEN_BUFFER_INFO info;
    int fresh = (vt_out != h);
    vt_out = h;
    if (!GetConsoleScreenBufferInfo(h, &info))
        return;
    vt_origin_x = info.srWindow.Left;
    vt_origin_y = info.srWindow.Top;
    vt_cols = info.srWindow.Right - info.srWindow.Left + 1;
    vt_rows = info.srWindow.Bottom - info.srWindow.Top + 1;
    if (vt_cols < 1) vt_cols = 1;
    if (vt_rows < 1) vt_rows = 1;
    if (fresh) {
        cur_x = info.dwCursorPosition.X - vt_origin_x;
        cur_y = info.dwCursorPosition.Y - vt_origin_y;
        clamp_cursor();
        reset_sgr();
        st = ST_NORMAL;
        utf_need = 0;
    }
}

static int console_output(HANDLE h) {
    CONSOLE_SCREEN_BUFFER_INFO info;
    return GetConsoleScreenBufferInfo(h, &info);
}

static volatile LONG vt_trace_any = 24;
static volatile LONG vt_trace_esc = 48;

static int buffer_has_esc(const void *buf, DWORD n, int wide) {
    const unsigned char *p = buf;
    DWORD step = wide ? 2 : 1;
    DWORD i;
    if (!buf || n < step)
        return 0;
    for (i = 0; i + step <= n && i < 96 * step; i += step) {
        if (p[i] == 0x1B && (!wide || p[i + 1] == 0))
            return 1;
    }
    return 0;
}

static void trace_write(const char *api, HANDLE h, const void *buf, DWORD n, int wide, int pass) {
    char hex[96];
    const unsigned char *p = buf;
    DWORD mode = 0, i, hn = 0, take;
    mode = 0;
    int vt, csbi;
    if (vt_log == INVALID_HANDLE_VALUE)
        return;
    vt = buffer_has_esc(buf, n, wide);
    if (vt) {
        if (InterlockedDecrement(&vt_trace_esc) < 0)
            return;
    } else if (InterlockedDecrement(&vt_trace_any) < 0) {
        return;
    }
    csbi = console_output(h);
    GetConsoleMode(h, &mode);
    take = n < 16 ? n : 16;
    for (i = 0; i < take && hn + 3 < sizeof hex; i++)
        hn += (DWORD)snprintf(hex + hn, sizeof hex - hn, "%02x", p ? p[i] : 0);
    hex[hn] = 0;
    log_line("%s h=%p n=%lu pass=%d csbi=%d mode=%lx ftype=%lu vt=%d %s",
             api, h, n, pass, csbi, mode, GetFileType(h), vt, hex);
}

static BOOL WINAPI hook_WriteFile(HANDLE h, LPCVOID buf, DWORD n, LPDWORD wrote, LPOVERLAPPED ov) {
    int pass = vt_depth || ov || !console_output(h);
    trace_write("WriteFile", h, buf, n, 0, pass);
    if (pass)
        return orig_WriteFile(h, buf, n, wrote, ov);
    vt_depth++;
    EnterCriticalSection(&vt_lock);
    bind_output(h);
    {
        DWORD i;
        const unsigned char *p = buf;
        for (i = 0; i < n; i++)
            feed(p[i]);
        place_cursor();
    }
    LeaveCriticalSection(&vt_lock);
    vt_depth--;
    if (wrote)
        *wrote = n;
    return TRUE;
}

static BOOL WINAPI hook_WriteConsoleA(HANDLE h, const VOID *buf, DWORD n, LPDWORD wrote, LPVOID reserved) {
    int pass = vt_depth || !console_output(h);
    trace_write("WriteConsoleA", h, buf, n, 0, pass);
    if (pass)
        return orig_WriteConsoleA(h, buf, n, wrote, reserved);
    vt_depth++;
    EnterCriticalSection(&vt_lock);
    bind_output(h);
    {
        DWORD i;
        const unsigned char *p = buf;
        for (i = 0; i < n; i++)
            feed(p[i]);
        place_cursor();
    }
    LeaveCriticalSection(&vt_lock);
    vt_depth--;
    if (wrote)
        *wrote = n;
    return TRUE;
}

/* FTXUI on Windows feeds ReadConsoleInput key characters into the same
 * VT parser as a Unix tty. Arrow keys arrive with a virtual-key code and
 * no character, so the parser never sees ESC [ A/B/C/D. Rewrite those
 * keydowns into that sequence. Overflow goes back onto the real input
 * buffer so GetNumberOfConsoleInputEvents still wakes the next read. */
typedef BOOL (WINAPI *read_input_fn)(HANDLE, PINPUT_RECORD, DWORD, LPDWORD);
static read_input_fn orig_ReadConsoleInputW;

static const char *arrow_seq(WORD vk) {
    switch (vk) {
    case VK_UP: return "\033[A";
    case VK_DOWN: return "\033[B";
    case VK_RIGHT: return "\033[C";
    case VK_LEFT: return "\033[D";
    case VK_HOME: return "\033[H";
    case VK_END: return "\033[F";
    case VK_PRIOR: return "\033[5~";
    case VK_NEXT: return "\033[6~";
    case VK_DELETE: return "\033[3~";
    default: return NULL;
    }
}

static void push_char_event(INPUT_RECORD *dst, int *n, int cap, unsigned char ch) {
    INPUT_RECORD *ir;
    if (*n >= cap)
        return;
    ir = &dst[*n];
    memset(ir, 0, sizeof *ir);
    ir->EventType = KEY_EVENT;
    ir->Event.KeyEvent.bKeyDown = TRUE;
    ir->Event.KeyEvent.wRepeatCount = 1;
    ir->Event.KeyEvent.uChar.UnicodeChar = ch;
    (*n)++;
}

static BOOL WINAPI hook_ReadConsoleInputW(HANDLE h, PINPUT_RECORD rec, DWORD n, LPDWORD got) {
    INPUT_RECORD tmp[16];
    INPUT_RECORD built[48];
    DWORD ngot = 0, i;
    int bn = 0;
    BOOL ok;
    if (!orig_ReadConsoleInputW)
        return FALSE;
    if (!n)
        return orig_ReadConsoleInputW(h, rec, n, got);
    ok = orig_ReadConsoleInputW(h, tmp, 16, &ngot);
    if (!ok)
        return FALSE;
    for (i = 0; i < ngot; i++) {
        const KEY_EVENT_RECORD *k;
        const char *seq;
        DWORD mods;
        if (tmp[i].EventType != KEY_EVENT) {
            if (bn < 48)
                built[bn++] = tmp[i];
            continue;
        }
        k = &tmp[i].Event.KeyEvent;
        mods = k->dwControlKeyState;
        seq = arrow_seq(k->wVirtualKeyCode);
        log_line("key down=%u vk=%u ch=%u", k->bKeyDown, k->wVirtualKeyCode, k->uChar.UnicodeChar);
        if (!seq || (mods & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED | LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED))) {
            if (bn < 48)
                built[bn++] = tmp[i];
            continue;
        }
        if (!k->bKeyDown)
            continue;
        for (; *seq; seq++)
            push_char_event(built, &bn, 48, (unsigned char)*seq);
    }
    if ((DWORD)bn > n) {
        DWORD wrote = 0;
        WriteConsoleInputW(h, built + n, (DWORD)bn - n, &wrote);
        bn = (int)n;
    }
    for (i = 0; i < (DWORD)bn; i++)
        rec[i] = built[i];
    if (got)
        *got = (DWORD)bn;
    return TRUE;
}

static BOOL WINAPI hook_WriteConsoleW(HANDLE h, const VOID *buf, DWORD n, LPDWORD wrote, LPVOID reserved) {
    const WCHAR *p = buf;
    DWORD i;
    int pass = vt_depth || !console_output(h);
    trace_write("WriteConsoleW", h, buf, n, 1, pass);
    if (pass)
        return orig_WriteConsoleW(h, buf, n, wrote, reserved);
    vt_depth++;
    EnterCriticalSection(&vt_lock);
    bind_output(h);
    for (i = 0; i < n; i++) {
        WCHAR ch = p[i];
        /* CRT paths widen each UTF-8 byte to a wchar. Bytes below U+0100
         * go through the same decoder as WriteFile. Real BMP characters
         * above that are already decoded. */
        if (ch < 0x100 || st != ST_NORMAL)
            feed((unsigned char)(ch & 0xFF));
        else
            put_char(ch);
    }
    place_cursor();
    LeaveCriticalSection(&vt_lock);
    vt_depth--;
    if (wrote)
        *wrote = n;
    return TRUE;
}

static void *hook_export(HMODULE mod, const char *name, void *detour) {
    void *fn = GetProcAddress(mod, name);
    void *tramp;
    if (!fn) {
        log_line("missing %s", name);
        return NULL;
    }
    tramp = install_hook(fn, detour);
    if (!tramp)
        log_line("hook failed %s bytes %02x %02x %02x %02x", name,
                 ((unsigned char *)fn)[0], ((unsigned char *)fn)[1],
                 ((unsigned char *)fn)[2], ((unsigned char *)fn)[3]);
    else
        log_line("hooked %s", name);
    return tramp;
}

static BOOL WINAPI hook_WriteFileEx(HANDLE h, LPCVOID buf, DWORD n, LPOVERLAPPED ov,
                                    LPOVERLAPPED_COMPLETION_ROUTINE done) {
    trace_write("WriteFileEx", h, buf, n, 0, 1);
    return orig_WriteFileEx(h, buf, n, ov, done);
}

static HRESULT WINAPI hook_CreatePseudoConsole(COORD size, HANDLE input, HANDLE output,
                                               DWORD flags, void **pc) {
    HRESULT hr;
    log_line("CreatePseudoConsole %dx%d in=%p out=%p flags=%lx", size.X, size.Y, input, output, flags);
    hr = orig_CreatePseudoConsole(size, input, output, flags, pc);
    log_line("CreatePseudoConsole hr=%lx pc=%p", (unsigned long)hr, (pc && *pc) ? *pc : NULL);
    return hr;
}

static LONG NTAPI hook_NtWriteFile(HANDLE h, HANDLE event, void *apc, void *ctx,
                                   vt_io_status *io, void *buf, ULONG n,
                                   LARGE_INTEGER *off, ULONG *key) {
    /* Grok writes its TUI with NtWriteFile on the console handle, which
     * never enters WriteFile or WriteConsole. Wine then stores the VT
     * bytes as glyphs. Parse those writes the same way as WriteFile. */
    int pass;
    if (nt_depth)
        return orig_NtWriteFile(h, event, apc, ctx, io, buf, n, off, key);
    pass = vt_depth || apc || !buf || GetFileType(h) != FILE_TYPE_CHAR || !console_output(h);
    trace_write("NtWriteFile", h, buf, n, 0, pass);
    if (pass)
        return orig_NtWriteFile(h, event, apc, ctx, io, buf, n, off, key);
    vt_depth++;
    EnterCriticalSection(&vt_lock);
    bind_output(h);
    {
        ULONG i;
        const unsigned char *p = buf;
        for (i = 0; i < n; i++)
            feed(p[i]);
        place_cursor();
    }
    LeaveCriticalSection(&vt_lock);
    vt_depth--;
    if (io) {
        io->u.Status = 0;
        io->Information = n;
    }
    if (event)
        SetEvent(event);
    (void)off;
    (void)key;
    return 0;
}

static void install_hooks(void) {
    HMODULE kb = GetModuleHandleW(L"kernelbase.dll");
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!kb)
        kb = GetModuleHandleW(L"kernel32.dll");
    orig_WriteFile = hook_export(kb, "WriteFile", hook_WriteFile);
    orig_WriteConsoleA = hook_export(kb, "WriteConsoleA", hook_WriteConsoleA);
    orig_WriteConsoleW = hook_export(kb, "WriteConsoleW", hook_WriteConsoleW);
    orig_ReadConsoleInputW = hook_export(kb, "ReadConsoleInputW", hook_ReadConsoleInputW);
    orig_WriteFileEx = hook_export(kb, "WriteFileEx", hook_WriteFileEx);
    orig_CreatePseudoConsole = hook_export(kb, "CreatePseudoConsole", hook_CreatePseudoConsole);
    if (nt)
        orig_NtWriteFile = install_syscall_hook(GetProcAddress(nt, "NtWriteFile"), hook_NtWriteFile);
    log_line("extra writeex=%p pseudo=%p ntwrite=%p",
             (void *)orig_WriteFileEx, (void *)orig_CreatePseudoConsole, (void *)orig_NtWriteFile);
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void)inst;
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;
    DisableThreadLibraryCalls(inst);
    InitializeCriticalSection(&vt_lock);
    if (GetEnvironmentVariableA("VTCON_DEBUG", NULL, 0) > 0) {
        vt_log = CreateFileA("Z:\\tmp\\vtcon.log", FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    install_hooks();
    if (!orig_WriteFile || !orig_WriteConsoleA || !orig_WriteConsoleW)
        log_line("vtcon incomplete");
    else
        log_line("vtcon ready");
    return TRUE;
}
