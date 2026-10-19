#!/bin/bash
# Build vtcon.dll and vtcon-launch.exe with the unpacked MinGW.
# The driver is relocatable from its own bin directory; do not wrap it.
set -euo pipefail
ROOT="${MINGW_ROOT:-$HOME/.local/opt/mingw-root}"
SRC="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HOME/bin/vtcon}"
GCC="$ROOT/usr/bin/x86_64-w64-mingw32-gcc-win32"
mkdir -p "$OUT"
"$GCC" -shared -O2 -Wall -Wextra -static-libgcc -o "$OUT/vtcon.dll" "$SRC/vtcon.c"
"$GCC" -O2 -Wall -Wextra -municode -mconsole -o "$OUT/vtcon-launch.exe" "$SRC/launch.c" -lntdll
echo "built $OUT/vtcon.dll and $OUT/vtcon-launch.exe"
