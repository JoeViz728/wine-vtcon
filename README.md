# wine-vtcon

A small C hook for Wine's console host.

Wine stores an ESC character as a glyph, so a modern text UI that paints with ANSI sequences shows garbage. This library watches console writes, parses the sequences, and applies them through the console-cell APIs Wine already has. Keyboard input is left alone.

`vtcon.c` is the hook. `launch.c` is a small launcher. `build.sh` compiles both with MinGW as `vtcon.dll` and `vtcon-launch.exe`.

```bash
./build.sh
```

`MINGW_ROOT` overrides the toolchain location. The default is `$HOME/.local/opt/mingw-root`.
