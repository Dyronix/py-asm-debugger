# ASM Debugger

A simple x86 (Intel syntax) assembly editor and step debugger built with PyQt6.

## Features

- Edit, open, and save `.asm` files.
- Parse and execute instructions step-by-step or automatically at a configurable rate.
- Live register and stack visualization with editable values.
- Instruction cheat sheet generated from the emulator instruction registry.
- Logging for parse errors, runtime errors, and halt events.
- Syscall output panel for INT 0x80 write calls.
- External symbol stubs (e.g., `extern printf`) with simple printf output support.
- Symbols dock listing code labels, data labels, globals, and externs.
- Memory view dock plus basic heap allocator with `malloc`/`free` extern stubs.
- Fixed memory limit (default 0x20000) with a simple heap range starting at 0x3000.

## Requirements

- Python 3.10+
- PyQt6

## Install

```bash
pip install PyQt6
```

## Icon Font (optional)

The editor toolbar buttons can use an icon font. If you want Font Awesome, place one
of these files in `assets/` (create the folder if needed):

- `FontAwesome6Free-Solid-900.otf`
- `fa-solid-900.ttf`
- `fontawesome-webfont.ttf`

If no Font Awesome files are found, the app falls back to a system icon font (on
Windows, `Segoe MDL2 Assets`) or plain text labels.

## Run

```bash
python main.py
```

On Windows, you can also use:

```bash
py main.py
```

## Examples

Sample programs are in `examples/`.

- `examples/add_sub_demo.asm`
- `examples/push_pop_demo.asm`
