# ASM Debugger

![Release workflow status](https://github.com/dsquad/py-asm-debugger/actions/workflows/release.yml/badge.svg)

A simple x86 (Intel syntax) assembly editor and step debugger built with PyQt6.

## Overview

ASM Debugger is a teaching-focused debugger for small x86 snippets. It combines a
lightweight emulator with a UI that keeps state visible and editable, so you can
step instructions, see register/flag changes, inspect memory, and experiment with
stack operations in real time.

## Project Layout

- `core/`: CPU state, instruction definitions, emulator, and parser.
- `ui/`: PyQt6 UI for editor, register/stack panels, memory view, and logs.
- `examples/`: Sample `.asm` programs.
- `tests/`: Pytest-based unit tests.

## Features

- Edit, open, and save `.asm` files.
- Parse and execute instructions step-by-step or automatically at a configurable rate.
- Live register and stack visualization with editable values.
- Instruction cheat sheet generated from the emulator instruction registry.
- Logging for parse errors, runtime errors, and halt events.
- Syscall output panel for INT 0x80 write calls.
- External symbol stubs for common C calls: `printf`/`puts`/`putchar`, `strlen`/`strcmp`, `memcpy`/`memset`, and `malloc`/`free` (plus `operator new/delete` aliases).
- Separate dock tabs for syscall output and simulated C function output.
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

## Tests

```bash
python -m pytest
```
