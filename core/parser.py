from __future__ import annotations

import ast
import re
from typing import List

from core.model import Instruction, Operand, Program


REGISTER_NAMES = {"EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP"}
DIRECTIVES = {
    "GLOBAL",
    "SECTION",
    "SEGMENT",
    "EXTERN",
    "BITS",
    "DEFAULT",
    "ORG",
    "ALIGN",
    "DB",
    "DW",
    "DD",
    "STRING",
    "ASCIZ",
}


class ParseError(Exception):
    def __init__(self, message: str, line_no: int, text: str) -> None:
        super().__init__(message)
        self.message = message
        self.line_no = line_no
        self.text = text


LABEL_RE = re.compile(r"^([A-Za-z_.$@][A-Za-z0-9_.$@]*)\s*:")


def _strip_comment(line: str) -> str:
    return line.split(";", 1)[0]


SIZE_PREFIXES = {"BYTE": 1, "WORD": 2, "DWORD": 4}


def _parse_char_literal(raw: str) -> int | None:
    if len(raw) >= 3 and raw[0] == raw[-1] and raw[0] in ("'", "\""):
        inner = raw[1:-1]
        if len(inner) == 1:
            return ord(inner)
    return None


def _parse_operand(token: str) -> Operand:
    raw = token.strip()
    upper = raw.upper()
    if raw.startswith("<") and raw.endswith(">"):
        raw = raw[1:-1].strip()
        upper = raw.upper()
    if not raw:
        return Operand(type="unsupported", value=raw, text=raw)
    size = None
    parts = raw.split(None, 1)
    if parts and parts[0].upper() in SIZE_PREFIXES:
        size = SIZE_PREFIXES[parts[0].upper()]
        raw = parts[1].strip() if len(parts) > 1 else ""
        upper = raw.upper()
    if upper in REGISTER_NAMES:
        return Operand(type="reg", value=upper, text=raw, size=size)
    if upper.startswith("OFFSET"):
        parts_after = raw.split(None, 1)
        target = parts_after[1] if len(parts_after) > 1 else ""
        if target.upper().startswith("FLAT:"):
            target = target[len("FLAT:") :].strip()
        return Operand(type="label", value=target.strip(), text=raw, size=size)
    if upper.startswith("PTR "):
        raw = raw[4:].strip()
        upper = raw.upper()
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        inner_upper = inner.upper()
        if inner_upper in REGISTER_NAMES:
            return Operand(type="mem", value=(inner_upper, 0), text=raw, size=size)
        match = re.fullmatch(
            r"([A-Za-z]+)\s*([+-])\s*(0x[0-9A-Fa-f]+|-?\d+)", inner
        )
        if match:
            base = match.group(1).upper()
            if base in REGISTER_NAMES:
                sign = match.group(2)
                offset_text = match.group(3)
                offset = int(offset_text, 16) if offset_text.lower().startswith("0x") else int(offset_text, 10)
                if sign == "-":
                    offset = -offset
                return Operand(type="mem", value=(base, offset), text=raw, size=size)
        return Operand(type="unsupported", value=raw, text=raw, size=size)
    if re.fullmatch(r"0x[0-9A-Fa-f]+", raw):
        return Operand(type="imm", value=int(raw, 16), text=raw, size=size)
    if re.fullmatch(r"-?\d+", raw):
        return Operand(type="imm", value=int(raw, 10), text=raw, size=size)
    char_value = _parse_char_literal(raw)
    if char_value is not None:
        return Operand(type="imm", value=char_value, text=raw, size=size)
    if (raw.startswith("\"") and raw.endswith("\"")) or (raw.startswith("'") and raw.endswith("'")):
        inner = raw[1:-1]
        if inner:
            return Operand(type="label", value=inner, text=raw, size=size)
    if "(" in raw and ")" in raw:
        return Operand(type="label", value=raw, text=raw, size=size)
    if re.fullmatch(r"[A-Za-z_.$@][A-Za-z0-9_.$@]*", raw):
        return Operand(type="label", value=raw, text=raw, size=size)
    return Operand(type="unsupported", value=raw, text=raw, size=size)


def _split_args(text: str) -> List[str]:
    items: List[str] = []
    current: List[str] = []
    depth = 0
    quote: str | None = None
    escaped = False
    for ch in text:
        if quote:
            current.append(ch)
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            current.append(ch)
            continue
        if ch == "(":
            depth += 1
            current.append(ch)
            continue
        if ch == ")":
            if depth > 0:
                depth -= 1
            current.append(ch)
            continue
        if ch == "," and depth == 0:
            item = "".join(current).strip()
            if item:
                items.append(item)
            current = []
            continue
        current.append(ch)
    item = "".join(current).strip()
    if item:
        items.append(item)
    return items


def _parse_data_bytes(data_text: str, size: int, line_no: int, raw_line: str) -> bytes:
    items = _split_args(data_text)
    data = bytearray()
    for item in items:
        if (item.startswith("\"") and item.endswith("\"")) or (item.startswith("'") and item.endswith("'")):
            if size != 1:
                raise ParseError("String literal only valid with DB", line_no, raw_line)
            try:
                literal = ast.literal_eval(item)
            except (SyntaxError, ValueError) as exc:
                raise ParseError(f"Invalid string literal: {item}", line_no, raw_line) from exc
            data.extend(str(literal).encode("utf-8"))
            continue
        char_value = _parse_char_literal(item)
        if char_value is not None:
            value = char_value
        elif re.fullmatch(r"0x[0-9A-Fa-f]+", item):
            value = int(item, 16)
        elif re.fullmatch(r"-?\d+", item):
            value = int(item, 10)
        else:
            raise ParseError(f"Invalid data value: {item}", line_no, raw_line)
        if size == 1:
            data.append(value & 0xFF)
        elif size == 2:
            data.extend((value & 0xFFFF).to_bytes(2, "little", signed=False))
        elif size == 4:
            data.extend((value & 0xFFFFFFFF).to_bytes(4, "little", signed=False))
    return bytes(data)


def parse_assembly(text: str) -> Program:
    instructions: List[Instruction] = []
    labels: dict[str, int] = {}
    externs: set[str] = set()
    globals_set: set[str] = set()
    data_labels: dict[str, int] = {}
    data_bytes: dict[int, int] = {}
    data_addr = 0x2000
    section = "text"

    lines = text.splitlines()
    for idx, raw_line in enumerate(lines, start=1):
        line = _strip_comment(raw_line).rstrip()
        if not line.strip():
            continue

        working = line.lstrip()
        upper_working = working.upper()
        if upper_working.startswith(("SECTION", ".SECTION", "SEGMENT", ".SEGMENT")):
            parts = working.split(None, 1)
            target = parts[1].lower() if len(parts) > 1 else ""
            if "data" in target:
                section = "data"
            elif "rodata" in target or "bss" in target:
                section = "data"
            elif "text" in target or "code" in target:
                section = "text"
            continue
        if upper_working in {".TEXT", "TEXT", ".CODE"}:
            section = "text"
            continue
        if upper_working in {".DATA", "DATA", ".RODATA", "RODATA", ".BSS", "BSS"}:
            section = "data"
            continue
        while True:
            match = LABEL_RE.match(working)
            if not match:
                break
            label = match.group(1).upper()
            if section == "data":
                if label in data_labels:
                    raise ParseError(f"Duplicate data label: {label}", idx, raw_line)
                data_labels[label] = data_addr
            else:
                if label in labels:
                    raise ParseError(f"Duplicate label: {label}", idx, raw_line)
                labels[label] = len(instructions)
            working = working[match.end():].lstrip()
            if not working:
                break
        if not working:
            continue

        parts = working.split(None, 1)
        if not parts:
            continue
        mnemonic = parts[0].upper()
        stripped_mnemonic = mnemonic[1:] if mnemonic.startswith(".") else mnemonic
        if stripped_mnemonic in {"EXTERN", "GLOBAL"}:
            if stripped_mnemonic == "EXTERN" and len(parts) > 1:
                symbols = _split_args(parts[1])
                externs.update(sym.upper() for sym in symbols)
            if stripped_mnemonic == "GLOBAL" and len(parts) > 1:
                symbols = _split_args(parts[1])
                globals_set.update(sym.upper() for sym in symbols)
            continue

        if section == "data":
            if len(parts) >= 2 and parts[1]:
                directive = stripped_mnemonic
                if directive in {"DB", "DW", "DD", "STRING", "ASCIZ"}:
                    size = {"DB": 1, "DW": 2, "DD": 4}.get(directive, 1)
                    data = _parse_data_bytes(parts[1], size, idx, raw_line)
                    if directive in {"STRING", "ASCIZ"}:
                        data += b"\x00"
                    for offset, byte in enumerate(data):
                        data_bytes[data_addr + offset] = byte
                    data_addr += len(data)
                    continue
            tokens = working.split(None, 2)
            token_directive = tokens[1].upper() if len(tokens) >= 2 else ""
            token_directive = token_directive[1:] if token_directive.startswith(".") else token_directive
            if len(tokens) >= 2 and token_directive in {"DB", "DW", "DD", "STRING", "ASCIZ"}:
                label = tokens[0].upper()
                if label in data_labels:
                    raise ParseError(f"Duplicate data label: {label}", idx, raw_line)
                data_labels[label] = data_addr
                directive = token_directive
                size = {"DB": 1, "DW": 2, "DD": 4}.get(directive, 1)
                data_text = tokens[2] if len(tokens) > 2 else ""
                data = _parse_data_bytes(data_text, size, idx, raw_line)
                if directive in {"STRING", "ASCIZ"}:
                    data += b"\x00"
                for offset, byte in enumerate(data):
                    data_bytes[data_addr + offset] = byte
                data_addr += len(data)
            continue

        if stripped_mnemonic in DIRECTIVES:
            continue
        operands: List[Operand] = []
        if len(parts) > 1:
            operand_text = parts[1]
            raw_operands = _split_args(operand_text)
            operands = [_parse_operand(op) for op in raw_operands if op.strip()]
        instruction = Instruction(
            line_no=idx,
            text=raw_line.rstrip("\n"),
            mnemonic=mnemonic,
            operands=operands,
        )
        instructions.append(instruction)

    entry_point = labels.get("_START")
    if entry_point is None and "MAIN" in globals_set and "MAIN" in labels:
        entry_point = labels.get("MAIN")
    return Program(
        instructions=instructions,
        labels=labels,
        entry_point=entry_point,
        externs=externs,
        globals=globals_set,
        data_labels=data_labels,
        data_bytes=data_bytes,
    )
