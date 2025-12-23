from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

from core.instructions import InstructionDef, get_instruction_executor, set_active_instruction_defs
from core.model import Instruction, Operand, Program


ALLOWED_ARCHES = {"x86"}
ALLOWED_SYNTAXES = {"intel", "att"}
ALLOWED_ASSEMBLERS = {"gas", "nasm", "masm", "unknown"}
ALLOWED_COMPILERS = {"gcc", "clang", "unknown"}
ALLOWED_OPERANDS = {
    "reg8",
    "reg16",
    "reg32",
    "imm8",
    "imm16",
    "imm32",
    "mem8",
    "mem16",
    "mem32",
    "rel8",
    "rel32",
    "segment",
}


@dataclass(frozen=True)
class OperandForm:
    operands: List[str]
    encoding: Optional[str] = None
    introduced_in: Optional[str] = None
    notes: Optional[str] = None
    flags: Optional[Dict[str, List[str]]] = None


@dataclass(frozen=True)
class CheatSheetInstruction:
    mnemonic: str
    summary: str
    description: str
    forms: List[OperandForm]
    examples: List[str]


@dataclass(frozen=True)
class CheatSheet:
    schema_version: int
    name: str
    description: str
    isa: Dict[str, object]
    syntax: str
    toolchain: Dict[str, object]
    instructions: List[CheatSheetInstruction]


class CheatSheetError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class CheatSheetValidationError(Exception):
    def __init__(self, message: str, line_no: int, text: str) -> None:
        super().__init__(message)
        self.message = message
        self.line_no = line_no
        self.text = text


def _default_cheat_sheet_path() -> Path:
    return Path(__file__).resolve().parent.parent / "assets" / "cheatsheets" / "default_gcc_intel_x86_32_min.json"


class CheatSheetManager:
    def __init__(self, default_path: Optional[Path] = None) -> None:
        self.default_path = default_path or _default_cheat_sheet_path()
        self.active_sheet: Optional[CheatSheet] = None
        self.active_path: Optional[Path] = None
        self._callbacks: List[Callable[[CheatSheet], None]] = []
        self.load_default()

    def on_change(self, callback: Callable[[CheatSheet], None]) -> None:
        self._callbacks.append(callback)

    def _emit_change(self) -> None:
        if not self.active_sheet:
            return
        for callback in list(self._callbacks):
            callback(self.active_sheet)

    def list_bundled(self) -> List[Path]:
        if not self.default_path.exists():
            return []
        return sorted(self.default_path.parent.glob("*.json"))

    def load_default(self) -> CheatSheet:
        return self.load_from_path(self.default_path)

    def load_from_path(self, path: Path | str) -> CheatSheet:
        resolved = Path(path).expanduser().resolve()
        data = self._load_json(resolved)
        sheet = self._validate_sheet(data, resolved)
        self.active_sheet = sheet
        self.active_path = resolved
        self._activate_sheet(sheet)
        self._emit_change()
        return sheet

    def reload(self) -> CheatSheet:
        if self.active_path:
            return self.load_from_path(self.active_path)
        return self.load_default()

    def active_syntax(self) -> str:
        return self.active_sheet.syntax if self.active_sheet else "intel"

    def validate_program(self, program: Program) -> None:
        if not self.active_sheet:
            raise CheatSheetError("No active cheat sheet.")
        mnemonic_to_forms = {instr.mnemonic: instr.forms for instr in self.active_sheet.instructions}
        for instr in program.instructions:
            mnemonic = instr.mnemonic.upper()
            if mnemonic not in mnemonic_to_forms:
                raise CheatSheetValidationError(
                    f"Unknown instruction: {mnemonic}",
                    instr.line_no,
                    instr.text,
                )
            forms = mnemonic_to_forms[mnemonic]
            if not self._matches_any_form(instr, forms):
                operand_desc = ", ".join(self._describe_operands(instr.operands)) or "(none)"
                raise CheatSheetValidationError(
                    f"{mnemonic} does not support operands {operand_desc} in this sheet",
                    instr.line_no,
                    instr.text,
                )

    def _activate_sheet(self, sheet: CheatSheet) -> None:
        defs: List[InstructionDef] = []
        for instruction in sheet.instructions:
            executor = get_instruction_executor(instruction.mnemonic)
            if not executor:
                raise CheatSheetError(
                    f"Instruction '{instruction.mnemonic}' is not implemented in the emulator.")
            syntax = self._format_syntax(instruction, sheet.syntax)
            defs.append(
                InstructionDef(
                    mnemonic=instruction.mnemonic,
                    summary=instruction.summary,
                    description=instruction.description,
                    syntax=syntax,
                    flags=self._format_flags(instruction),
                    executor=executor,
                )
            )
        set_active_instruction_defs(defs)

    def _format_syntax(self, instruction: CheatSheetInstruction, syntax: str) -> str:
        if not instruction.forms:
            return instruction.mnemonic
        if syntax == "att":
            return self._format_att_syntax(instruction)
        parts = []
        for form in instruction.forms:
            operands = ", ".join(form.operands)
            parts.append(f"{instruction.mnemonic} {operands}" if operands else instruction.mnemonic)
        return " | ".join(parts)

    def _format_att_syntax(self, instruction: CheatSheetInstruction) -> str:
        parts = []
        for form in instruction.forms:
            suffix = self._att_suffix_for_operands(form.operands)
            mnemonic = f"{instruction.mnemonic}{suffix}" if suffix else instruction.mnemonic
            operands = list(reversed(form.operands))
            rendered_ops = ", ".join(self._att_operand_display(op) for op in operands)
            parts.append(f"{mnemonic} {rendered_ops}" if rendered_ops else mnemonic)
        return " | ".join(parts)

    def _att_suffix_for_operands(self, operands: List[str]) -> str:
        size_map = {"8": "b", "16": "w", "32": "l"}
        sizes = []
        for op in operands:
            for bits in ("32", "16", "8"):
                if op.endswith(bits):
                    sizes.append(bits)
                    break
        if not sizes:
            return ""
        preferred = sizes[0]
        for bits in sizes:
            if bits == "32":
                preferred = "32"
                break
            if bits == "16" and preferred != "32":
                preferred = "16"
        return size_map.get(preferred, "")

    def _att_operand_display(self, operand: str) -> str:
        if operand.startswith("reg"):
            return f"%{operand}"
        if operand.startswith("imm"):
            return f"${operand}"
        if operand.startswith("mem"):
            return f"disp(%{operand.replace('mem', 'reg')})"
        if operand.startswith("rel"):
            return "label"
        if operand == "segment":
            return "%seg"
        return operand

    def _format_flags(self, instruction: CheatSheetInstruction) -> str:
        flagged = []
        for form in instruction.forms:
            if not form.flags:
                continue
            for key, values in form.flags.items():
                if values:
                    joined = ",".join(values)
                    flagged.append(f"{key}:{joined}")
        return " ".join(flagged) if flagged else ""

    def _load_json(self, path: Path) -> dict:
        if not path.exists():
            raise CheatSheetError(f"Cheat sheet not found: {path}")
        try:
            with path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except json.JSONDecodeError as exc:
            raise CheatSheetError(f"Invalid JSON in {path}: {exc}") from exc
        except OSError as exc:
            raise CheatSheetError(f"Failed to read cheat sheet: {exc}") from exc

    def _validate_sheet(self, data: dict, path: Path) -> CheatSheet:
        if not isinstance(data, dict):
            raise CheatSheetError("Cheat sheet must be a JSON object.")
        schema_version = data.get("schema_version")
        if not isinstance(schema_version, int):
            raise CheatSheetError("schema_version must be an integer.")
        if schema_version != 1:
            raise CheatSheetError(f"Unsupported schema_version: {schema_version}")
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise CheatSheetError("name is required and must be a string.")
        description = data.get("description") or ""
        if description and not isinstance(description, str):
            raise CheatSheetError("description must be a string if provided.")
        isa = data.get("isa")
        if not isinstance(isa, dict):
            raise CheatSheetError("isa is required and must be an object.")
        arch = isa.get("arch")
        mode = isa.get("mode")
        if not isinstance(arch, str) or arch not in ALLOWED_ARCHES:
            raise CheatSheetError(f"Unsupported ISA arch: {arch}")
        if not isinstance(mode, int) or mode != 32:
            raise CheatSheetError("Only x86 32-bit cheat sheets are supported.")
        if isa.get("mode") == 64 or str(arch).lower() in {"x86_64", "amd64"}:
            raise CheatSheetError("x64/AMD64 cheat sheets are not supported.")
        syntax = data.get("syntax")
        if syntax not in ALLOWED_SYNTAXES:
            raise CheatSheetError("syntax must be one of: intel, att.")
        toolchain = data.get("toolchain")
        if not isinstance(toolchain, dict):
            raise CheatSheetError("toolchain is required and must be an object.")
        assembler = toolchain.get("assembler")
        compiler = toolchain.get("compiler")
        if assembler not in ALLOWED_ASSEMBLERS:
            raise CheatSheetError("toolchain.assembler is invalid.")
        if compiler not in ALLOWED_COMPILERS:
            raise CheatSheetError("toolchain.compiler is invalid.")
        for version_key in ("version_min", "version_max"):
            if version_key in toolchain and toolchain[version_key] is not None:
                if not isinstance(toolchain[version_key], str):
                    raise CheatSheetError(f"toolchain.{version_key} must be a string.")
        instructions_data = data.get("instructions")
        if not isinstance(instructions_data, list) or not instructions_data:
            raise CheatSheetError("instructions must be a non-empty array.")
        instructions: List[CheatSheetInstruction] = []
        seen: set[str] = set()
        for idx, entry in enumerate(instructions_data, start=1):
            instruction = self._validate_instruction(entry, idx, path)
            if instruction.mnemonic in seen:
                raise CheatSheetError(f"Duplicate mnemonic in cheat sheet: {instruction.mnemonic}")
            seen.add(instruction.mnemonic)
            instructions.append(instruction)
        return CheatSheet(
            schema_version=schema_version,
            name=name.strip(),
            description=description.strip(),
            isa=isa,
            syntax=syntax,
            toolchain=toolchain,
            instructions=instructions,
        )

    def _validate_instruction(self, entry: dict, index: int, path: Path) -> CheatSheetInstruction:
        if not isinstance(entry, dict):
            raise CheatSheetError(f"Instruction #{index} must be an object in {path}.")
        mnemonic = entry.get("mnemonic")
        if not isinstance(mnemonic, str) or not mnemonic.strip():
            raise CheatSheetError(f"Instruction #{index} is missing mnemonic.")
        summary = entry.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            raise CheatSheetError(f"Instruction {mnemonic} is missing summary.")
        description = entry.get("description") or ""
        if description and not isinstance(description, str):
            raise CheatSheetError(f"Instruction {mnemonic} description must be a string.")
        forms_data = entry.get("forms")
        if not isinstance(forms_data, list):
            raise CheatSheetError(f"Instruction {mnemonic} forms must be an array.")
        forms: List[OperandForm] = []
        for form in forms_data:
            forms.append(self._validate_form(mnemonic, form))
        examples = entry.get("examples") or []
        if not isinstance(examples, list) or any(not isinstance(ex, str) for ex in examples):
            raise CheatSheetError(f"Instruction {mnemonic} examples must be an array of strings.")
        return CheatSheetInstruction(
            mnemonic=mnemonic.strip().upper(),
            summary=summary.strip(),
            description=description.strip(),
            forms=forms,
            examples=examples,
        )

    def _validate_form(self, mnemonic: str, form: dict) -> OperandForm:
        if not isinstance(form, dict):
            raise CheatSheetError(f"Instruction {mnemonic} form must be an object.")
        operands = form.get("operands")
        if operands is None:
            operands = []
        if not isinstance(operands, list) or any(not isinstance(op, str) for op in operands):
            raise CheatSheetError(f"Instruction {mnemonic} operands must be a list of strings.")
        normalized = []
        for op in operands:
            if op not in ALLOWED_OPERANDS:
                raise CheatSheetError(f"Instruction {mnemonic} has unsupported operand type: {op}")
            if op in {"reg64", "imm64", "mem64"}:
                raise CheatSheetError("x64 operands are not supported.")
            normalized.append(op)
        flags = form.get("flags")
        if flags is not None and not isinstance(flags, dict):
            raise CheatSheetError(f"Instruction {mnemonic} flags must be an object if provided.")
        return OperandForm(
            operands=normalized,
            encoding=form.get("encoding"),
            introduced_in=form.get("introduced_in"),
            notes=form.get("notes"),
            flags=flags,
        )

    def _matches_any_form(self, instr: Instruction, forms: Iterable[OperandForm]) -> bool:
        forms_list = list(forms)
        if not forms_list:
            return len(instr.operands) == 0
        for form in forms_list:
            if self._matches_form(instr, form):
                return True
        return False

    def _matches_form(self, instr: Instruction, form: OperandForm) -> bool:
        if len(instr.operands) != len(form.operands):
            return False
        for op, descriptor in zip(instr.operands, form.operands):
            options = self._operand_descriptor_options(op)
            if descriptor not in options:
                return False
        return True

    def _operand_descriptor_options(self, op: Operand) -> List[str]:
        if op.type == "reg":
            return ["reg32"]
        if op.type == "imm":
            return self._imm_descriptor_options(op)
        if op.type == "mem":
            return self._mem_descriptor_options(op)
        if op.type == "label":
            return ["rel32", "imm32"]
        return ["unsupported"]

    def _imm_descriptor_options(self, op: Operand) -> List[str]:
        if op.size == 1:
            return ["imm8"]
        if op.size == 2:
            return ["imm16"]
        if op.size == 4:
            return ["imm32"]
        value = int(op.value) if isinstance(op.value, int) else 0
        options = ["imm32"]
        if -128 <= value <= 255:
            options.append("imm8")
        if -32768 <= value <= 65535:
            options.append("imm16")
        return options

    def _mem_descriptor_options(self, op: Operand) -> List[str]:
        if op.size == 1:
            return ["mem8"]
        if op.size == 2:
            return ["mem16"]
        if op.size == 4:
            return ["mem32"]
        return ["mem32"]

    def _describe_operands(self, operands: List[Operand]) -> List[str]:
        return [self._describe_operand(op) for op in operands]

    def _describe_operand(self, op: Operand) -> str:
        options = self._operand_descriptor_options(op)
        return options[0] if options else "unsupported"


cheat_sheet_manager = CheatSheetManager()
