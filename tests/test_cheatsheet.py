import json
from pathlib import Path

import pytest

from core.cheatsheet import CheatSheetError, CheatSheetValidationError, cheat_sheet_manager
from core.cpu import CPUState
from core.emulator import Emulator
from core.parser import parse_assembly


def _write_sheet(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def test_default_sheet_executes_minimal_program():
    cheat_sheet_manager.load_default()
    program = parse_assembly("mov eax, 1\nadd eax, 2\nhlt\n", cheat_sheet_manager.active_syntax())
    cheat_sheet_manager.validate_program(program)

    cpu = CPUState()
    emulator = Emulator(cpu, program)
    for _ in range(5):
        outcome = emulator.step()
        if outcome.error:
            pytest.fail(outcome.error.message)
        if outcome.halted:
            break
    assert cpu.get_reg("EAX") == 3


def test_mov_only_sheet_rejects_add(tmp_path: Path):
    sheet_path = tmp_path / "mov_only.json"
    _write_sheet(
        sheet_path,
        {
            "schema_version": 1,
            "name": "MOV Only",
            "isa": {"arch": "x86", "mode": 32},
            "syntax": "intel",
            "toolchain": {"assembler": "gas", "compiler": "gcc"},
            "instructions": [
                {
                    "mnemonic": "mov",
                    "summary": "Move",
                    "forms": [{"operands": ["reg32", "imm32"]}],
                }
            ],
        },
    )
    cheat_sheet_manager.load_from_path(sheet_path)
    program = parse_assembly("mov eax, 1\nadd eax, 2\n", cheat_sheet_manager.active_syntax())
    with pytest.raises(CheatSheetValidationError) as exc:
        cheat_sheet_manager.validate_program(program)
    assert "Unknown instruction: ADD" in exc.value.message


def test_rejects_x64_sheet(tmp_path: Path):
    sheet_path = tmp_path / "x64.json"
    _write_sheet(
        sheet_path,
        {
            "schema_version": 1,
            "name": "x64",
            "isa": {"arch": "x86", "mode": 64},
            "syntax": "intel",
            "toolchain": {"assembler": "gas", "compiler": "gcc"},
            "instructions": [
                {"mnemonic": "mov", "summary": "Move", "forms": []}
            ],
        },
    )
    with pytest.raises(CheatSheetError):
        cheat_sheet_manager.load_from_path(sheet_path)


def test_att_syntax_parsing_and_validation(tmp_path: Path):
    sheet_path = tmp_path / "att.json"
    _write_sheet(
        sheet_path,
        {
            "schema_version": 1,
            "name": "AT&T Test",
            "isa": {"arch": "x86", "mode": 32},
            "syntax": "att",
            "toolchain": {"assembler": "gas", "compiler": "gcc"},
            "instructions": [
                {
                    "mnemonic": "mov",
                    "summary": "Move",
                    "forms": [{"operands": ["reg32", "imm32"]}],
                }
            ],
        },
    )
    cheat_sheet_manager.load_from_path(sheet_path)
    program = parse_assembly("mov $1, %eax", cheat_sheet_manager.active_syntax())
    cheat_sheet_manager.validate_program(program)
    instr = program.instructions[0]
    assert instr.operands[0].type == "reg"
    assert instr.operands[0].value == "EAX"
    assert instr.operands[1].type == "imm"
    assert instr.operands[1].value == 1
