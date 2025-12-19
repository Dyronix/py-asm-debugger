import pytest

from core.parser import parse_assembly


def test_equ_computes_length_and_constants_resolve():
    program = parse_assembly(
        """
section .data
    msg db "Hello", 10
    len equ $ - msg

section .text
    global _start
_start:
    mov edx, len
        """
    )

    assert program.constants["LEN"] == 6  # "Hello" + newline
    assert program.data_labels["MSG"] == 0x2000
    assert program.data_bytes[0x2000] == ord("H")
    assert program.data_bytes[0x2005] == 10

    # instruction operand resolves to label and constant
    mov_instr = program.instructions[-1]
    assert mov_instr.mnemonic == "MOV"
    assert mov_instr.operands[1].type == "label"
    assert mov_instr.operands[1].value.upper() == "LEN"
