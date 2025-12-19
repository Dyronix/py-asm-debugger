import pytest

from core.cpu import CPUState
from core.emulator import Emulator
from core.instructions import (
    INSTRUCTION_SET,
    EmulationError,
    exec_add,
    exec_and,
    exec_call,
    exec_cmp,
    exec_dec,
    exec_div,
    exec_hlt,
    exec_inc,
    exec_int,
    exec_je,
    exec_jmp,
    exec_jne,
    exec_lea,
    exec_leave,
    exec_mov,
    exec_nop,
    exec_not,
    exec_or,
    exec_pop,
    exec_push,
    exec_ret,
    exec_shl,
    exec_shr,
    exec_sub,
    exec_test,
    exec_xor,
)
from core.model import Instruction, Operand, Program
from core.parser import parse_assembly


def _blank_program(**kwargs) -> Program:
    return Program(
        instructions=kwargs.get("instructions", []),
        labels=kwargs.get("labels", {}),
        entry_point=kwargs.get("entry_point"),
        externs=set(kwargs.get("externs", set())),
        globals=set(kwargs.get("globals", set())),
        data_labels=kwargs.get("data_labels", {}),
        data_bytes=kwargs.get("data_bytes", {}),
        constants=kwargs.get("constants", {}),
    )


def _cpu_with_data(program: Program) -> CPUState:
    cpu = CPUState()
    cpu.load_data(program.data_bytes)
    return cpu


def test_mov_handles_register_and_memory_variants():
    program = _blank_program()
    cpu = CPUState()
    cpu.set_reg("EAX", 10)
    cpu.set_reg("EBX", 0x1200)
    cpu.write_mem(0x1204, 4, 0xDEADBEEF)

    exec_mov(
        cpu,
        Instruction(1, "mov ecx, 5", "MOV", [Operand("reg", "ECX", "ecx"), Operand("imm", 5, "5")]),
        program,
    )
    assert cpu.get_reg("ECX") == 5

    exec_mov(
        cpu,
        Instruction(2, "mov edx, eax", "MOV", [Operand("reg", "EDX", "edx"), Operand("reg", "EAX", "eax")]),
        program,
    )
    assert cpu.get_reg("EDX") == 10

    exec_mov(
        cpu,
        Instruction(
            3,
            "mov eax, [ebx+4]",
            "MOV",
            [Operand("reg", "EAX", "eax"), Operand("mem", ("EBX", 4), "[ebx+4]")],
        ),
        program,
    )
    assert cpu.get_reg("EAX") == 0xDEADBEEF

    exec_mov(
        cpu,
        Instruction(
            4, "mov [ebx], ecx", "MOV", [Operand("mem", ("EBX", 0), "[ebx]"), Operand("reg", "ECX", "ecx")]
        ),
        program,
    )
    assert cpu.read_mem(0x1200, 4) == 5


@pytest.mark.parametrize(
    ("executor", "mnemonic", "start", "operand", "expected"),
    [
        (exec_add, "ADD", 10, Operand("imm", 5, "5"), 15),
        (exec_sub, "SUB", 10, Operand("imm", 3, "3"), 7),
        (exec_and, "AND", 0b1111, Operand("imm", 0b1010, "0b1010"), 0b1010),
        (exec_or, "OR", 0b0101, Operand("imm", 0b1010, "0b1010"), 0b1111),
        (exec_xor, "XOR", 0b1100, Operand("imm", 0b1010, "0b1010"), 0b0110),
    ],
)
def test_basic_arithmetic_and_bitwise_ops(executor, mnemonic, start, operand, expected):
    cpu = CPUState()
    program = _blank_program()
    cpu.set_reg("EAX", start)

    instr = Instruction(
        1,
        f"{mnemonic.lower()} eax, {operand.text}",
        mnemonic,
        [Operand("reg", "EAX", "eax"), operand],
    )
    executor(cpu, instr, program)
    assert cpu.get_reg("EAX") == expected


def test_not_inverts_bits_and_clamps_to_32_bits():
    cpu = CPUState()
    program = _blank_program()
    cpu.set_reg("EAX", 0)

    exec_not(cpu, Instruction(1, "not eax", "NOT", [Operand("reg", "EAX", "eax")]), program)
    assert cpu.get_reg("EAX") == 0xFFFFFFFF

    cpu.set_reg("EAX", 0x1_0000_0001)
    exec_not(cpu, Instruction(2, "not eax", "NOT", [Operand("reg", "EAX", "eax")]), program)
    assert cpu.get_reg("EAX") == 0xFFFFFFFE


def test_shift_masks_amount_and_shifts_correctly():
    cpu = CPUState()
    program = _blank_program()
    cpu.set_reg("EAX", 1)

    exec_shl(
        cpu,
        Instruction(
            1,
            "shl eax, 40",
            "SHL",
            [Operand("reg", "EAX", "eax"), Operand("imm", 40, "40")],
        ),
        program,
    )
    assert cpu.get_reg("EAX") == 0x100

    cpu.set_reg("EBX", 0x80000000)
    exec_shr(
        cpu,
        Instruction(2, "shr ebx, 1", "SHR", [Operand("reg", "EBX", "ebx"), Operand("imm", 1, "1")]),
        program,
    )
    assert cpu.get_reg("EBX") == 0x40000000


def test_inc_dec_on_byte_memory_updates_flags_and_value():
    program = _blank_program(data_labels={"DIGIT": 0x2000}, data_bytes={0x2000: 0x7F})
    cpu = _cpu_with_data(program)

    inc_instr = Instruction(1, "inc byte [digit]", "INC", [Operand("mem", ("DIGIT", 0), "[digit]", size=1)])
    exec_inc(cpu, inc_instr, program)
    assert cpu.read_mem(0x2000, 1) == 0x80
    assert cpu.flags["OF"] == 1
    assert cpu.flags["SF"] == 1
    assert cpu.flags["ZF"] == 0

    dec_instr = Instruction(2, "dec byte [digit]", "DEC", [Operand("mem", ("DIGIT", 0), "[digit]", size=1)])
    exec_dec(cpu, dec_instr, program)
    assert cpu.read_mem(0x2000, 1) == 0x7F
    assert cpu.flags["OF"] == 1
    assert cpu.flags["SF"] == 0


def test_inc_on_register_sets_overflow_and_zero_flags():
    program = _blank_program()
    cpu = CPUState()
    cpu.set_reg("EAX", 0x7FFFFFFF)

    exec_inc(cpu, Instruction(1, "inc eax", "INC", [Operand("reg", "EAX", "eax")]), program)
    assert cpu.get_reg("EAX") == 0x80000000
    assert cpu.flags["OF"] == 1
    assert cpu.flags["SF"] == 1
    assert cpu.flags["ZF"] == 0

    exec_dec(cpu, Instruction(2, "dec eax", "DEC", [Operand("reg", "EAX", "eax")]), program)
    assert cpu.get_reg("EAX") == 0x7FFFFFFF
    assert cpu.flags["OF"] == 1


def test_test_sets_flags_without_storing_result():
    program = _blank_program()
    cpu = CPUState()
    cpu.set_reg("EAX", 0x80000001)

    instr = Instruction(1, "test eax, 1", "TEST", [Operand("reg", "EAX", "EAX"), Operand("imm", 1, "1")])
    exec_test(cpu, instr, program)
    assert cpu.flags["ZF"] == 0
    assert cpu.flags["SF"] == 0
    assert cpu.flags["CF"] == 0
    assert cpu.flags["OF"] == 0

    cpu.set_reg("EAX", 0x80000000)
    exec_test(cpu, instr, program)
    assert cpu.flags["ZF"] == 1
    assert cpu.flags["SF"] == 1


def test_div_updates_eax_and_edx():
    program = _blank_program()
    cpu = CPUState()
    cpu.set_reg("EAX", 10)
    cpu.set_reg("EDX", 0)

    exec_div(cpu, Instruction(1, "div 3", "DIV", [Operand("imm", 3, "3")]), program)
    assert cpu.get_reg("EAX") == 3
    assert cpu.get_reg("EDX") == 1


def test_push_and_pop_round_trip_value_and_stack_pointer():
    program = _blank_program()
    cpu = CPUState()
    start_esp = cpu.get_reg("ESP")
    exec_push(cpu, Instruction(1, "push 0xDEAD", "PUSH", [Operand("imm", 0xDEAD, "0xDEAD")]), program)
    assert cpu.get_reg("ESP") == start_esp - 4
    assert cpu.read_mem(cpu.get_reg("ESP"), 4) == 0xDEAD

    exec_pop(cpu, Instruction(2, "pop eax", "POP", [Operand("reg", "EAX", "eax")]), program)
    assert cpu.get_reg("EAX") == 0xDEAD
    assert cpu.get_reg("ESP") == start_esp


def test_nop_and_hlt_exec_results():
    program = _blank_program()
    cpu = CPUState()
    nop_result = exec_nop(cpu, Instruction(1, "nop", "NOP", []), program)
    assert nop_result.halt is False

    hlt_result = exec_hlt(cpu, Instruction(2, "hlt", "HLT", []), program)
    assert hlt_result.halt is True


def test_int_syscalls_support_exit_write_read_and_file_ops():
    program = _blank_program()
    cpu = CPUState()
    cpu.set_reg("EAX", 1)
    res = exec_int(cpu, Instruction(1, "int 0x80", "INT", [Operand("imm", 0x80, "0x80")]), program)
    assert res.halt is True

    cpu.set_reg("EAX", 4)
    cpu.set_reg("ECX", 0x2100)
    cpu.set_reg("EDX", 5)
    cpu.write_bytes(0x2100, b"hello")
    res = exec_int(cpu, Instruction(2, "int 0x80", "INT", [Operand("imm", 0x80, "0x80")]), program)
    assert res.output == "hello"
    assert res.output_target == "syscall"
    assert cpu.get_reg("EAX") == 5

    cpu.set_reg("EAX", 3)
    cpu.set_reg("ECX", 0x2200)
    cpu.set_reg("EDX", 3)
    res = exec_int(cpu, Instruction(3, "int 0x80", "INT", [Operand("imm", 0x80, "0x80")]), program)
    assert cpu.read_bytes(0x2200, 3) == b"\x00\x00\x00"
    assert cpu.get_reg("EAX") == 3
    assert res.output is None

    cpu.set_reg("EAX", 5)
    res = exec_int(cpu, Instruction(4, "int 0x80", "INT", [Operand("imm", 0x80, "0x80")]), program)
    assert cpu.get_reg("EAX") == 3
    assert res.output is None

    cpu.set_reg("EAX", 6)
    res = exec_int(cpu, Instruction(5, "int 0x80", "INT", [Operand("imm", 0x80, "0x80")]), program)
    assert cpu.get_reg("EAX") == 0
    assert res.output is None


def test_int_rejects_unknown_interrupt():
    program = _blank_program()
    cpu = CPUState()
    with pytest.raises(EmulationError):
        exec_int(cpu, Instruction(1, "int 0x81", "INT", [Operand("imm", 0x81, "0x81")]), program)


def test_cmp_sets_flags_for_equality_and_signed_overflow():
    program = _blank_program()
    cpu = CPUState()

    exec_cmp(
        cpu,
        Instruction(
            1,
            "cmp eax, eax",
            "CMP",
            [Operand("reg", "EAX", "eax"), Operand("reg", "EAX", "eax")],
        ),
        program,
    )
    assert cpu.flags["ZF"] == 1
    assert cpu.flags["CF"] == 0
    assert cpu.flags["OF"] == 0

    cpu.set_reg("EAX", 0x80000000)
    exec_cmp(
        cpu,
        Instruction(
            2,
            "cmp eax, 1",
            "CMP",
            [Operand("reg", "EAX", "eax"), Operand("imm", 1, "1")],
        ),
        program,
    )
    assert cpu.flags["OF"] == 1
    assert cpu.flags["SF"] == 0
    assert cpu.flags["CF"] == 1


def _program_with_label(target_index: int = 2) -> Program:
    instructions = [
        Instruction(1, "nop", "NOP", []),
        Instruction(2, "nop", "NOP", []),
        Instruction(3, "nop", "NOP", []),
    ]
    return _blank_program(instructions=instructions, labels={"TARGET": target_index})


def test_unconditional_and_conditional_jumps_follow_flags():
    program = _program_with_label()
    cpu = CPUState()
    target = program.labels["TARGET"]

    jmp_res = exec_jmp(
        cpu, Instruction(1, "jmp target", "JMP", [Operand("label", "TARGET", "target")]), program
    )
    assert jmp_res.next_eip == target

    cpu.flags["ZF"] = 1
    je_res = exec_je(
        cpu, Instruction(2, "je target", "JE", [Operand("label", "TARGET", "target")]), program
    )
    assert je_res.next_eip == target

    cpu.flags["ZF"] = 0
    jne_res = exec_jne(
        cpu, Instruction(3, "jne target", "JNE", [Operand("label", "TARGET", "target")]), program
    )
    assert jne_res.next_eip == target


@pytest.mark.parametrize(
    ("mnemonic", "flags", "should_jump"),
    [
        ("JZ", {"ZF": 1}, True),
        ("JNZ", {"ZF": 0}, True),
        ("JLE", {"ZF": 1, "SF": 0, "OF": 1}, True),
        ("JNG", {"ZF": 0, "SF": 1, "OF": 0}, True),
        ("JGE", {"SF": 0, "OF": 0}, True),
        ("JNL", {"SF": 1, "OF": 0}, False),
    ],
)
def test_jump_aliases_match_flag_logic(mnemonic, flags, should_jump):
    program = _program_with_label()
    cpu = CPUState()
    cpu.flags.update({"ZF": 0, "SF": 0, "OF": 0})
    cpu.flags.update(flags)
    executor = INSTRUCTION_SET[mnemonic].executor

    res = executor(
        cpu,
        Instruction(1, f"{mnemonic.lower()} target", mnemonic, [Operand("label", "TARGET", "target")]),
        program,
    )
    target = program.labels["TARGET"]
    if should_jump:
        assert res.next_eip == target
    else:
        assert res.next_eip is None


def test_call_pushes_return_and_sets_next_eip():
    instructions = [
        Instruction(1, "call func", "CALL", []),
        Instruction(2, "nop", "NOP", []),
        Instruction(3, "ret", "RET", []),
    ]
    program = _blank_program(instructions=instructions, labels={"FUNC": 2})
    cpu = CPUState()
    cpu.set_reg("EIP", 0)

    res = exec_call(cpu, Instruction(1, "call func", "CALL", [Operand("label", "FUNC", "func")]), program)
    assert res.next_eip == 2
    assert cpu.read_mem(cpu.get_reg("ESP"), 4) == 1


def test_call_invokes_simulated_external_and_restores_stack():
    program = _blank_program(
        externs={"puts"},
        data_labels={"MSG": 0x2000},
        data_bytes={0x2000: ord("H"), 0x2001: 0},
    )
    cpu = _cpu_with_data(program)
    cpu.write_mem(cpu.get_reg("ESP") + 4, 4, program.get_data_label("MSG") or 0)

    res = exec_call(cpu, Instruction(1, "call puts", "CALL", [Operand("label", "PUTS", "puts")]), program)
    assert res.output == "H\n"
    assert res.output_target == "extern"
    assert cpu.get_reg("EAX") == 2
    assert cpu.get_reg("ESP") == 0x1000


def test_ret_pops_return_address_and_validates_bounds():
    instructions = [
        Instruction(1, "nop", "NOP", []),
        Instruction(2, "ret", "RET", []),
        Instruction(3, "hlt", "HLT", []),
    ]
    program = _blank_program(instructions=instructions)
    cpu = CPUState()
    cpu.push(2)

    res = exec_ret(cpu, Instruction(2, "ret", "RET", []), program)
    assert res.next_eip == 2
    assert cpu.get_reg("ESP") == 0x1000


def test_leave_restores_stack_frame():
    program = _blank_program()
    cpu = CPUState()
    cpu.set_reg("EBP", 0x0FF0)
    cpu.set_reg("ESP", 0x0FE0)
    cpu.write_mem(0x0FF0, 4, 0x2222)

    res = exec_leave(cpu, Instruction(1, "leave", "LEAVE", []), program)
    assert res.next_eip is None
    assert cpu.get_reg("ESP") == 0x0FF4
    assert cpu.get_reg("EBP") == 0x2222


def test_lea_supports_memory_and_labels():
    program = _blank_program(data_labels={"BUF": 0x4000}, labels={"CODE": 5})
    cpu = CPUState()
    cpu.set_reg("EBX", 0x1200)

    exec_lea(
        cpu,
        Instruction(
            1,
            "lea eax, [ebx+8]",
            "LEA",
            [Operand("reg", "EAX", "eax"), Operand("mem", ("EBX", 8), "[ebx+8]")],
        ),
        program,
    )
    assert cpu.get_reg("EAX") == 0x1208

    exec_lea(
        cpu,
        Instruction(
            2,
            "lea ecx, buf",
            "LEA",
            [Operand("reg", "ECX", "ecx"), Operand("label", "BUF", "buf")],
        ),
        program,
    )
    assert cpu.get_reg("ECX") == 0x4000

    exec_lea(
        cpu,
        Instruction(
            3,
            "lea edx, code",
            "LEA",
            [Operand("reg", "EDX", "edx"), Operand("label", "CODE", "code")],
        ),
        program,
    )
    assert cpu.get_reg("EDX") == 5


def test_jnz_loop_with_dec_halts_when_counter_zero():
    program = parse_assembly(
        """
section .text
    global _start
_start:
    mov ecx, 2
loop:
    dec ecx
    jnz loop
    hlt
"""
    )
    cpu = _cpu_with_data(program)
    entry = program.entry_point or 0
    cpu.set_reg("EIP", entry)
    emu = Emulator(cpu, program)

    for _ in range(10):
        outcome = emu.step()
        if outcome.halted:
            break
    else:
        raise AssertionError("Emulator did not halt")

    assert cpu.get_reg("ECX") == 0
