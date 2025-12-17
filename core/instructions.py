from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List

from core.cpu import CPUState, clamp_u32
from core.model import Instruction, Operand, Program
from core.syscalls import get_syscall


@dataclass
class ExecResult:
    next_eip: int | None = None
    halt: bool = False
    output: str | None = None


@dataclass(frozen=True)
class InstructionDef:
    mnemonic: str
    meaning: str
    description: str
    syntax: str
    flags: str
    executor: Callable[[CPUState, Instruction, Program], ExecResult]


class EmulationError(Exception):
    def __init__(self, message: str, line_no: int, text: str) -> None:
        super().__init__(message)
        self.message = message
        self.line_no = line_no
        self.text = text


REGISTERS = {"EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP"}


INSTRUCTION_SET: Dict[str, InstructionDef] = {}


def register_instruction(defn: InstructionDef) -> None:
    INSTRUCTION_SET[defn.mnemonic.upper()] = defn


def _expect_operands(instr: Instruction, count: int) -> None:
    if len(instr.operands) != count:
        raise EmulationError(
            f"Expected {count} operands for {instr.mnemonic}",
            instr.line_no,
            instr.text,
        )


def _require_reg(op: Operand, instr: Instruction) -> str:
    if op.type != "reg":
        raise EmulationError(
            f"Unsupported operand for {instr.mnemonic}: {op.text}",
            instr.line_no,
            instr.text,
        )
    return str(op.value).upper()


def _value_of(op: Operand, cpu: CPUState, instr: Instruction, program: Program) -> int:
    if op.type == "reg":
        return cpu.get_reg(str(op.value))
    if op.type == "imm":
        return int(op.value)
    if op.type == "label":
        name = str(op.value).upper()
        data_addr = program.get_data_label(name)
        if data_addr is not None:
            return data_addr
        code_addr = program.get_label(name)
        if code_addr is not None:
            return code_addr
        raise EmulationError(
            f"Unknown label: {op.text}",
            instr.line_no,
            instr.text,
        )
    raise EmulationError(
        f"Unsupported operand for {instr.mnemonic}: {op.text}",
        instr.line_no,
        instr.text,
    )


def _read_mem(op: Operand, cpu: CPUState, instr: Instruction) -> int:
    if op.type != "mem":
        raise EmulationError(
            f"Unsupported operand for {instr.mnemonic}: {op.text}",
            instr.line_no,
            instr.text,
        )
    if isinstance(op.value, tuple):
        base, offset = op.value
        addr = clamp_u32(cpu.get_reg(str(base)) + int(offset))
    else:
        addr = cpu.get_reg(str(op.value))
    size = op.size or 4
    return cpu.read_mem(addr, size)


def _write_mem(op: Operand, cpu: CPUState, value: int, instr: Instruction) -> None:
    if op.type != "mem":
        raise EmulationError(
            f"Unsupported operand for {instr.mnemonic}: {op.text}",
            instr.line_no,
            instr.text,
        )
    if isinstance(op.value, tuple):
        base, offset = op.value
        addr = clamp_u32(cpu.get_reg(str(base)) + int(offset))
    else:
        addr = cpu.get_reg(str(op.value))
    size = op.size or 4
    cpu.write_mem(addr, size, value)


def exec_mov(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 2)
    dest_op = instr.operands[0]
    src_op = instr.operands[1]
    if dest_op.type == "reg":
        if src_op.type == "mem":
            cpu.set_reg(str(dest_op.value), _read_mem(src_op, cpu, instr))
        else:
            cpu.set_reg(str(dest_op.value), _value_of(src_op, cpu, instr, program))
    elif dest_op.type == "mem":
        if src_op.type == "mem":
            raise EmulationError(
                f"Unsupported operand for {instr.mnemonic}: {src_op.text}",
                instr.line_no,
                instr.text,
            )
        _write_mem(dest_op, cpu, _value_of(src_op, cpu, instr, program), instr)
    else:
        raise EmulationError(
            f"Unsupported operand for {instr.mnemonic}: {dest_op.text}",
            instr.line_no,
            instr.text,
        )
    return ExecResult()


def exec_add(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 2)
    dest = _require_reg(instr.operands[0], instr)
    src = _value_of(instr.operands[1], cpu, instr, program)
    result = cpu.get_reg(dest) + src
    cpu.set_reg(dest, result)
    return ExecResult()


def exec_sub(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 2)
    dest = _require_reg(instr.operands[0], instr)
    src = _value_of(instr.operands[1], cpu, instr, program)
    result = cpu.get_reg(dest) - src
    cpu.set_reg(dest, result)
    return ExecResult()


def exec_inc(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 1)
    reg = _require_reg(instr.operands[0], instr)
    cpu.set_reg(reg, cpu.get_reg(reg) + 1)
    return ExecResult()


def exec_dec(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 1)
    reg = _require_reg(instr.operands[0], instr)
    cpu.set_reg(reg, cpu.get_reg(reg) - 1)
    return ExecResult()


def exec_push(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 1)
    value = _value_of(instr.operands[0], cpu, instr, program)
    cpu.push(value)
    return ExecResult()


def exec_pop(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 1)
    dest = _require_reg(instr.operands[0], instr)
    cpu.set_reg(dest, cpu.pop())
    return ExecResult()


def exec_nop(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 0)
    return ExecResult()


def exec_hlt(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 0)
    return ExecResult(halt=True)


def exec_int(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 1)
    op = instr.operands[0]
    if op.type != "imm":
        raise EmulationError(
            f"Unsupported operand for {instr.mnemonic}: {op.text}",
            instr.line_no,
            instr.text,
        )
    interrupt = int(op.value)
    if interrupt != 0x80:
        raise EmulationError(
            f"Unsupported interrupt: 0x{interrupt:X}",
            instr.line_no,
            instr.text,
        )
    syscall = cpu.get_reg("EAX")
    defn = get_syscall(syscall)
    if not defn:
        raise EmulationError(
            f"Unsupported system call: {syscall}",
            instr.line_no,
            instr.text,
        )
    if defn.number == 1:
        return ExecResult(halt=True)
    if defn.number == 4:
        buf = cpu.get_reg("ECX")
        length = cpu.get_reg("EDX")
        data = cpu.read_bytes(buf, length)
        output = data.decode("utf-8", errors="replace")
        cpu.set_reg("EAX", length)
        return ExecResult(output=output)
    raise EmulationError(
        f"System call not implemented: {defn.name}",
        instr.line_no,
        instr.text,
    )


def exec_cmp(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 2)
    left = _value_of(instr.operands[0], cpu, instr, program)
    right = _value_of(instr.operands[1], cpu, instr, program)
    result = clamp_u32(left - right)
    cpu.flags["ZF"] = 1 if result == 0 else 0
    cpu.flags["SF"] = 1 if (result & 0x80000000) else 0
    cpu.flags["CF"] = 1 if left < right else 0
    left_signed = (left & 0x7FFFFFFF) - (left & 0x80000000)
    right_signed = (right & 0x7FFFFFFF) - (right & 0x80000000)
    res_signed = (result & 0x7FFFFFFF) - (result & 0x80000000)
    cpu.flags["OF"] = 1 if ((left_signed ^ right_signed) & (left_signed ^ res_signed) & 0x80000000) else 0
    return ExecResult()


def exec_jmp(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 1)
    op = instr.operands[0]
    if op.type != "label":
        raise EmulationError(
            f"Unsupported operand for {instr.mnemonic}: {op.text}",
            instr.line_no,
            instr.text,
        )
    target = program.get_label(str(op.value))
    if target is None:
        raise EmulationError(
            f"Unknown label: {op.text}",
            instr.line_no,
            instr.text,
        )
    return ExecResult(next_eip=target)


def _exec_jcc(cpu: CPUState, instr: Instruction, program: Program, jump_on_zero: bool) -> ExecResult:
    _expect_operands(instr, 1)
    op = instr.operands[0]
    if op.type != "label":
        raise EmulationError(
            f"Unsupported operand for {instr.mnemonic}: {op.text}",
            instr.line_no,
            instr.text,
        )
    target = program.get_label(str(op.value))
    if target is None:
        raise EmulationError(
            f"Unknown label: {op.text}",
            instr.line_no,
            instr.text,
        )
    if bool(cpu.flags.get("ZF", 0)) == jump_on_zero:
        return ExecResult(next_eip=target)
    return ExecResult()


def exec_je(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    return _exec_jcc(cpu, instr, program, jump_on_zero=True)


def exec_jne(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    return _exec_jcc(cpu, instr, program, jump_on_zero=False)


def _simulate_printf(cpu: CPUState) -> str:
    esp = cpu.get_reg("ESP")
    fmt_ptr = cpu.read_mem(esp + 4, 4)
    fmt = cpu.read_c_string(fmt_ptr)
    arg_index = 1
    output = []
    i = 0
    while i < len(fmt):
        ch = fmt[i]
        if ch == "%" and i + 1 < len(fmt):
            spec = fmt[i + 1]
            if spec == "%":
                output.append("%")
                i += 2
                continue
            if spec in ("d", "i"):
                raw = cpu.read_mem(esp + 4 + arg_index * 4, 4)
                value = raw if raw < 0x80000000 else raw - 0x100000000
                output.append(str(value))
                arg_index += 1
                i += 2
                continue
            if spec == "s":
                ptr = cpu.read_mem(esp + 4 + arg_index * 4, 4)
                output.append(cpu.read_c_string(ptr))
                arg_index += 1
                i += 2
                continue
        output.append(ch)
        i += 1
    return "".join(output)


def _normalize_symbol(name: str) -> str:
    return "".join(name.split())


def exec_call(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 1)
    op = instr.operands[0]
    if op.type != "label":
        raise EmulationError(
            f"Unsupported operand for {instr.mnemonic}: {op.text}",
            instr.line_no,
            instr.text,
        )
    name = str(op.value).upper()
    normalized = _normalize_symbol(name)
    target = program.get_label(name)
    if target is None:
        if name in program.externs or any(_normalize_symbol(sym) == normalized for sym in program.externs):
            return_address = cpu.get_reg("EIP") + 1
            cpu.push(return_address)
            output = None
            if normalized.startswith("PRINTF"):
                output = _simulate_printf(cpu)
                cpu.set_reg("EAX", len(output))
            elif normalized.startswith("MALLOC") or normalized.startswith("OPERATORNEW") or normalized == "NEW":
                size = cpu.read_mem(cpu.get_reg("ESP") + 4, 4)
                ptr = cpu.malloc(size)
                cpu.set_reg("EAX", ptr)
            elif normalized.startswith("FREE") or normalized.startswith("OPERATORDELETE") or normalized == "DELETE":
                ptr = cpu.read_mem(cpu.get_reg("ESP") + 4, 4)
                cpu.free(ptr)
                cpu.set_reg("EAX", 0)
            else:
                cpu.set_reg("EAX", 0)
            cpu.pop()
            return ExecResult(output=output)
        raise EmulationError(
            f"Unknown label: {op.text}",
            instr.line_no,
            instr.text,
        )
    return_address = cpu.get_reg("EIP") + 1
    cpu.push(return_address)
    return ExecResult(next_eip=target)


def exec_ret(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 0)
    return_address = cpu.pop()
    return ExecResult(next_eip=return_address)


def exec_lea(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 2)
    dest = _require_reg(instr.operands[0], instr)
    src = instr.operands[1]
    if src.type == "mem":
        if isinstance(src.value, tuple):
            base, offset = src.value
            addr = clamp_u32(cpu.get_reg(str(base)) + int(offset))
        else:
            addr = cpu.get_reg(str(src.value))
        cpu.set_reg(dest, addr)
        return ExecResult()
    if src.type == "label":
        name = str(src.value).upper()
        data_addr = program.get_data_label(name)
        if data_addr is not None:
            cpu.set_reg(dest, data_addr)
            return ExecResult()
        code_addr = program.get_label(name)
        if code_addr is not None:
            cpu.set_reg(dest, code_addr)
            return ExecResult()
        raise EmulationError(
            f"Unknown label: {src.text}",
            instr.line_no,
            instr.text,
        )
    raise EmulationError(
        f"Unsupported operand for {instr.mnemonic}: {src.text}",
        instr.line_no,
        instr.text,
    )


register_instruction(
    InstructionDef(
        mnemonic="MOV",
        meaning="Move",
        description="Copy data from source to destination register.",
        syntax="MOV reg, imm | MOV reg, reg | MOV reg, [reg] | MOV [reg], imm/reg",
        flags="N/A",
        executor=exec_mov,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="ADD",
        meaning="Add",
        description="Add source operand to destination register.",
        syntax="ADD reg, imm | ADD reg, reg",
        flags="N/A",
        executor=exec_add,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="SUB",
        meaning="Subtract",
        description="Subtract source operand from destination register.",
        syntax="SUB reg, imm | SUB reg, reg",
        flags="N/A",
        executor=exec_sub,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="INC",
        meaning="Increment",
        description="Increment register by 1.",
        syntax="INC reg",
        flags="N/A",
        executor=exec_inc,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="DEC",
        meaning="Decrement",
        description="Decrement register by 1.",
        syntax="DEC reg",
        flags="N/A",
        executor=exec_dec,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="PUSH",
        meaning="Push",
        description="Push a value onto the stack.",
        syntax="PUSH reg | PUSH imm",
        flags="N/A",
        executor=exec_push,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="POP",
        meaning="Pop",
        description="Pop a value from the stack into a register.",
        syntax="POP reg",
        flags="N/A",
        executor=exec_pop,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="NOP",
        meaning="No Operation",
        description="Do nothing.",
        syntax="NOP",
        flags="N/A",
        executor=exec_nop,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="HLT",
        meaning="Halt",
        description="Stop execution.",
        syntax="HLT",
        flags="N/A",
        executor=exec_hlt,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="INT",
        meaning="Interrupt",
        description="Software interrupt; supports INT 0x80 Linux syscalls.",
        syntax="INT imm",
        flags="N/A",
        executor=exec_int,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="CMP",
        meaning="Compare",
        description="Compare two operands and set flags.",
        syntax="CMP reg, imm | CMP reg, reg",
        flags="ZF SF CF OF",
        executor=exec_cmp,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="JMP",
        meaning="Jump",
        description="Unconditional jump to label.",
        syntax="JMP label",
        flags="N/A",
        executor=exec_jmp,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="JE",
        meaning="Jump Equal",
        description="Jump if ZF == 1.",
        syntax="JE label",
        flags="Reads ZF",
        executor=exec_je,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="JZ",
        meaning="Jump Zero",
        description="Jump if ZF == 1.",
        syntax="JZ label",
        flags="Reads ZF",
        executor=exec_je,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="JNE",
        meaning="Jump Not Equal",
        description="Jump if ZF == 0.",
        syntax="JNE label",
        flags="Reads ZF",
        executor=exec_jne,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="JNZ",
        meaning="Jump Not Zero",
        description="Jump if ZF == 0.",
        syntax="JNZ label",
        flags="Reads ZF",
        executor=exec_jne,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="CALL",
        meaning="Call",
        description="Call a label, pushing return address onto the stack.",
        syntax="CALL label",
        flags="N/A",
        executor=exec_call,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="RET",
        meaning="Return",
        description="Return to the address on top of the stack.",
        syntax="RET",
        flags="N/A",
        executor=exec_ret,
    )
)
register_instruction(
    InstructionDef(
        mnemonic="LEA",
        meaning="Load Effective Address",
        description="Load effective address of a memory operand into a register.",
        syntax="LEA reg, [reg] | LEA reg, [reg+imm] | LEA reg, label",
        flags="N/A",
        executor=exec_lea,
    )
)


def get_instruction_defs() -> List[InstructionDef]:
    return list(INSTRUCTION_SET.values())
