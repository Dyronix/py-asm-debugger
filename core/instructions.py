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
    output_target: str | None = None


@dataclass(frozen=True)
class InstructionDef:
    mnemonic: str
    summary: str
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


INSTRUCTION_IMPLS: Dict[str, Callable[[CPUState, Instruction, Program], ExecResult]] = {}
INSTRUCTION_SET: Dict[str, InstructionDef] = {}


def register_instruction_impl(mnemonic: str, executor: Callable[[CPUState, Instruction, Program], ExecResult]) -> None:
    INSTRUCTION_IMPLS[mnemonic.upper()] = executor


def set_active_instruction_defs(defs: List[InstructionDef]) -> None:
    INSTRUCTION_SET.clear()
    for defn in defs:
        INSTRUCTION_SET[defn.mnemonic.upper()] = defn


def get_instruction_executor(mnemonic: str) -> Callable[[CPUState, Instruction, Program], ExecResult] | None:
    return INSTRUCTION_IMPLS.get(mnemonic.upper())


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
    if op.type == "mem":
        return _read_mem(op, cpu, instr, program)
    if op.type == "label":
        name = str(op.value).upper()
        constant_value = program.get_constant(name)
        if constant_value is not None:
            return constant_value
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


def _resolve_mem_address(op: Operand, cpu: CPUState, instr: Instruction, program: Program) -> int:
    if op.type != "mem":
        raise EmulationError(
            f"Unsupported operand for {instr.mnemonic}: {op.text}",
            instr.line_no,
            instr.text,
        )
    offset = 0
    base = op.value
    if isinstance(op.value, tuple):
        base, offset = op.value

    def _base_address(base_val) -> int:
        if isinstance(base_val, str):
            upper = base_val.upper()
            if upper in REGISTERS:
                return cpu.get_reg(upper)
            constant_value = program.get_constant(upper)
            if constant_value is not None:
                return constant_value
            data_addr = program.get_data_label(upper)
            if data_addr is not None:
                return data_addr
            code_addr = program.get_label(upper)
            if code_addr is not None:
                return code_addr
            raise EmulationError(f"Unknown label: {base_val}", instr.line_no, instr.text)
        return int(base_val)

    base_addr = _base_address(base)
    return clamp_u32(base_addr + int(offset))


def _read_mem(op: Operand, cpu: CPUState, instr: Instruction, program: Program) -> int:
    if op.type != "mem":
        raise EmulationError(
            f"Unsupported operand for {instr.mnemonic}: {op.text}",
            instr.line_no,
            instr.text,
        )
    addr = _resolve_mem_address(op, cpu, instr, program)
    size = op.size or 4
    return cpu.read_mem(addr, size)


def _write_mem(op: Operand, cpu: CPUState, value: int, instr: Instruction, program: Program) -> None:
    if op.type != "mem":
        raise EmulationError(
            f"Unsupported operand for {instr.mnemonic}: {op.text}",
            instr.line_no,
            instr.text,
        )
    addr = _resolve_mem_address(op, cpu, instr, program)
    size = op.size or 4
    cpu.write_mem(addr, size, value)


def _inc_dec_result(prev: int, size_bytes: int, op: str, cpu: CPUState) -> int:
    bits = max(8, size_bytes * 8)
    mask = (1 << bits) - 1
    sign_bit = 1 << (bits - 1)
    prev_masked = prev & mask
    if op == "inc":
        result = (prev_masked + 1) & mask
        overflow = prev_masked == (sign_bit - 1)
    else:
        result = (prev_masked - 1) & mask
        overflow = prev_masked == sign_bit
    cpu.flags["ZF"] = 1 if result == 0 else 0
    cpu.flags["SF"] = 1 if (result & sign_bit) else 0
    cpu.flags["OF"] = 1 if overflow else 0
    return result


def exec_mov(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 2)
    dest_op = instr.operands[0]
    src_op = instr.operands[1]
    if dest_op.type == "reg":
        if src_op.type == "mem":
            cpu.set_reg(str(dest_op.value), _read_mem(src_op, cpu, instr, program))
        else:
            cpu.set_reg(str(dest_op.value), _value_of(src_op, cpu, instr, program))
    elif dest_op.type == "mem":
        if src_op.type == "mem":
            raise EmulationError(
                f"Unsupported operand for {instr.mnemonic}: {src_op.text}",
                instr.line_no,
                instr.text,
            )
        _write_mem(dest_op, cpu, _value_of(src_op, cpu, instr, program), instr, program)
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


def exec_and(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 2)
    dest = _require_reg(instr.operands[0], instr)
    src = _value_of(instr.operands[1], cpu, instr, program)
    cpu.set_reg(dest, cpu.get_reg(dest) & src)
    return ExecResult()


def exec_or(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 2)
    dest = _require_reg(instr.operands[0], instr)
    src = _value_of(instr.operands[1], cpu, instr, program)
    cpu.set_reg(dest, cpu.get_reg(dest) | src)
    return ExecResult()


def exec_xor(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 2)
    dest = _require_reg(instr.operands[0], instr)
    src = _value_of(instr.operands[1], cpu, instr, program)
    cpu.set_reg(dest, cpu.get_reg(dest) ^ src)
    return ExecResult()


def exec_not(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 1)
    dest = _require_reg(instr.operands[0], instr)
    cpu.set_reg(dest, clamp_u32(~cpu.get_reg(dest)))
    return ExecResult()


def _shift(cpu: CPUState, instr: Instruction, program: Program, direction: str) -> ExecResult:
    _expect_operands(instr, 2)
    dest = _require_reg(instr.operands[0], instr)
    amount = _value_of(instr.operands[1], cpu, instr, program) & 0x1F
    current = cpu.get_reg(dest)
    if direction == "left":
        cpu.set_reg(dest, clamp_u32(current << amount))
    else:
        cpu.set_reg(dest, clamp_u32(current >> amount))
    return ExecResult()


def exec_shl(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    return _shift(cpu, instr, program, direction="left")


def exec_shr(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    return _shift(cpu, instr, program, direction="right")


def exec_inc(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 1)
    op = instr.operands[0]
    if op.type == "reg":
        reg = _require_reg(op, instr)
        prev = cpu.get_reg(reg)
        result = _inc_dec_result(prev, 4, "inc", cpu)
        cpu.set_reg(reg, result)
    elif op.type == "mem":
        value = _read_mem(op, cpu, instr, program)
        result = _inc_dec_result(value, op.size or 4, "inc", cpu)
        _write_mem(op, cpu, result, instr, program)
    else:
        raise EmulationError(
            f"Unsupported operand for {instr.mnemonic}: {op.text}",
            instr.line_no,
            instr.text,
        )
    return ExecResult()


def exec_dec(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 1)
    op = instr.operands[0]
    if op.type == "reg":
        reg = _require_reg(op, instr)
        prev = cpu.get_reg(reg)
        result = _inc_dec_result(prev, 4, "dec", cpu)
        cpu.set_reg(reg, result)
    elif op.type == "mem":
        value = _read_mem(op, cpu, instr, program)
        result = _inc_dec_result(value, op.size or 4, "dec", cpu)
        _write_mem(op, cpu, result, instr, program)
    else:
        raise EmulationError(
            f"Unsupported operand for {instr.mnemonic}: {op.text}",
            instr.line_no,
            instr.text,
        )
    return ExecResult()


def exec_test(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 2)
    left = _value_of(instr.operands[0], cpu, instr, program)
    right = _value_of(instr.operands[1], cpu, instr, program)
    result = clamp_u32(left & right)
    cpu.flags["ZF"] = 1 if result == 0 else 0
    sign_bit = 0x80000000
    if result == 0:
        cpu.flags["SF"] = 1 if (left & sign_bit) else 0
    else:
        cpu.flags["SF"] = 1 if (result & sign_bit) else 0
    cpu.flags["CF"] = 0
    cpu.flags["OF"] = 0
    return ExecResult()


def exec_div(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 1)
    op = instr.operands[0]
    divisor = _value_of(op, cpu, instr, program)
    if divisor == 0:
        raise EmulationError("Division by zero", instr.line_no, instr.text)
    eax = cpu.get_reg("EAX")
    edx = cpu.get_reg("EDX")
    dividend = (edx << 32) | eax
    quotient = dividend // divisor
    remainder = dividend % divisor
    cpu.set_reg("EAX", clamp_u32(quotient))
    cpu.set_reg("EDX", clamp_u32(remainder))
    return ExecResult()


def exec_push(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 1)
    op = instr.operands[0]
    if op.type == "mem":
        value = _read_mem(op, cpu, instr, program)
    else:
        value = _value_of(op, cpu, instr, program)
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
        return ExecResult(output=output, output_target="syscall")
    if defn.number == 3:
        length = cpu.get_reg("EDX")
        buf = cpu.get_reg("ECX")
        # Simulate read with zero-fill; no actual FD handling.
        data = bytes([0] * length)
        cpu.write_bytes(buf, data)
        cpu.set_reg("EAX", length)
        return ExecResult()
    if defn.number == 5:
        # Simulate open by returning a dummy FD > 2.
        cpu.set_reg("EAX", 3)
        return ExecResult()
    if defn.number == 6:
        # Simulate close as success.
        cpu.set_reg("EAX", 0)
        return ExecResult()
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
    left_signed = (left & 0x7FFFFFFF) - (left & 0x80000000)
    right_signed = (right & 0x7FFFFFFF) - (right & 0x80000000)
    res_signed = (result & 0x7FFFFFFF) - (result & 0x80000000)
    cpu.flags["CF"] = 1 if left_signed < right_signed else 0
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


def _exec_jle(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
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
    zf = bool(cpu.flags.get("ZF", 0))
    sf = bool(cpu.flags.get("SF", 0))
    of = bool(cpu.flags.get("OF", 0))
    if zf or (sf != of):
        return ExecResult(next_eip=target)
    return ExecResult()


def _exec_jge(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
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
    sf = bool(cpu.flags.get("SF", 0))
    of = bool(cpu.flags.get("OF", 0))
    if sf == of:
        return ExecResult(next_eip=target)
    return ExecResult()


def exec_je(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    return _exec_jcc(cpu, instr, program, jump_on_zero=True)


def exec_jne(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    return _exec_jcc(cpu, instr, program, jump_on_zero=False)


def _simulate_printf(cpu: CPUState) -> ExecResult:
    esp = cpu.get_reg("ESP")
    fmt_ptr = cpu.read_mem(esp + 4, 4)
    fmt = cpu.read_c_string(fmt_ptr)
    arg_base = 4
    if not fmt:
        fallback_ptr = cpu.read_mem(esp + 8, 4)
        fallback_fmt = cpu.read_c_string(fallback_ptr)
        if fallback_fmt:
            fmt = fallback_fmt
            arg_base = 8
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
            raw_arg = cpu.read_mem(esp + arg_base + arg_index * 4, 4)
            arg_index += 1
            if spec in ("d", "i"):
                value = raw_arg if raw_arg < 0x80000000 else raw_arg - 0x100000000
                output.append(str(value))
                i += 2
                continue
            if spec == "u":
                output.append(str(raw_arg & 0xFFFFFFFF))
                i += 2
                continue
            if spec in ("x", "X"):
                hex_value = f"{raw_arg & 0xFFFFFFFF:08x}"
                output.append(hex_value.upper() if spec == "X" else hex_value)
                i += 2
                continue
            if spec == "p":
                output.append(f"0x{raw_arg & 0xFFFFFFFF:08x}")
                i += 2
                continue
            if spec == "c":
                output.append(chr(raw_arg & 0xFF))
                i += 2
                continue
            if spec == "s":
                output.append(cpu.read_c_string(raw_arg))
                i += 2
                continue
            output.append("%")
            output.append(spec)
            i += 2
            continue
        output.append(ch)
        i += 1
    rendered = "".join(output)
    cpu.set_reg("EAX", len(rendered))
    return ExecResult(output=rendered, output_target="extern")


def _simulate_puts(cpu: CPUState) -> ExecResult:
    esp = cpu.get_reg("ESP")
    primary_ptr = cpu.read_mem(esp + 4, 4)
    fallback_ptr = cpu.read_mem(esp + 8, 4)
    text = cpu.read_c_string(primary_ptr)
    if not text:
        fallback_text = cpu.read_c_string(fallback_ptr)
        if fallback_text:
            text = fallback_text
    rendered = f"{text}\n"
    cpu.set_reg("EAX", len(rendered))
    return ExecResult(output=rendered, output_target="extern")


def _simulate_putchar(cpu: CPUState) -> ExecResult:
    esp = cpu.get_reg("ESP")
    value = cpu.read_mem(esp + 4, 4) & 0xFF
    cpu.set_reg("EAX", value)
    return ExecResult(output=chr(value), output_target="extern")


def _simulate_strlen(cpu: CPUState) -> ExecResult:
    esp = cpu.get_reg("ESP")
    ptr = cpu.read_mem(esp + 4, 4)
    length = len(cpu.read_c_string(ptr))
    cpu.set_reg("EAX", length)
    return ExecResult()


def _simulate_strcmp(cpu: CPUState) -> ExecResult:
    esp = cpu.get_reg("ESP")
    left_ptr = cpu.read_mem(esp + 4, 4)
    right_ptr = cpu.read_mem(esp + 8, 4)
    left = cpu.read_c_string(left_ptr)
    right = cpu.read_c_string(right_ptr)
    result = (left > right) - (left < right)
    cpu.set_reg("EAX", result)
    return ExecResult()


def _simulate_memcpy(cpu: CPUState) -> ExecResult:
    esp = cpu.get_reg("ESP")
    dest = cpu.read_mem(esp + 4, 4)
    src = cpu.read_mem(esp + 8, 4)
    length = cpu.read_mem(esp + 12, 4)
    safe_length = max(0, min(length, cpu.memory_limit - max(dest, 0)))
    data = cpu.read_bytes(src, safe_length)
    cpu.write_bytes(dest, data)
    cpu.set_reg("EAX", dest)
    return ExecResult()


def _simulate_memset(cpu: CPUState) -> ExecResult:
    esp = cpu.get_reg("ESP")
    dest = cpu.read_mem(esp + 4, 4)
    value = cpu.read_mem(esp + 8, 4) & 0xFF
    length = cpu.read_mem(esp + 12, 4)
    safe_length = max(0, min(length, cpu.memory_limit - max(dest, 0)))
    cpu.write_bytes(dest, bytes([value]) * safe_length)
    cpu.set_reg("EAX", dest)
    return ExecResult()


def _simulate_malloc(cpu: CPUState) -> ExecResult:
    esp = cpu.get_reg("ESP")
    size = cpu.read_mem(esp + 4, 4)
    ptr = cpu.malloc(size)
    cpu.set_reg("EAX", ptr)
    return ExecResult()


def _simulate_free(cpu: CPUState) -> ExecResult:
    esp = cpu.get_reg("ESP")
    ptr = cpu.read_mem(esp + 4, 4)
    cpu.free(ptr)
    cpu.set_reg("EAX", 0)
    return ExecResult()


SIMULATED_CALLS: Dict[str, Callable[[CPUState], ExecResult]] = {
    "PRINTF": _simulate_printf,
    "PUTS": _simulate_puts,
    "PUTCHAR": _simulate_putchar,
    "STRLEN": _simulate_strlen,
    "STRCMP": _simulate_strcmp,
    "MEMCPY": _simulate_memcpy,
    "MEMSET": _simulate_memset,
    "MALLOC": _simulate_malloc,
    "OPERATORNEW": _simulate_malloc,
    "NEW": _simulate_malloc,
    "FREE": _simulate_free,
    "OPERATORDELETE": _simulate_free,
    "DELETE": _simulate_free,
}


def _normalize_symbol(name: str) -> str:
    return "".join(name.split())


def _match_simulated_call(symbol_id: str) -> Callable[[CPUState], ExecResult] | None:
    candidates = [symbol_id, symbol_id.lstrip("_")]
    for candidate in candidates:
        for prefix, handler in SIMULATED_CALLS.items():
            if candidate.startswith(prefix):
                return handler
    return None


def _extern_matches_symbol(name: str, externs: set[str]) -> bool:
    normalized_externs = {_normalize_symbol(sym) for sym in externs}
    normalized_externs |= {_normalize_symbol(sym.lstrip("_")) for sym in externs}
    candidates = {
        name,
        name.split("@", 1)[0],
        name.lstrip("_"),
        _normalize_symbol(name),
        _normalize_symbol(name.split("@", 1)[0]),
        _normalize_symbol(name.lstrip("_")),
    }
    return any(candidate in normalized_externs for candidate in candidates)


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
    base_name = name.split("@", 1)[0]
    base_normalized = _normalize_symbol(base_name)
    target = program.get_label(name)
    if target is None:
        extern_match = _extern_matches_symbol(name, program.externs)
        handler = _match_simulated_call(base_normalized if "@PLT" in name else normalized)
        if extern_match or "@PLT" in name or handler:
            return_address = cpu.get_reg("EIP") + 1
            cpu.push(return_address)
            result = handler(cpu) if handler else ExecResult()
            if handler and result.output and not result.output_target:
                result.output_target = "extern"
            if handler is None:
                cpu.set_reg("EAX", 0)
            cpu.pop()
            return result
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
    esp = cpu.get_reg("ESP")
    addresses = [esp + offset for offset in range(4)]
    if any(clamp_u32(addr) not in cpu.stack_memory for addr in addresses):
        raise EmulationError(
            "Missing return address on stack (RET reached via JMP or stack clobbered)",
            instr.line_no,
            instr.text,
        )
    return_address = cpu.pop()
    if return_address < 0 or return_address >= len(program.instructions):
        raise EmulationError(
            f"Invalid return address: 0x{return_address:X} (possible JMP into RET)",
            instr.line_no,
            instr.text,
        )
    return ExecResult(next_eip=return_address)


def exec_leave(cpu: CPUState, instr: Instruction, program: Program) -> ExecResult:
    _expect_operands(instr, 0)
    ebp = cpu.get_reg("EBP")
    cpu.set_reg("ESP", ebp)
    new_ebp = cpu.pop()
    cpu.set_reg("EBP", new_ebp)
    return ExecResult()


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


register_instruction_impl("MOV", exec_mov)
register_instruction_impl("ADD", exec_add)
register_instruction_impl("SUB", exec_sub)
register_instruction_impl("AND", exec_and)
register_instruction_impl("OR", exec_or)
register_instruction_impl("XOR", exec_xor)
register_instruction_impl("NOT", exec_not)
register_instruction_impl("SHL", exec_shl)
register_instruction_impl("SHR", exec_shr)
register_instruction_impl("INC", exec_inc)
register_instruction_impl("DEC", exec_dec)
register_instruction_impl("DIV", exec_div)
register_instruction_impl("PUSH", exec_push)
register_instruction_impl("POP", exec_pop)
register_instruction_impl("NOP", exec_nop)
register_instruction_impl("HLT", exec_hlt)
register_instruction_impl("INT", exec_int)
register_instruction_impl("CMP", exec_cmp)
register_instruction_impl("JMP", exec_jmp)
register_instruction_impl("JE", exec_je)
register_instruction_impl("JZ", exec_je)
register_instruction_impl("JNE", exec_jne)
register_instruction_impl("JNZ", exec_jne)
register_instruction_impl("JLE", _exec_jle)
register_instruction_impl("JNG", _exec_jle)
register_instruction_impl("JGE", _exec_jge)
register_instruction_impl("JNL", _exec_jge)
register_instruction_impl("TEST", exec_test)
register_instruction_impl("CALL", exec_call)
register_instruction_impl("RET", exec_ret)
register_instruction_impl("LEAVE", exec_leave)
register_instruction_impl("LEA", exec_lea)


def get_instruction_defs() -> List[InstructionDef]:
    return list(INSTRUCTION_SET.values())
