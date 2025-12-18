from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple


REGISTER_ORDER = [
    "EAX",
    "EBX",
    "ECX",
    "EDX",
    "ESI",
    "EDI",
    "EBP",
    "ESP",
    "EIP",
]


def clamp_u32(value: int) -> int:
    return value & 0xFFFFFFFF


@dataclass
class CPUState:
    registers: Dict[str, int] = field(default_factory=dict)
    flags: Dict[str, int] = field(default_factory=dict)
    stack_memory: Dict[int, int] = field(default_factory=dict)
    memory_limit: int = 0x20000
    heap_base: int = 0x3000
    heap_end: int = 0x18000
    heap_ptr: int = 0x3000
    allocations: Dict[int, int] = field(default_factory=dict)
    free_list: List[Tuple[int, int]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.registers:
            self.reset()
        if not self.flags:
            self.flags = {"ZF": 0, "SF": 0, "CF": 0, "OF": 0}

    def reset(self) -> None:
        self.registers = {name: 0 for name in REGISTER_ORDER}
        self.registers["ESP"] = 0x1000
        self.registers["EBP"] = 0x1000
        self.registers["EIP"] = 0
        self.stack_memory = {}
        self.flags = {"ZF": 0, "SF": 0, "CF": 0, "OF": 0}
        self.heap_ptr = self.heap_base
        self.allocations = {}
        self.free_list = []

    def get_reg(self, name: str) -> int:
        return self.registers[name.upper()]

    def set_reg(self, name: str, value: int) -> None:
        self.registers[name.upper()] = clamp_u32(value)

    def push(self, value: int) -> None:
        esp = clamp_u32(self.registers["ESP"] - 4)
        self.registers["ESP"] = esp
        self.write_mem(esp, 4, value)

    def pop(self) -> int:
        esp = self.registers["ESP"]
        value = self.read_mem(esp, 4)
        self.registers["ESP"] = clamp_u32(esp + 4)
        return clamp_u32(value)

    def read_mem(self, addr: int, size: int) -> int:
        if addr < 0 or addr + size > self.memory_limit:
            return 0
        value = 0
        for i in range(size):
            byte = self.stack_memory.get(clamp_u32(addr + i), 0)
            value |= (byte & 0xFF) << (8 * i)
        return clamp_u32(value)

    def write_mem(self, addr: int, size: int, value: int) -> None:
        if addr < 0 or addr + size > self.memory_limit:
            return
        for i in range(size):
            byte = (value >> (8 * i)) & 0xFF
            self.stack_memory[clamp_u32(addr + i)] = byte

    def read_bytes(self, addr: int, length: int) -> bytes:
        if addr < 0:
            return b""
        if addr + length > self.memory_limit:
            length = max(0, min(length, self.memory_limit - addr))
        return bytes(self.stack_memory.get(clamp_u32(addr + i), 0) & 0xFF for i in range(length))

    def write_bytes(self, addr: int, data: bytes) -> None:
        if addr < 0 or addr >= self.memory_limit:
            return
        max_len = max(0, min(len(data), self.memory_limit - addr))
        for offset in range(max_len):
            self.stack_memory[clamp_u32(addr + offset)] = data[offset] & 0xFF

    def read_c_string(self, addr: int, max_len: int = 1024) -> str:
        data = bytearray()
        for i in range(max_len):
            byte = self.stack_memory.get(clamp_u32(addr + i), 0) & 0xFF
            if byte == 0:
                break
            data.append(byte)
        return data.decode("utf-8", errors="replace")

    def load_data(self, data_bytes: Dict[int, int]) -> None:
        for addr, byte in data_bytes.items():
            if 0 <= addr < self.memory_limit:
                self.stack_memory[clamp_u32(addr)] = byte & 0xFF

    def malloc(self, size: int) -> int:
        if size <= 0:
            return 0
        size = (size + 3) & ~3
        for index, (addr, block_size) in enumerate(self.free_list):
            if block_size >= size:
                self.free_list.pop(index)
                if block_size > size:
                    self.free_list.append((addr + size, block_size - size))
                self.allocations[addr] = size
                return addr
        if self.heap_ptr + size > self.heap_end or self.heap_ptr + size > self.memory_limit:
            return 0
        addr = self.heap_ptr
        self.heap_ptr += size
        self.allocations[addr] = size
        return addr

    def free(self, addr: int) -> None:
        size = self.allocations.pop(addr, None)
        if size is None:
            return
        self.free_list.append((addr, size))
