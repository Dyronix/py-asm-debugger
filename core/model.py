from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass(frozen=True)
class Operand:
    type: str  # reg, imm, mem, label, unsupported
    value: str | int
    text: str
    size: int | None = None


@dataclass(frozen=True)
class Instruction:
    line_no: int
    text: str
    mnemonic: str
    operands: List[Operand]


@dataclass
class Program:
    instructions: List[Instruction]
    labels: Dict[str, int]
    entry_point: Optional[int] = None
    externs: Set[str] = field(default_factory=set)
    globals: Set[str] = field(default_factory=set)
    data_labels: Dict[str, int] = field(default_factory=dict)
    data_bytes: Dict[int, int] = field(default_factory=dict)

    def get_label(self, name: str) -> Optional[int]:
        return self.labels.get(name.upper())

    def get_data_label(self, name: str) -> Optional[int]:
        return self.data_labels.get(name.upper())
