from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class SyscallDef:
    number: int
    name: str
    description: str
    args: str
    returns: str


SYSCALLS: Dict[int, SyscallDef] = {}


def register_syscall(defn: SyscallDef) -> None:
    SYSCALLS[defn.number] = defn


def get_syscall(number: int) -> Optional[SyscallDef]:
    return SYSCALLS.get(number)


def get_syscall_defs() -> List[SyscallDef]:
    return list(SYSCALLS.values())


register_syscall(
    SyscallDef(
        number=1,
        name="exit",
        description="Exit the process. Emulator halts.",
        args="EBX = status",
        returns="N/A",
    )
)
register_syscall(
    SyscallDef(
        number=3,
        name="read",
        description="Read bytes from fd into buffer (simulated zero-fill).",
        args="EBX=fd, ECX=buf, EDX=len",
        returns="EAX = bytes read",
    )
)
register_syscall(
    SyscallDef(
        number=4,
        name="write",
        description="Write bytes to a file descriptor (simulated).",
        args="EBX=fd, ECX=buf, EDX=len",
        returns="EAX = bytes written",
    )
)
register_syscall(
    SyscallDef(
        number=5,
        name="open",
        description="Open a file path (simulated stub).",
        args="EBX=pathname, ECX=flags, EDX=mode",
        returns="EAX = fd (simulated)",
    )
)
register_syscall(
    SyscallDef(
        number=6,
        name="close",
        description="Close a file descriptor (simulated stub).",
        args="EBX=fd",
        returns="EAX = status (0 on success)",
    )
)
