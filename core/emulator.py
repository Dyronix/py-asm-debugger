from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.cpu import CPUState
from core.instructions import EmulationError, ExecResult, INSTRUCTION_SET
from core.model import Program


@dataclass
class StepOutcome:
    halted: bool = False
    error: Optional[EmulationError] = None
    output: Optional[str] = None
    output_target: Optional[str] = None


class Emulator:
    def __init__(self, cpu: CPUState, program: Program) -> None:
        self.cpu = cpu
        self.program = program
        self.halted = False

    def reset(self) -> None:
        self.cpu.reset()
        self.halted = False

    def step(self) -> StepOutcome:
        if self.halted:
            return StepOutcome(halted=True)

        if self.cpu.registers["EIP"] >= len(self.program.instructions):
            self.halted = True
            return StepOutcome(halted=True)

        instr = self.program.instructions[self.cpu.registers["EIP"]]
        defn = INSTRUCTION_SET.get(instr.mnemonic)
        if not defn:
            error = EmulationError(
                f"Unknown instruction: {instr.mnemonic}",
                instr.line_no,
                instr.text,
            )
            return StepOutcome(error=error)

        try:
            result: ExecResult = defn.executor(self.cpu, instr, self.program)
        except EmulationError as exc:
            return StepOutcome(error=exc)

        if result.halt:
            self.halted = True
            return StepOutcome(halted=True, output=result.output, output_target=result.output_target)

        if result.next_eip is None:
            self.cpu.registers["EIP"] += 1
        else:
            self.cpu.registers["EIP"] = result.next_eip
        return StepOutcome(output=result.output, output_target=result.output_target)
