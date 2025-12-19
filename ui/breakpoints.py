from __future__ import annotations

import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QMessageBox,
    QWidget,
)

from core.cpu import REGISTER_ORDER

FLAG_ORDER = ["ZF", "SF", "CF", "OF"]


class BreakpointType(Enum):
    LINE = "Line"
    TEMPORARY_LINE = "Temporary"
    REGISTER_CONDITION = "Register"
    FLAG_CONDITION = "Flag"


@dataclass
class Breakpoint:
    id: int
    type: BreakpointType
    enabled: bool
    file_path: Optional[str]
    line: Optional[int]
    name: Optional[str]
    op: Optional[str]
    value: Optional[int]
    hit_count: int = 0
    last_hit_timestamp: Optional[float] = None


class BreakpointManager(QObject):
    changed = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        self._next_id = 1
        self._breakpoints: dict[int, Breakpoint] = {}
        self._valid_lines: dict[str, set[int]] = {}

    def _normalize_path(self, path: Optional[str]) -> Optional[str]:
        if not path:
            return None
        return os.path.abspath(path)

    def _new_id(self) -> int:
        value = self._next_id
        self._next_id += 1
        return value

    def list_all(self) -> list[Breakpoint]:
        return sorted(self._breakpoints.values(), key=lambda bp: bp.id)

    def get(self, bp_id: int) -> Optional[Breakpoint]:
        return self._breakpoints.get(bp_id)

    def get_line_breakpoints(self, file_path: Optional[str]) -> list[Breakpoint]:
        norm = self._normalize_path(file_path)
        if not norm:
            return []
        return [
            bp
            for bp in self._breakpoints.values()
            if bp.file_path == norm and bp.type in {BreakpointType.LINE, BreakpointType.TEMPORARY_LINE}
        ]

    def add_line(self, file_path: Optional[str], line: int, temporary: bool = False) -> int:
        norm = self._normalize_path(file_path)
        line_type = BreakpointType.TEMPORARY_LINE if temporary else BreakpointType.LINE
        for bp in self._breakpoints.values():
            if bp.type == line_type and bp.file_path == norm and bp.line == line:
                if not bp.enabled:
                    bp.enabled = True
                    self.changed.emit()
                return bp.id
        bp = Breakpoint(
            id=self._new_id(),
            type=line_type,
            enabled=True,
            file_path=norm,
            line=line,
            name=None,
            op=None,
            value=None,
        )
        self._breakpoints[bp.id] = bp
        self.changed.emit()
        return bp.id

    def toggle_line(self, file_path: Optional[str], line: int) -> bool:
        norm = self._normalize_path(file_path)
        for bp_id, bp in list(self._breakpoints.items()):
            if bp.type == BreakpointType.LINE and bp.file_path == norm and bp.line == line:
                del self._breakpoints[bp_id]
                self.changed.emit()
                return False
        self.add_line(norm, line, temporary=False)
        return True

    def add_register_condition(self, name: str, value: int) -> int:
        bp = Breakpoint(
            id=self._new_id(),
            type=BreakpointType.REGISTER_CONDITION,
            enabled=True,
            file_path=None,
            line=None,
            name=name.upper(),
            op="==",
            value=value,
        )
        self._breakpoints[bp.id] = bp
        self.changed.emit()
        return bp.id

    def add_flag_condition(self, name: str, value: int) -> int:
        bp = Breakpoint(
            id=self._new_id(),
            type=BreakpointType.FLAG_CONDITION,
            enabled=True,
            file_path=None,
            line=None,
            name=name.upper(),
            op="==",
            value=value,
        )
        self._breakpoints[bp.id] = bp
        self.changed.emit()
        return bp.id

    def set_enabled(self, bp_id: int, enabled: bool) -> None:
        bp = self._breakpoints.get(bp_id)
        if not bp or bp.enabled == enabled:
            return
        bp.enabled = enabled
        self.changed.emit()

    def remove(self, bp_id: int) -> None:
        if bp_id in self._breakpoints:
            del self._breakpoints[bp_id]
            self.changed.emit()

    def increment_hit(self, bp_id: int) -> bool:
        bp = self._breakpoints.get(bp_id)
        if not bp:
            return False
        bp.hit_count += 1
        bp.last_hit_timestamp = time.time()
        if bp.type == BreakpointType.TEMPORARY_LINE:
            del self._breakpoints[bp_id]
            self.changed.emit()
            return True
        self.changed.emit()
        return False

    def set_valid_lines(self, file_path: Optional[str], lines: Iterable[int]) -> None:
        norm = self._normalize_path(file_path)
        if not norm:
            return
        self._valid_lines[norm] = set(lines)
        self.changed.emit()

    def line_has_instruction(self, file_path: Optional[str], line: Optional[int]) -> bool:
        if not file_path or line is None:
            return False
        norm = self._normalize_path(file_path)
        if not norm:
            return False
        if norm not in self._valid_lines:
            return True
        return line in self._valid_lines.get(norm, set())

    def should_break(self, file_path: Optional[str], line: Optional[int], cpu_state) -> tuple[bool, Optional[int], str]:
        norm = self._normalize_path(file_path)
        for bp in self.list_all():
            if not bp.enabled:
                continue
            if bp.type in {BreakpointType.LINE, BreakpointType.TEMPORARY_LINE}:
                if norm and bp.file_path == norm and bp.line == line:
                    if not self.line_has_instruction(norm, line):
                        continue
                    reason = f"{bp.type.value} breakpoint at {os.path.basename(norm)}:{line}"
                    return True, bp.id, reason
            elif bp.type == BreakpointType.REGISTER_CONDITION:
                if bp.name and bp.value is not None:
                    if cpu_state.get_reg(bp.name) == bp.value:
                        return True, bp.id, f"{bp.name} == 0x{bp.value:X}"
            elif bp.type == BreakpointType.FLAG_CONDITION:
                if bp.name and bp.value is not None:
                    if cpu_state.flags.get(bp.name, 0) == bp.value:
                        return True, bp.id, f"{bp.name} == {bp.value}"
        return False, None, ""

    def to_json(self) -> dict:
        return {
            "next_id": self._next_id,
            "breakpoints": [
                {
                    "id": bp.id,
                    "type": bp.type.value,
                    "enabled": bp.enabled,
                    "file_path": bp.file_path,
                    "line": bp.line,
                    "name": bp.name,
                    "op": bp.op,
                    "value": bp.value,
                    "hit_count": bp.hit_count,
                    "last_hit_timestamp": bp.last_hit_timestamp,
                }
                for bp in self.list_all()
            ],
        }

    def load_json(self, data: dict) -> None:
        self._breakpoints.clear()
        self._next_id = int(data.get("next_id", 1))
        for item in data.get("breakpoints", []):
            try:
                bp_type = BreakpointType(item.get("type", BreakpointType.LINE.value))
            except ValueError:
                bp_type = BreakpointType.LINE
            bp = Breakpoint(
                id=int(item.get("id", self._new_id())),
                type=bp_type,
                enabled=bool(item.get("enabled", True)),
                file_path=item.get("file_path"),
                line=item.get("line"),
                name=item.get("name"),
                op=item.get("op"),
                value=item.get("value"),
                hit_count=int(item.get("hit_count", 0)),
                last_hit_timestamp=item.get("last_hit_timestamp"),
            )
            self._breakpoints[bp.id] = bp
            self._next_id = max(self._next_id, bp.id + 1)
        self.changed.emit()


class BreakpointsTableModel(QAbstractTableModel):
    headers = ["Enabled", "Type", "Location", "Condition", "Hit Count", "Remove"]

    def __init__(self, manager: BreakpointManager, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.manager = manager
        self._rows: list[Breakpoint] = []
        self.manager.changed.connect(self.refresh)
        self.refresh()

    def refresh(self) -> None:
        self.beginResetModel()
        self._rows = self.manager.list_all()
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # type: ignore[override]
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # type: ignore[override]
        return 0 if parent.isValid() else len(self.headers)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.headers[section]
        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:  # type: ignore[override]
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        column = index.column()
        base = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if column == 0:
            return base | Qt.ItemFlag.ItemIsUserCheckable
        return base

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):  # type: ignore[override]
        if not index.isValid():
            return None
        bp = self._rows[index.row()]
        column = index.column()

        if role == Qt.ItemDataRole.CheckStateRole and column == 0:
            return Qt.CheckState.Checked if bp.enabled else Qt.CheckState.Unchecked

        if role == Qt.ItemDataRole.DisplayRole:
            if column == 1:
                return bp.type.value
            if column == 2:
                if bp.file_path and bp.line:
                    base = f"{bp.file_path}:{bp.line}"
                    if not self.manager.line_has_instruction(bp.file_path, bp.line):
                        return f"{base} (no instruction)"
                    return base
                return "-"
            if column == 3:
                if bp.name and bp.op and bp.value is not None:
                    if bp.type == BreakpointType.REGISTER_CONDITION:
                        return f"{bp.name} {bp.op} 0x{bp.value:X}"
                    return f"{bp.name} {bp.op} {bp.value}"
                return "-"
            if column == 4:
                return str(bp.hit_count)
            if column == 5:
                return "Remove"
        if role == Qt.ItemDataRole.ForegroundRole:
            if not bp.enabled:
                return QColor("#6272a4")
            if bp.type == BreakpointType.TEMPORARY_LINE:
                return QColor("#ffb86c")
            if bp.file_path and bp.line and not self.manager.line_has_instruction(bp.file_path, bp.line):
                return QColor("#ff5555")
        if role == Qt.ItemDataRole.ToolTipRole:
            if bp.file_path and bp.line and not self.manager.line_has_instruction(bp.file_path, bp.line):
                return "No instruction mapped to this line."
        return None

    def setData(self, index: QModelIndex, value, role: int = Qt.ItemDataRole.EditRole) -> bool:  # type: ignore[override]
        if not index.isValid() or index.column() != 0:
            return False
        if role == Qt.ItemDataRole.CheckStateRole:
            bp = self._rows[index.row()]
            self.manager.set_enabled(bp.id, value == Qt.CheckState.Checked)
            return True
        return False

    def breakpoint_at(self, row: int) -> Optional[Breakpoint]:
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None


class ConditionalBreakpointDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add Conditional Breakpoint")
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QFormLayout(self)

        self.kind_combo = QComboBox()
        self.kind_combo.addItems(["Register", "Flag"])
        self.kind_combo.currentIndexChanged.connect(self._on_kind_changed)
        layout.addRow("Type", self.kind_combo)

        self.name_combo = QComboBox()
        self.name_combo.addItems(list(REGISTER_ORDER))
        layout.addRow("Name", self.name_combo)

        self.value_edit = QLineEdit()
        self.value_edit.setPlaceholderText("0x10 or 16")
        layout.addRow("Value", self.value_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _on_kind_changed(self, index: int) -> None:
        self.name_combo.clear()
        if index == 0:
            self.name_combo.addItems(list(REGISTER_ORDER))
            self.value_edit.setPlaceholderText("0x10 or 16")
        else:
            self.name_combo.addItems(list(FLAG_ORDER))
            self.value_edit.setPlaceholderText("0 or 1")

    def get_data(self) -> Optional[tuple[str, str, int]]:
        if self.exec() != QDialog.DialogCode.Accepted:
            return None
        name = self.name_combo.currentText().strip().upper()
        raw = self.value_edit.text().strip()
        try:
            value = int(raw, 16) if raw.lower().startswith("0x") else int(raw, 10)
        except ValueError:
            QMessageBox.warning(self, "Invalid Value", "Value must be a decimal or hex number.")
            return None
        if self.kind_combo.currentText() == "Flag" and value not in (0, 1):
            QMessageBox.warning(self, "Invalid Flag Value", "Flags can only be 0 or 1.")
            return None
        return self.kind_combo.currentText(), name, value
