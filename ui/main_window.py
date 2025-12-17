from __future__ import annotations

import os
from typing import Optional

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import (
    QAction,
    QColor,
    QFont,
    QFontDatabase,
    QTextCharFormat,
    QSyntaxHighlighter,
    QTextCursor,
)
from PyQt6.QtWidgets import (
    QApplication,
    QDockWidget,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QSpinBox,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolButton,
    QToolBar,
    QVBoxLayout,
    QWidget,
    QTextEdit,
)

from core.cpu import CPUState, REGISTER_ORDER, clamp_u32
from core.emulator import Emulator, StepOutcome
from core.instructions import EmulationError, get_instruction_defs
from core.model import Program
from core.parser import ParseError, parse_assembly
from core.syscalls import get_syscall_defs


class AsmHighlighter(QSyntaxHighlighter):
    def __init__(self, parent) -> None:
        super().__init__(parent)
        self.mnemonic_format = QTextCharFormat()
        self.mnemonic_format.setForeground(QColor("#005f87"))
        self.mnemonic_format.setFontWeight(QFont.Weight.Bold)

        self.register_format = QTextCharFormat()
        self.register_format.setForeground(QColor("#5f005f"))

        self.number_format = QTextCharFormat()
        self.number_format.setForeground(QColor("#875f00"))

        self.comment_format = QTextCharFormat()
        self.comment_format.setForeground(QColor("#5f875f"))

        self.mnemonics = {d.mnemonic for d in get_instruction_defs()}
        self.registers = {name for name in REGISTER_ORDER}

    def highlightBlock(self, text: str) -> None:
        stripped = text.strip()
        if not stripped:
            return

        comment_index = text.find(";")
        if comment_index >= 0:
            self.setFormat(comment_index, len(text) - comment_index, self.comment_format)
            text = text[:comment_index]

        parts = text.strip().split(None, 1)
        if parts:
            mnemonic = parts[0].upper()
            if mnemonic in self.mnemonics:
                start = text.upper().find(mnemonic)
                self.setFormat(start, len(mnemonic), self.mnemonic_format)

        tokens = [tok.strip(" ,") for tok in text.replace(",", " ").split()]
        for tok in tokens:
            upper = tok.upper()
            if upper in self.registers:
                start = text.upper().find(upper)
                self.setFormat(start, len(tok), self.register_format)
            if tok.startswith("0x") or tok.lstrip("-").isdigit():
                start = text.find(tok)
                self.setFormat(start, len(tok), self.number_format)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ASM Debugger")
        self.resize(1200, 700)

        self.current_file: Optional[str] = None
        self.source_dirty = True
        self.updating_views = False
        self.run_state = "Ready"

        self.cpu = CPUState()
        self.program = Program(instructions=[], labels={})
        self.emulator = Emulator(self.cpu, self.program)
        self.icon_font_family, self.icon_map, self.icon_is_ligature = self._load_icon_font()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.on_timer_step)

        self._build_ui()
        self._update_views()
        self._update_status()

    def _build_ui(self) -> None:
        toolbar = QToolBar("Controls")
        self.addToolBar(toolbar)

        new_action = QAction("New", self)
        new_action.triggered.connect(self.new_file)
        toolbar.addAction(new_action)

        open_action = QAction("Open", self)
        open_action.triggered.connect(self.open_file)
        toolbar.addAction(open_action)

        save_action = QAction("Save", self)
        save_action.triggered.connect(self.save_file)
        toolbar.addAction(save_action)

        save_as_action = QAction("Save As", self)
        save_as_action.triggered.connect(self.save_file_as)
        toolbar.addAction(save_as_action)

        toolbar.addSeparator()

        toolbar.addSeparator()

        rate_label = QLabel("Steps/s")
        toolbar.addWidget(rate_label)
        self.rate_spin = QSpinBox()
        self.rate_spin.setRange(1, 1000)
        self.rate_spin.setValue(5)
        self.rate_spin.valueChanged.connect(self._update_timer_interval)
        toolbar.addWidget(self.rate_spin)

        central = QWidget()
        layout = QHBoxLayout(central)
        layout.setContentsMargins(8, 8, 8, 8)
        self.setCentralWidget(central)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(QLabel("Cheat Sheets"))

        self.cheat_tabs = QTabWidget()
        self.cheat_tabs.addTab(self._build_instruction_tab(), "Instructions")
        self.cheat_tabs.addTab(self._build_syscall_tab(), "Syscalls")
        left_layout.addWidget(self.cheat_tabs)
        layout.addWidget(left_panel, 1)

        center_panel = QWidget()
        center_layout = QVBoxLayout(center_panel)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.addWidget(QLabel("Assembly Editor"))
        center_layout.addWidget(self._build_center_controls())
        self.editor = QPlainTextEdit()
        self.editor.setFont(QFont("Consolas", 11))
        self.editor.textChanged.connect(self.on_text_changed)
        self.highlighter = AsmHighlighter(self.editor.document())
        center_layout.addWidget(self.editor)
        layout.addWidget(center_panel, 2)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)

        right_layout.addWidget(QLabel("Registers"))
        self.register_table = QTableWidget(len(REGISTER_ORDER), 2)
        self.register_table.setHorizontalHeaderLabels(["Register", "Value"])
        self.register_table.verticalHeader().setVisible(False)
        self.register_table.cellChanged.connect(self.on_register_edit)
        right_layout.addWidget(self.register_table)

        right_layout.addWidget(QLabel("Stack"))
        self.stack_table = QTableWidget(16, 3)
        self.stack_table.setHorizontalHeaderLabels(["Address", "Value", "Markers"])
        self.stack_table.verticalHeader().setVisible(False)
        self.stack_table.cellChanged.connect(self.on_stack_edit)
        right_layout.addWidget(self.stack_table)

        layout.addWidget(right_panel, 1)

        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        log_dock = QDockWidget("Log / Output", self)
        log_dock.setWidget(self.log_output)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, log_dock)

        self.syscall_output = QPlainTextEdit()
        self.syscall_output.setReadOnly(True)
        syscall_dock = QDockWidget("Syscall Output", self)
        syscall_dock.setWidget(self.syscall_output)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, syscall_dock)

        self.symbol_table = QTableWidget(0, 3)
        self.symbol_table.setHorizontalHeaderLabels(["Symbol", "Kind", "Address/Info"])
        self.symbol_table.verticalHeader().setVisible(False)
        self.symbol_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.symbol_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        symbol_dock = QDockWidget("Symbols", self)
        symbol_dock.setWidget(self.symbol_table)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, symbol_dock)

        self.memory_base = QLineEdit()
        self.memory_base.setPlaceholderText("0x00000000")
        self.memory_base.setText("0x00003000")
        self.memory_rows = QSpinBox()
        self.memory_rows.setRange(1, 256)
        self.memory_rows.setValue(16)
        self.memory_rows.valueChanged.connect(self._update_memory_view)
        self.memory_base.editingFinished.connect(self._update_memory_view)

        self.memory_table = QTableWidget(0, 3)
        self.memory_table.setHorizontalHeaderLabels(["Address", "Hex (16 bytes)", "ASCII"])
        self.memory_table.verticalHeader().setVisible(False)
        self.memory_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.memory_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

        memory_controls = QWidget()
        memory_layout = QHBoxLayout(memory_controls)
        memory_layout.setContentsMargins(0, 0, 0, 0)
        memory_layout.addWidget(QLabel("Base"))
        memory_layout.addWidget(self.memory_base)
        memory_layout.addWidget(QLabel("Rows"))
        memory_layout.addWidget(self.memory_rows)

        memory_panel = QWidget()
        memory_panel_layout = QVBoxLayout(memory_panel)
        memory_panel_layout.setContentsMargins(0, 0, 0, 0)
        memory_panel_layout.addWidget(memory_controls)
        memory_panel_layout.addWidget(self.memory_table)

        memory_dock = QDockWidget("Memory View", self)
        memory_dock.setWidget(memory_panel)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, memory_dock)

        status = QStatusBar()
        self.setStatusBar(status)
        self.state_label = QLabel("Ready")
        self.line_label = QLabel("Line: -")
        status.addWidget(self.state_label)
        status.addPermanentWidget(self.line_label)

    def _build_center_controls(self) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        self.play_button = QToolButton()
        self.pause_button = QToolButton()
        self.step_button = QToolButton()
        self.reset_button = QToolButton()

        self._configure_icon_button(self.play_button, "play", "Play")
        self._configure_icon_button(self.pause_button, "pause", "Pause")
        self._configure_icon_button(self.step_button, "step", "Step")
        self._configure_icon_button(self.reset_button, "reset", "Reset")

        self.play_button.clicked.connect(self.play)
        self.pause_button.clicked.connect(self.pause)
        self.step_button.clicked.connect(self.step_once)
        self.reset_button.clicked.connect(self.reset_state)

        layout.addWidget(self.play_button)
        layout.addWidget(self.pause_button)
        layout.addWidget(self.step_button)
        layout.addWidget(self.reset_button)
        return widget

    def _load_icon_font(self) -> tuple[Optional[str], dict[str, str], bool]:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        assets_dir = os.path.join(base_dir, "assets")

        candidates = [
            {
                "family": "Font Awesome 6 Free Solid",
                "files": ["FontAwesome6Free-Solid-900.otf", "fa-solid-900.ttf"],
                "map": {"play": "\uf04b", "pause": "\uf04c", "step": "\uf051", "reset": "\uf01e"},
                "ligature": False,
            },
            {
                "family": "Font Awesome 5 Free Solid",
                "files": ["fa-solid-900.ttf"],
                "map": {"play": "\uf04b", "pause": "\uf04c", "step": "\uf051", "reset": "\uf01e"},
                "ligature": False,
            },
            {
                "family": "FontAwesome",
                "files": ["fontawesome-webfont.ttf"],
                "map": {"play": "\uf04b", "pause": "\uf04c", "step": "\uf051", "reset": "\uf01e"},
                "ligature": False,
            },
            {
                "family": "Material Icons",
                "files": ["MaterialIcons-Regular.ttf"],
                "map": {"play": "play_arrow", "pause": "pause", "step": "skip_next", "reset": "restart_alt"},
                "ligature": True,
            },
            {
                "family": "Segoe MDL2 Assets",
                "files": [],
                "map": {"play": "\ue768", "pause": "\ue769", "step": "\ue72a", "reset": "\ue777"},
                "ligature": False,
            },
        ]

        for candidate in candidates:
            for filename in candidate["files"]:
                path = os.path.join(assets_dir, filename)
                if os.path.exists(path):
                    QFontDatabase.addApplicationFont(path)
            if candidate["family"] in QFontDatabase.families():
                return candidate["family"], candidate["map"], candidate["ligature"]
        return None, {}, False

    def _configure_icon_button(self, button: QToolButton, name: str, fallback: str) -> None:
        button.setAutoRaise(True)
        button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        button.setToolTip(fallback)
        if self.icon_font_family and name in self.icon_map:
            font = QFont(self.icon_font_family)
            font.setPointSize(14)
            button.setFont(font)
            button.setText(self.icon_map[name])
        else:
            button.setText(fallback)

    def _populate_cheat_sheet(self) -> None:
        defs = get_instruction_defs()
        self.cheat_table.setRowCount(len(defs))
        for row, defn in enumerate(defs):
            self.cheat_table.setItem(row, 0, QTableWidgetItem(defn.mnemonic))
            self.cheat_table.setItem(row, 1, QTableWidgetItem(defn.meaning))
            self.cheat_table.setItem(row, 2, QTableWidgetItem(defn.description))
            self.cheat_table.setItem(row, 3, QTableWidgetItem(defn.syntax))
            self.cheat_table.setItem(row, 4, QTableWidgetItem(defn.flags))
        self.cheat_table.resizeColumnsToContents()

    def filter_cheat_sheet(self, text: str) -> None:
        query = text.strip().lower()
        for row in range(self.cheat_table.rowCount()):
            matches = False
            for col in range(self.cheat_table.columnCount()):
                item = self.cheat_table.item(row, col)
                if item and query in item.text().lower():
                    matches = True
                    break
            self.cheat_table.setRowHidden(row, not matches if query else False)

    def _populate_syscall_sheet(self) -> None:
        defs = get_syscall_defs()
        self.syscall_table.setRowCount(len(defs))
        for row, defn in enumerate(defs):
            number_text = f"{defn.number} (0x{defn.number:X})"
            self.syscall_table.setItem(row, 0, QTableWidgetItem(number_text))
            self.syscall_table.setItem(row, 1, QTableWidgetItem(defn.name))
            self.syscall_table.setItem(row, 2, QTableWidgetItem(defn.description))
            self.syscall_table.setItem(row, 3, QTableWidgetItem(defn.args))
            self.syscall_table.setItem(row, 4, QTableWidgetItem(defn.returns))
        self.syscall_table.resizeColumnsToContents()

    def filter_syscall_sheet(self, text: str) -> None:
        query = text.strip().lower()
        for row in range(self.syscall_table.rowCount()):
            matches = False
            for col in range(self.syscall_table.columnCount()):
                item = self.syscall_table.item(row, col)
                if item and query in item.text().lower():
                    matches = True
                    break
            self.syscall_table.setRowHidden(row, not matches if query else False)

    def _build_instruction_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        self.cheat_search = QLineEdit()
        self.cheat_search.setPlaceholderText("Search instructions...")
        self.cheat_search.textChanged.connect(self.filter_cheat_sheet)
        layout.addWidget(self.cheat_search)

        self.cheat_table = QTableWidget(0, 5)
        self.cheat_table.setHorizontalHeaderLabels(
            ["Mnemonic", "Meaning", "Description", "Syntax", "Flags"]
        )
        self.cheat_table.verticalHeader().setVisible(False)
        self.cheat_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.cheat_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.cheat_table)
        self._populate_cheat_sheet()
        return widget

    def _build_syscall_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        self.syscall_search = QLineEdit()
        self.syscall_search.setPlaceholderText("Search syscalls...")
        self.syscall_search.textChanged.connect(self.filter_syscall_sheet)
        layout.addWidget(self.syscall_search)

        self.syscall_table = QTableWidget(0, 5)
        self.syscall_table.setHorizontalHeaderLabels(
            ["Number", "Name", "Description", "Args", "Returns"]
        )
        self.syscall_table.verticalHeader().setVisible(False)
        self.syscall_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.syscall_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.syscall_table)
        self._populate_syscall_sheet()
        return widget

    def on_text_changed(self) -> None:
        self.source_dirty = True

    def new_file(self) -> None:
        self.editor.clear()
        self.current_file = None
        self.source_dirty = True
        self.setWindowTitle("ASM Debugger")
        self.log("New file created.")

    def open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open .asm", "", "ASM Files (*.asm);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as file:
                self.editor.setPlainText(file.read())
            self.current_file = path
            self.source_dirty = True
            self.setWindowTitle(f"ASM Debugger - {path}")
            self.log(f"Opened {path}")
        except OSError as exc:
            QMessageBox.warning(self, "Open Failed", str(exc))

    def save_file(self) -> None:
        if not self.current_file:
            self.save_file_as()
            return
        try:
            with open(self.current_file, "w", encoding="utf-8") as file:
                file.write(self.editor.toPlainText())
            self.source_dirty = False
            self.log(f"Saved {self.current_file}")
        except OSError as exc:
            QMessageBox.warning(self, "Save Failed", str(exc))

    def save_file_as(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save .asm", "", "ASM Files (*.asm);;All Files (*)")
        if not path:
            return
        self.current_file = path
        self.save_file()
        self.setWindowTitle(f"ASM Debugger - {path}")

    def parse_current_program(self) -> bool:
        try:
            program = parse_assembly(self.editor.toPlainText())
        except ParseError as exc:
            self.set_state("Error")
            self.log(f"Parse error (line {exc.line_no}): {exc.message}")
            self.log(f"  {exc.text}")
            return False

        self.program = program
        self.cpu.reset()
        self.cpu.load_data(self.program.data_bytes)
        if self.program.entry_point is not None:
            self.cpu.set_reg("EIP", self.program.entry_point)
        self.emulator = Emulator(self.cpu, self.program)
        self.source_dirty = False
        self._populate_symbols()
        self.set_state("Ready")
        self._update_views()
        return True

    def play(self) -> None:
        if not self.ensure_program():
            return
        if self.emulator.halted:
            self.log("Execution halted. Reset to run again.")
            return
        self.set_state("Running")
        self._update_timer_interval()
        self.timer.start()

    def pause(self) -> None:
        self.timer.stop()
        if self.run_state == "Running":
            self.set_state("Paused")

    def step_once(self) -> None:
        self.timer.stop()
        if not self.ensure_program():
            return
        if self.emulator.halted:
            self.log("Execution halted. Reset to run again.")
            self.set_state("Halted")
            return
        outcome = self.emulator.step()
        self.handle_step_outcome(outcome)
        self._update_views()
        if not outcome.error and not outcome.halted:
            self.set_state("Paused")

    def on_timer_step(self) -> None:
        outcome = self.emulator.step()
        self.handle_step_outcome(outcome)
        self._update_views()
        if outcome.error or outcome.halted:
            self.timer.stop()

    def handle_step_outcome(self, outcome: StepOutcome) -> None:
        if outcome.output:
            self.syscall_output.appendPlainText(outcome.output)
        if outcome.error:
            self.set_state("Error")
            self.log(f"HALT due to error: {outcome.error.message}")
            self.log(f"Line {outcome.error.line_no}: {outcome.error.text}")
            self.emulator.halted = True
            return
        if outcome.halted:
            self.set_state("Halted")
            self.log("Program halted.")

    def reset_state(self) -> None:
        self.timer.stop()
        self.cpu.reset()
        self.cpu.load_data(self.program.data_bytes)
        if self.program.entry_point is not None:
            self.cpu.set_reg("EIP", self.program.entry_point)
        self.emulator = Emulator(self.cpu, self.program)
        self.set_state("Ready")
        self._update_views()
        self.log("CPU state reset.")

    def ensure_program(self) -> bool:
        if self.source_dirty or not self.program.instructions:
            return self.parse_current_program()
        return True

    def _update_timer_interval(self) -> None:
        steps = self.rate_spin.value()
        interval_ms = max(1, int(1000 / steps))
        self.timer.setInterval(interval_ms)

    def _update_views(self) -> None:
        self.updating_views = True
        try:
            self._update_register_view()
            self._update_stack_view()
            self._update_memory_view()
            self._highlight_current_line()
            self._update_status()
        finally:
            self.updating_views = False

    def _update_register_view(self) -> None:
        for row, reg in enumerate(REGISTER_ORDER):
            name_item = QTableWidgetItem(reg)
            name_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.register_table.setItem(row, 0, name_item)
            value = self.cpu.get_reg(reg)
            value_item = QTableWidgetItem(f"0x{value:08X}")
            value_item.setData(Qt.ItemDataRole.UserRole, reg)
            value_item.setToolTip(str(value))
            self.register_table.setItem(row, 1, value_item)
        self.register_table.resizeColumnsToContents()

    def _update_stack_view(self) -> None:
        esp = self.cpu.get_reg("ESP")
        ebp = self.cpu.get_reg("EBP")
        base = clamp_u32(esp - 32)
        rows = self.stack_table.rowCount()
        for i in range(rows):
            addr = clamp_u32(base + i * 4)
            value = self.cpu.read_mem(addr, 4)
            addr_item = QTableWidgetItem(f"0x{addr:08X}")
            addr_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            value_item = QTableWidgetItem(f"0x{value:08X}")
            value_item.setData(Qt.ItemDataRole.UserRole, addr)
            marker_text = []
            if addr == esp:
                marker_text.append("ESP")
            if addr == ebp:
                marker_text.append("EBP")
            marker_item = QTableWidgetItem(", ".join(marker_text))
            marker_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.stack_table.setItem(i, 0, addr_item)
            self.stack_table.setItem(i, 1, value_item)
            self.stack_table.setItem(i, 2, marker_item)
            if addr == esp:
                highlight = QColor("#ffd6d6")
                addr_item.setBackground(highlight)
                value_item.setBackground(highlight)
                marker_item.setBackground(highlight)
        self.stack_table.resizeColumnsToContents()

    def _populate_symbols(self) -> None:
        rows = []
        for name, addr in sorted(self.program.labels.items()):
            kind = "code label"
            if name in self.program.globals:
                kind = "global code label"
            rows.append((name, kind, str(addr)))
        for name, addr in sorted(self.program.data_labels.items()):
            kind = "data label"
            if name in self.program.globals:
                kind = "global data label"
            rows.append((name, kind, f"0x{addr:08X}"))
        for name in sorted(self.program.externs):
            kind = "extern"
            info = "external symbol"
            rows.append((name, kind, info))

        self.symbol_table.setRowCount(len(rows))
        for row, (name, kind, info) in enumerate(rows):
            self.symbol_table.setItem(row, 0, QTableWidgetItem(name))
            self.symbol_table.setItem(row, 1, QTableWidgetItem(kind))
            self.symbol_table.setItem(row, 2, QTableWidgetItem(info))
        self.symbol_table.resizeColumnsToContents()

    def _update_memory_view(self) -> None:
        try:
            base = self._parse_value(self.memory_base.text())
        except ValueError:
            if not self.updating_views:
                self.log("Invalid memory base address.")
            return
        rows = self.memory_rows.value()
        self.memory_table.setRowCount(rows)
        for row in range(rows):
            addr = clamp_u32(base + row * 16)
            data = self.cpu.read_bytes(addr, 16)
            hex_bytes = " ".join(f"{b:02X}" for b in data)
            ascii_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
            self.memory_table.setItem(row, 0, QTableWidgetItem(f"0x{addr:08X}"))
            self.memory_table.setItem(row, 1, QTableWidgetItem(hex_bytes))
            self.memory_table.setItem(row, 2, QTableWidgetItem(ascii_text))
        self.memory_table.resizeColumnsToContents()

    def _highlight_current_line(self) -> None:
        selections = []
        if self.program.instructions:
            eip = self.cpu.get_reg("EIP")
            if 0 <= eip < len(self.program.instructions):
                line_no = self.program.instructions[eip].line_no
                block = self.editor.document().findBlockByNumber(line_no - 1)
                if block.isValid():
                    cursor = QTextCursor(block)
                    cursor.select(QTextCursor.SelectionType.LineUnderCursor)
                    selection = QTextEdit.ExtraSelection()
                    selection.cursor = cursor
                    selection.format.setBackground(QColor("#fff2cc"))
                    selections.append(selection)
        self.editor.setExtraSelections(selections)

    def _update_status(self) -> None:
        self.state_label.setText(self.run_state)
        if self.program.instructions:
            eip = self.cpu.get_reg("EIP")
            if 0 <= eip < len(self.program.instructions):
                line_no = self.program.instructions[eip].line_no
                self.line_label.setText(f"Line: {line_no} | EIP: {eip}")
                return
        self.line_label.setText("Line: -")

    def set_state(self, state: str) -> None:
        self.run_state = state
        self._update_status()

    def log(self, message: str) -> None:
        self.log_output.appendPlainText(message)

    def on_register_edit(self, row: int, column: int) -> None:
        if self.updating_views or column != 1:
            return
        item = self.register_table.item(row, column)
        if not item:
            return
        reg = item.data(Qt.ItemDataRole.UserRole)
        if not reg:
            return
        try:
            value = self._parse_value(item.text())
        except ValueError:
            self.log("Invalid register value.")
            self._update_register_view()
            return
        self.cpu.set_reg(reg, value)
        self._update_views()

    def on_stack_edit(self, row: int, column: int) -> None:
        if self.updating_views or column != 1:
            return
        item = self.stack_table.item(row, column)
        if not item:
            return
        addr = item.data(Qt.ItemDataRole.UserRole)
        if addr is None:
            return
        try:
            value = self._parse_value(item.text())
        except ValueError:
            self.log("Invalid stack value.")
            self._update_stack_view()
            return
        self.cpu.write_mem(int(addr), 4, value)
        self._update_stack_view()

    def _parse_value(self, text: str) -> int:
        raw = text.strip()
        if raw.lower().startswith("0x"):
            return int(raw, 16)
        return int(raw, 10)


def run_app() -> None:
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()
