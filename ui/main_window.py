from __future__ import annotations

import os
import json
from typing import Optional

from PyQt6.QtCore import Qt, QEvent, QTimer, QRect, QSize, pyqtSignal
from PyQt6.QtGui import (
    QAction,
    QColor,
    QFont,
    QFontDatabase,
    QIcon,
    QKeySequence,
    QPainter,
    QPixmap,
    QTextCharFormat,
    QPalette,
    QShortcut,
    QSyntaxHighlighter,
    QTextCursor,
)
from PyQt6.QtWidgets import (
    QApplication,
    QDockWidget,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QHeaderView,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QComboBox,
    QSpinBox,
    QStatusBar,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolButton,
    QStyle,
    QSplitter,
    QVBoxLayout,
    QWidget,
    QTextEdit,
    QAbstractItemView,
    QAbstractScrollArea,
    QSizePolicy,
)

from core.cpu import CPUState, REGISTER_ORDER, clamp_u32
from core.emulator import Emulator, StepOutcome
from core.instructions import get_instruction_defs
from core.model import Program
from core.parser import ParseError, parse_assembly
from core.syscalls import get_syscall_defs
from ui.breakpoints import (
    BreakpointManager,
    BreakpointsTableModel,
    BreakpointType,
    ConditionalBreakpointDialog,
)

FLAG_ORDER = ["ZF", "SF", "CF", "OF"]


class AsmHighlighter(QSyntaxHighlighter):
    def __init__(self, parent) -> None:
        super().__init__(parent)
        self.mnemonic_format = QTextCharFormat()
        self.mnemonic_format.setForeground(QColor("#ff79c6"))
        self.mnemonic_format.setFontWeight(QFont.Weight.Bold)

        self.register_format = QTextCharFormat()
        self.register_format.setForeground(QColor("#bd93f9"))

        self.number_format = QTextCharFormat()
        self.number_format.setForeground(QColor("#ffb86c"))

        self.comment_format = QTextCharFormat()
        self.comment_format.setForeground(QColor("#6272a4"))

        self.size_format = QTextCharFormat()
        self.size_format.setForeground(QColor("#8be9fd"))
        self.size_format.setFontWeight(QFont.Weight.Medium)

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
            if upper in {"BYTE", "WORD", "DWORD", "QWORD", "PTR"}:
                start = text.upper().find(upper)
                self.setFormat(start, len(tok), self.size_format)
            if upper in self.registers:
                start = text.upper().find(upper)
                self.setFormat(start, len(tok), self.register_format)
            if tok.startswith("0x") or tok.lstrip("-").isdigit():
                start = text.find(tok)
                self.setFormat(start, len(tok), self.number_format)


class LineNumberArea(QWidget):
    def __init__(self, editor: "CodeEditor") -> None:
        super().__init__(editor)
        self.editor = editor

    def sizeHint(self) -> QSize:
        return QSize(self.editor.line_number_area_width(), 0)

    def paintEvent(self, event) -> None:
        self.editor.line_number_area_paint_event(event)

    def mousePressEvent(self, event) -> None:
        self.editor.line_number_area_mouse_event(event)


class CodeEditor(QPlainTextEdit):
    breakpoint_toggle_requested = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._line_number_bg = QColor("#1e1f29")
        self._line_number_fg = QColor("#6272a4")
        self._breakpoint_area_width = 14
        self._breakpoint_enabled_color = QColor("#ff5555")
        self._breakpoint_disabled_color = QColor("#6272a4")
        self._breakpoint_temporary_color = QColor("#ffb86c")
        self.breakpoint_manager: Optional[BreakpointManager] = None
        self.current_file: Optional[str] = None
        self.line_number_area = LineNumberArea(self)

        self.blockCountChanged.connect(self.update_line_number_area_width)
        self.updateRequest.connect(self.update_line_number_area)
        self.update_line_number_area_width(0)

    def set_line_number_colors(self, background: QColor, foreground: QColor) -> None:
        self._line_number_bg = background
        self._line_number_fg = foreground
        self.line_number_area.update()

    def line_number_area_width(self) -> int:
        digits = max(1, len(str(self.blockCount())))
        return self._breakpoint_area_width + 10 + self.fontMetrics().horizontalAdvance("9") * digits

    def set_breakpoint_manager(self, manager: Optional[BreakpointManager]) -> None:
        self.breakpoint_manager = manager
        self.line_number_area.update()

    def set_current_file(self, path: Optional[str]) -> None:
        self.current_file = path
        self.line_number_area.update()

    def update_line_number_area_width(self, _block_count: int) -> None:
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def update_line_number_area(self, rect: QRect, dy: int) -> None:
        if dy:
            self.line_number_area.scroll(0, dy)
        else:
            self.line_number_area.update(0, rect.y(), self.line_number_area.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self.update_line_number_area_width(0)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        contents = self.contentsRect()
        self.line_number_area.setGeometry(
            QRect(contents.left(), contents.top(), self.line_number_area_width(), contents.height())
        )

    def line_number_area_paint_event(self, event) -> None:
        painter = QPainter(self.line_number_area)
        painter.fillRect(event.rect(), self._line_number_bg)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        line_breakpoints = {}
        if self.breakpoint_manager and self.current_file:
            for bp in self.breakpoint_manager.get_line_breakpoints(self.current_file):
                if bp.line is None:
                    continue
                if bp.type == BreakpointType.TEMPORARY_LINE or bp.line not in line_breakpoints:
                    line_breakpoints[bp.line] = bp

        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = self.blockBoundingGeometry(block).translated(self.contentOffset()).top()
        bottom = top + self.blockBoundingRect(block).height()

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)
                line_no = block_number + 1
                bp = line_breakpoints.get(line_no)
                if bp:
                    radius = 5
                    center_x = self._breakpoint_area_width // 2
                    center_y = int(top + (self.fontMetrics().height() / 2))
                    if not bp.enabled:
                        painter.setPen(self._breakpoint_disabled_color)
                        painter.setBrush(Qt.BrushStyle.NoBrush)
                    else:
                        color = (
                            self._breakpoint_temporary_color
                            if bp.type == BreakpointType.TEMPORARY_LINE
                            else self._breakpoint_enabled_color
                        )
                        painter.setPen(color)
                        painter.setBrush(color)
                    painter.drawEllipse(center_x - radius, center_y - radius, radius * 2, radius * 2)
                painter.setPen(self._line_number_fg)
                painter.drawText(
                    self._breakpoint_area_width,
                    int(top),
                    self.line_number_area.width() - self._breakpoint_area_width - 6,
                    int(self.fontMetrics().height()),
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                    number,
                )
            block = block.next()
            top = bottom
            bottom = top + self.blockBoundingRect(block).height()
            block_number += 1

    def line_number_area_mouse_event(self, event) -> None:
        if event.button() != Qt.MouseButton.LeftButton:
            return
        y = event.position().y()
        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = self.blockBoundingGeometry(block).translated(self.contentOffset()).top()
        bottom = top + self.blockBoundingRect(block).height()
        while block.isValid() and top <= y:
            if block.isVisible() and bottom >= y:
                self.breakpoint_toggle_requested.emit(block_number + 1)
                return
            block = block.next()
            top = bottom
            bottom = top + self.blockBoundingRect(block).height()
            block_number += 1


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ASM Debugger")
        self.resize(1200, 700)

        self.current_file: Optional[str] = None
        self.source_dirty = True
        self.updating_views = False
        self.run_state = "Ready"
        self.prev_registers: dict[str, int] = {}
        self.prev_stack_values: dict[int, int] = {}
        self.execution_mode = "Freestanding"
        self._skip_breakpoint_id: Optional[int] = None
        self.recent_files: list[str] = []
        self._max_recent_files = 10

        self.cpu = CPUState()
        self.program = Program(instructions=[], labels={})
        self.emulator = Emulator(self.cpu, self.program)
        self.icon_font_family, self.icon_map, self.icon_is_ligature = self._load_icon_font()
        self.breakpoint_manager = BreakpointManager()
        self._pinnable_panels: dict[QWidget, bool] = {}
        self._panel_contents: dict[QWidget, QWidget] = {}
        self._panel_restore_sizes: dict[QWidget, int] = {}
        self._panel_splitters: dict[QWidget, QSplitter] = {}
        self._panel_widget_map: dict[QWidget, QWidget] = {}
        self._panel_pin_buttons: dict[QWidget, QToolButton] = {}
        self._panel_headers: dict[QWidget, QWidget] = {}
        self._panel_collapse_buttons: dict[QWidget, QWidget] = {}
        self._panel_view_actions: dict[QWidget, QAction] = {}
        self._panel_names: dict[QWidget, str] = {}
        self._panel_axes: dict[QWidget, str] = {}
        self._collapsed_panel_size = 72
        self._collapsed_panel_height = 48
        self._pending_pinned_state: Optional[dict[str, bool]] = None
        self._pin_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_TitleBarUnshadeButton)
        self._unpin_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_TitleBarShadeButton)
        self._close_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_TitleBarCloseButton)
        self._collapse_left_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowRight)
        self._collapse_right_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowLeft)
        self._collapse_bottom_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowUp)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.on_timer_step)

        self._build_ui()
        self._setup_shortcuts()
        self._update_views()
        self._update_status()
        self._load_layout()
        self._load_breakpoints()
        QApplication.instance().focusChanged.connect(self._on_focus_changed)

    def _resolve_entry_point(self) -> int | None:
        if self.program.entry_point is not None:
            return self.program.entry_point
        if self.execution_mode == "Snippet":
            return 0
        return None

    def _setup_shortcuts(self) -> None:
        self.shortcuts: list[QShortcut] = []

        shortcut_map = [
            ("F5", self.play),
            ("Shift+F5", self.pause),
            ("F9", self.toggle_breakpoint_at_cursor),
            ("F10", self.step_once),
            ("Ctrl+Shift+F5", self.reset_state),
            ("Ctrl+Alt+B", self._show_breakpoints_dock),
            ("PgUp", lambda: self._adjust_step_rate(1)),
            ("PgDown", lambda: self._adjust_step_rate(-1)),
        ]
        for sequence, handler in shortcut_map:
            shortcut = QShortcut(QKeySequence(sequence), self)
            shortcut.activated.connect(handler)
            self.shortcuts.append(shortcut)

    def _build_panel_header(self, title: str, panel: QWidget) -> QWidget:
        header = QWidget()
        layout = QHBoxLayout(header)
        layout.setContentsMargins(4, 4, 4, 0)
        label = QLabel(title)
        layout.addWidget(label)
        layout.addStretch(1)

        pin_button = QToolButton()
        pin_button.setCheckable(True)
        pin_button.setChecked(True)
        pin_button.setAutoRaise(True)
        pin_button.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._set_pin_button_state(pin_button, True)
        pin_button.toggled.connect(lambda checked, p=panel: self._set_panel_pinned(p, checked))
        layout.addWidget(pin_button)

        close_button = QToolButton()
        close_button.setAutoRaise(True)
        close_button.setIcon(self._close_icon)
        close_button.setToolTip("Close panel")
        close_button.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        close_button.clicked.connect(lambda checked=False, p=panel: self._close_panel(p))
        layout.addWidget(close_button)

        self._panel_pin_buttons[panel] = pin_button
        self._panel_headers[panel] = header
        self._panel_widget_map[header] = panel
        header.installEventFilter(self)
        return header

    def _tinted_icon(self, icon: QIcon, color: QColor, size: int = 18) -> QIcon:
        if icon.isNull():
            return icon
        pixmap = icon.pixmap(size, size)
        if pixmap.isNull():
            return icon
        tinted = QPixmap(pixmap.size())
        tinted.fill(Qt.GlobalColor.transparent)
        painter = QPainter(tinted)
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Source)
        painter.drawPixmap(0, 0, pixmap)
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
        painter.fillRect(tinted.rect(), color)
        painter.end()
        return QIcon(tinted)

    def _build_panel_collapse_button(
        self, title: str, panel: QWidget, icon: QIcon, orientation: str = "horizontal"
    ) -> QWidget:
        container = QWidget()
        if orientation == "vertical":
            layout = QHBoxLayout(container)
            layout.setContentsMargins(8, 4, 8, 4)
            container.setMinimumHeight(self._collapsed_panel_height)
            button = QToolButton()
            button.setAutoRaise(True)
            button.setIcon(self._tinted_icon(icon, QColor("#f8f8f2")))
            button.setIconSize(QSize(18, 18))
            button.setText(title)
            button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
            button.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
            font = button.font()
            font.setWeight(QFont.Weight.DemiBold)
            button.setFont(font)
            button.setStyleSheet(
                "QToolButton { background: #2f4f6f; color: #f8f8f2; border-radius: 4px; padding: 6px 14px; text-align: left; }"
                "QToolButton::icon { margin-right: 8px; }"
                "QToolButton:hover { background: #3a5b7f; }"
            )
            button.setToolTip(f"Show {title}")
            button.clicked.connect(lambda checked=False, p=panel: self._expand_panel(p))
            layout.addStretch(1)
            layout.addWidget(button, alignment=Qt.AlignmentFlag.AlignCenter)
            layout.addStretch(1)
        else:
            layout = QVBoxLayout(container)
            layout.setContentsMargins(0, 0, 0, 0)
            container.setMinimumWidth(self._collapsed_panel_size)
            layout.addStretch(1)
            button = QToolButton()
            button.setAutoRaise(True)
            button.setIcon(self._tinted_icon(icon, QColor("#f8f8f2")))
            button.setIconSize(QSize(20, 20))
            button.setText("\n".join(title))
            button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextUnderIcon)
            button.setMinimumHeight(120)
            button.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
            font = button.font()
            font.setWeight(QFont.Weight.DemiBold)
            button.setFont(font)
            button.setStyleSheet(
                "QToolButton { background: #2f4f6f; color: #f8f8f2; border-radius: 4px; padding: 6px; }"
                "QToolButton:hover { background: #3a5b7f; }"
            )
            button.setToolTip(f"Show {title}")
            button.clicked.connect(lambda checked=False, p=panel: self._expand_panel(p))
            layout.addWidget(button, alignment=Qt.AlignmentFlag.AlignCenter)
            layout.addStretch(1)
        container.setVisible(False)

        self._panel_collapse_buttons[panel] = container
        self._panel_widget_map[container] = panel
        self._panel_widget_map[button] = panel
        container.installEventFilter(self)
        button.installEventFilter(self)
        return container

    def _set_pin_button_state(self, button: QToolButton, pinned: bool) -> None:
        if pinned:
            icon = self._pin_icon
            tooltip = "Pin panel"
        else:
            icon = self._unpin_icon
            tooltip = "Unpin panel"
        button.setIcon(icon)
        button.setText("")
        button.setToolTip(tooltip)

    def _register_pinnable_panel(
        self, panel: QWidget, content: QWidget, splitter: QSplitter, name: str, axis: str = "horizontal"
    ) -> None:
        self._pinnable_panels[panel] = True
        self._panel_contents[panel] = content
        self._panel_splitters[panel] = splitter
        self._panel_names[panel] = name
        self._panel_axes[panel] = axis
        for widget in (panel, content):
            self._panel_widget_map[widget] = panel
            widget.installEventFilter(self)
        header = self._panel_headers.get(panel)
        collapse_button = self._panel_collapse_buttons.get(panel)
        for widget in (header, collapse_button):
            if widget is None:
                continue
            self._panel_widget_map[widget] = panel
            widget.installEventFilter(self)

    def _set_panel_pinned(self, panel: QWidget, pinned: bool) -> None:
        self._pinnable_panels[panel] = pinned
        button = self._panel_pin_buttons.get(panel)
        if button is not None:
            if button.isChecked() != pinned:
                button.blockSignals(True)
                button.setChecked(pinned)
                button.blockSignals(False)
            self._set_pin_button_state(button, pinned)
        if pinned:
            self._expand_panel(panel)
        else:
            self._maybe_collapse_panel(panel)

    def _close_panel(self, panel: QWidget) -> None:
        panel.setVisible(False)
        action = self._panel_view_actions.get(panel)
        if action is not None:
            action.setChecked(False)

    def _set_splitter_size(self, splitter: QSplitter, panel: QWidget, size: int) -> None:
        index = splitter.indexOf(panel)
        if index == -1:
            return
        sizes = splitter.sizes()
        if index >= len(sizes):
            return
        sizes[index] = size
        splitter.setSizes(sizes)

    def _collapse_panel(self, panel: QWidget) -> None:
        if panel not in self._panel_contents:
            return
        axis = self._panel_axes.get(panel, "horizontal")
        if axis == "vertical":
            size_value = panel.height()
        else:
            size_value = panel.width()
        if size_value > 0:
            self._panel_restore_sizes[panel] = size_value
        content = self._panel_contents[panel]
        content.setVisible(False)
        header = self._panel_headers.get(panel)
        if header is not None:
            header.setVisible(False)
        collapse_button = self._panel_collapse_buttons.get(panel)
        target_size = self._collapsed_panel_height if axis == "vertical" else self._collapsed_panel_size
        if collapse_button is not None:
            collapse_button.setVisible(True)
            hint = collapse_button.sizeHint().height() if axis == "vertical" else collapse_button.sizeHint().width()
            target_size = max(target_size, hint)
        if axis == "vertical":
            panel.setMinimumHeight(target_size)
            panel.setMaximumHeight(target_size)
        else:
            panel.setMinimumWidth(target_size)
            panel.setMaximumWidth(target_size)
        splitter = self._panel_splitters.get(panel)
        if splitter is not None:
            self._set_splitter_size(splitter, panel, target_size)
        panel.updateGeometry()
        panel.update()

    def _expand_panel(self, panel: QWidget) -> None:
        if panel not in self._panel_contents:
            return
        content = self._panel_contents[panel]
        axis = self._panel_axes.get(panel, "horizontal")
        if axis == "vertical":
            panel.setMinimumHeight(0)
            panel.setMaximumHeight(16777215)
        else:
            panel.setMinimumWidth(0)
            panel.setMaximumWidth(16777215)
        content.setVisible(True)
        header = self._panel_headers.get(panel)
        if header is not None:
            header.setVisible(True)
        collapse_button = self._panel_collapse_buttons.get(panel)
        if collapse_button is not None:
            collapse_button.setVisible(False)
        splitter = self._panel_splitters.get(panel)
        if splitter is not None:
            size_hint = panel.sizeHint().height() if axis == "vertical" else panel.sizeHint().width()
            size = self._panel_restore_sizes.get(panel, size_hint)
            self._set_splitter_size(splitter, panel, size)
        if not self._pinnable_panels.get(panel, True):
            pin_button = self._panel_pin_buttons.get(panel)
            if pin_button is not None:
                pin_button.setFocus(Qt.FocusReason.OtherFocusReason)

    def _maybe_collapse_panel(self, panel: QWidget) -> None:
        if self._pinnable_panels.get(panel, True):
            return
        if not panel.isVisible():
            return
        focus = self.focusWidget()
        if focus is not None and (focus is panel or panel.isAncestorOf(focus)):
            return
        self._collapse_panel(panel)

    def _on_panel_visibility_changed(self, panel: QWidget, visible: bool) -> None:
        if not visible:
            return
        if self._pinnable_panels.get(panel, True):
            self._expand_panel(panel)
        else:
            self._maybe_collapse_panel(panel)

    def eventFilter(self, obj, event) -> bool:
        panel = self._panel_widget_map.get(obj)
        if panel is not None and not self._pinnable_panels.get(panel, True):
            event_type = event.type()
            if event_type == QEvent.Type.FocusIn:
                self._expand_panel(panel)
            elif event_type == QEvent.Type.FocusOut:
                QTimer.singleShot(0, lambda p=panel: self._maybe_collapse_panel(p))
        return super().eventFilter(obj, event)

    def _on_focus_changed(self, old, new) -> None:
        if old is None:
            return
        for panel, pinned in self._pinnable_panels.items():
            if pinned:
                continue
            if old is panel or panel.isAncestorOf(old):
                if new is None or not (new is panel or panel.isAncestorOf(new)):
                    self._maybe_collapse_panel(panel)

    def _rebuild_recent_menu(self) -> None:
        self.open_recent_menu.clear()
        if not self.recent_files:
            empty_action = QAction("No recent files", self)
            empty_action.setEnabled(False)
            self.open_recent_menu.addAction(empty_action)
            return
        for path in self.recent_files:
            action = QAction(path, self)
            action.triggered.connect(lambda checked=False, p=path: self._open_recent_path(p))
            self.open_recent_menu.addAction(action)
        self.open_recent_menu.addSeparator()
        clear_action = QAction("Clear Recent", self)
        clear_action.triggered.connect(self.clear_recent_files)
        self.open_recent_menu.addAction(clear_action)

    def _add_recent_file(self, path: str) -> None:
        if not path:
            return
        if path in self.recent_files:
            self.recent_files.remove(path)
        self.recent_files.insert(0, path)
        if len(self.recent_files) > self._max_recent_files:
            self.recent_files = self.recent_files[: self._max_recent_files]
        self._rebuild_recent_menu()

    def _remove_recent_file(self, path: str) -> None:
        if path in self.recent_files:
            self.recent_files.remove(path)
            self._rebuild_recent_menu()

    def _open_recent_path(self, path: str) -> None:
        if not os.path.exists(path):
            QMessageBox.warning(self, "Open Failed", f"File not found: {path}")
            self._remove_recent_file(path)
            return
        self._open_file_path(path)

    def clear_recent_files(self) -> None:
        self.recent_files = []
        self._rebuild_recent_menu()

    def _show_breakpoints_dock(self) -> None:
        if self.breakpoints_dock is None:
            return
        self.breakpoints_dock.setVisible(True)
        self.breakpoints_dock.raise_()

    def _on_mode_changed(self, index: int) -> None:
        self.execution_mode = "Snippet" if index == 1 else "Freestanding"
        self.log(f"Mode set to {self.execution_mode}.")
        self._update_views()

    def _build_ui(self) -> None:
        self.file_menu = self.menuBar().addMenu("File")
        self.debug_menu = self.menuBar().addMenu("Debug")
        self.view_menu = self.menuBar().addMenu("View")

        new_action = QAction("New", self)
        new_action.triggered.connect(self.new_file)
        self.file_menu.addAction(new_action)

        open_action = QAction("Open", self)
        open_action.triggered.connect(self.open_file)
        self.file_menu.addAction(open_action)

        self.open_recent_menu = self.file_menu.addMenu("Open Recent")
        self._rebuild_recent_menu()

        save_action = QAction("Save", self)
        save_action.triggered.connect(self.save_file)
        self.file_menu.addAction(save_action)

        save_as_action = QAction("Save As", self)
        save_as_action.triggered.connect(self.save_file_as)
        self.file_menu.addAction(save_as_action)

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        self.file_menu.addAction(exit_action)

        toggle_bp_action = QAction("Toggle Breakpoint", self)
        toggle_bp_action.triggered.connect(self.toggle_breakpoint_at_cursor)
        self.debug_menu.addAction(toggle_bp_action)

        break_here_action = QAction("Break Here", self)
        break_here_action.triggered.connect(self.break_here)
        self.debug_menu.addAction(break_here_action)

        conditional_bp_action = QAction("Add Conditional Breakpoint...", self)
        conditional_bp_action.triggered.connect(self.add_conditional_breakpoint)
        self.debug_menu.addAction(conditional_bp_action)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(8, 8, 8, 8)

        left_header = self._build_panel_header("Cheat Sheets", left_panel)
        left_layout.addWidget(left_header)

        left_collapse = self._build_panel_collapse_button("Cheat Sheets", left_panel, self._collapse_left_icon)
        left_layout.addWidget(left_collapse)

        left_content = QWidget()
        left_content_layout = QVBoxLayout(left_content)
        left_content_layout.setContentsMargins(0, 0, 0, 0)
        self.cheat_tabs = QTabWidget()
        self.cheat_tabs.addTab(self._build_instruction_tab(), "Instructions")
        self.cheat_tabs.addTab(self._build_syscall_tab(), "Syscalls")
        left_content_layout.addWidget(self.cheat_tabs)
        left_layout.addWidget(left_content)
        left_panel.setMinimumWidth(220)
        self.left_panel = left_panel
        self.left_panel_content = left_content
        self.left_panel_collapse = left_collapse

        center_panel = QWidget()
        center_layout = QVBoxLayout(center_panel)
        center_layout.setContentsMargins(8, 8, 8, 8)
        center_layout.addWidget(QLabel("Assembly Editor"))
        center_layout.addWidget(self._build_center_controls())
        self.editor = CodeEditor()
        self.editor.setFont(self._default_font())
        self.editor.update_line_number_area_width(0)
        self.editor.textChanged.connect(self.on_text_changed)
        self.editor.set_breakpoint_manager(self.breakpoint_manager)
        self.editor.set_current_file(self._current_file_key())
        self.editor.breakpoint_toggle_requested.connect(self.on_gutter_breakpoint_toggle)
        self.highlighter = AsmHighlighter(self.editor.document())
        center_layout.addWidget(self.editor)
        center_layout.addLayout(self._build_editor_footer())

        register_section = QWidget()
        register_layout = QVBoxLayout(register_section)
        register_layout.setContentsMargins(8, 8, 8, 8)
        self.register_table = QTableWidget(len(REGISTER_ORDER), 4)
        self.register_table.setHorizontalHeaderLabels(["Register", "Hex", "Dec", "ASCII"])
        self.register_table.verticalHeader().setVisible(False)
        self.register_table.cellChanged.connect(self.on_register_edit)
        self.register_table.setFont(self._default_font())
        register_header = self.register_table.horizontalHeader()
        register_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        register_header.setStretchLastSection(True)
        self.register_table.setColumnHidden(3, True)
        register_flags_row = QHBoxLayout()
        register_layout.addLayout(register_flags_row)
        register_panel = QWidget()
        register_panel_layout = QVBoxLayout(register_panel)
        register_panel_layout.setContentsMargins(0, 0, 0, 0)
        register_panel_layout.addWidget(QLabel("Registers"))
        register_panel_layout.addWidget(self.register_table)
        register_flags_row.addWidget(register_panel, 2)
        flags_panel = QWidget()
        flags_layout = QVBoxLayout(flags_panel)
        flags_layout.setContentsMargins(0, 0, 0, 0)
        flags_layout.addWidget(QLabel("Flags"))
        self.flag_table = QTableWidget(len(FLAG_ORDER), 2)
        self.flag_table.setHorizontalHeaderLabels(["Flag", "Value"])
        self.flag_table.verticalHeader().setVisible(False)
        self.flag_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.flag_table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self.flag_table.setFont(self._default_font())
        self.flag_table.setSizeAdjustPolicy(QAbstractScrollArea.SizeAdjustPolicy.AdjustToContents)
        self.flag_table.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        flag_header = self.flag_table.horizontalHeader()
        flag_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        flag_header.setStretchLastSection(True)
        flags_layout.addWidget(self.flag_table)
        flags_layout.addStretch()
        register_flags_row.addWidget(flags_panel, 1, Qt.AlignmentFlag.AlignTop)

        stack_section = QWidget()
        stack_layout = QVBoxLayout(stack_section)
        stack_layout.setContentsMargins(8, 8, 8, 8)
        stack_layout.addWidget(QLabel("Stack"))
        self.stack_table = QTableWidget(16, 5)
        self.stack_table.setHorizontalHeaderLabels(["Address", "Hex", "Dec", "ASCII", "Markers"])
        self.stack_table.verticalHeader().setVisible(False)
        self.stack_table.cellChanged.connect(self.on_stack_edit)
        self.stack_table.setFont(self._default_font())
        stack_header = self.stack_table.horizontalHeader()
        stack_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        stack_header.setStretchLastSection(True)
        self.stack_table.setColumnHidden(3, True)
        stack_layout.addWidget(self.stack_table)

        right_splitter = QSplitter(Qt.Orientation.Vertical)
        right_splitter.setChildrenCollapsible(False)
        right_splitter.addWidget(register_section)
        right_splitter.addWidget(stack_section)
        right_splitter.setStretchFactor(0, 1)
        right_splitter.setStretchFactor(1, 1)
        right_splitter.setMinimumWidth(260)
        right_splitter.setStyleSheet(
            "QSplitter::handle { background: #3b3f4a; }"
            "QSplitter::handle:horizontal { width: 4px; }"
            "QSplitter::handle:vertical { height: 4px; }"
        )
        self.right_splitter = right_splitter

        right_panel = QWidget()
        right_panel_layout = QVBoxLayout(right_panel)
        right_panel_layout.setContentsMargins(8, 8, 8, 8)
        right_header = self._build_panel_header("Registers / Stack", right_panel)
        right_panel_layout.addWidget(right_header)
        right_collapse = self._build_panel_collapse_button(
            "Registers / Stack", right_panel, self._collapse_right_icon
        )
        right_panel_layout.addWidget(right_collapse)
        right_panel_layout.addWidget(right_splitter)
        self.right_panel = right_panel
        self.right_panel_content = right_splitter
        self.right_panel_collapse = right_collapse

        central_splitter = QSplitter(Qt.Orientation.Horizontal)
        central_splitter.setChildrenCollapsible(False)
        central_splitter.addWidget(left_panel)
        central_splitter.addWidget(center_panel)
        central_splitter.addWidget(right_panel)
        central_splitter.setStretchFactor(0, 1)
        central_splitter.setStretchFactor(1, 3)
        central_splitter.setStretchFactor(2, 1)
        central_splitter.setSizes([240, 720, 320])
        central_splitter.setStyleSheet(
            "QSplitter::handle { background: #3b3f4a; }"
            "QSplitter::handle:horizontal { width: 4px; }"
            "QSplitter::handle:vertical { height: 4px; }"
        )
        self.central_splitter = central_splitter
        self._register_pinnable_panel(self.left_panel, self.left_panel_content, self.central_splitter, "Cheat Sheets")
        self._register_pinnable_panel(self.right_panel, self.right_panel_content, self.central_splitter, "Registers / Stack")

        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setFont(self._default_font())

        self.syscall_output = QPlainTextEdit()
        self.syscall_output.setReadOnly(True)
        self.syscall_output.setFont(self._default_font())

        self.extern_output = QPlainTextEdit()
        self.extern_output.setReadOnly(True)
        self.extern_output.setFont(self._default_font())

        log_panel = self._build_output_panel(self.log_output, self.clear_log_output)
        syscall_panel = self._build_output_panel(self.syscall_output, self.clear_syscall_output)
        extern_panel = self._build_output_panel(self.extern_output, self.clear_extern_output)

        output_tabs = QTabWidget()
        output_tabs.addTab(log_panel, "Log / Output")
        output_tabs.addTab(syscall_panel, "Syscall Output")
        output_tabs.addTab(extern_panel, "C Function Output")

        output_panel = QWidget()
        output_layout = QVBoxLayout(output_panel)
        output_layout.setContentsMargins(8, 8, 8, 8)
        output_header = self._build_panel_header("Output", output_panel)
        output_layout.addWidget(output_header)
        output_collapse = self._build_panel_collapse_button(
            "Output", output_panel, self._collapse_bottom_icon, "vertical"
        )
        output_layout.addWidget(output_collapse)
        output_layout.addWidget(output_tabs)
        self.output_panel = output_panel
        self.output_panel_content = output_tabs
        self.output_panel_collapse = output_collapse

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.setChildrenCollapsible(False)
        main_splitter.addWidget(central_splitter)
        main_splitter.addWidget(output_panel)
        main_splitter.setStretchFactor(0, 3)
        main_splitter.setStretchFactor(1, 1)
        main_splitter.setSizes([720, 220])
        main_splitter.setStyleSheet(
            "QSplitter::handle { background: #3b3f4a; }"
            "QSplitter::handle:horizontal { width: 4px; }"
            "QSplitter::handle:vertical { height: 4px; }"
        )
        self.main_splitter = main_splitter
        self._register_pinnable_panel(
            self.output_panel, self.output_panel_content, self.main_splitter, "Output", axis="vertical"
        )

        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(10, 10, 10, 10)
        container_layout.addWidget(main_splitter)
        self.setCentralWidget(container)

        left_panel_action = QAction("Cheat Sheets", self)
        left_panel_action.setCheckable(True)
        left_panel_action.setChecked(True)
        left_panel_action.toggled.connect(self.left_panel.setVisible)
        left_panel_action.toggled.connect(lambda visible: self._on_panel_visibility_changed(self.left_panel, visible))
        self.view_menu.addAction(left_panel_action)
        self._panel_view_actions[self.left_panel] = left_panel_action

        right_panel_action = QAction("Registers / Stack", self)
        right_panel_action.setCheckable(True)
        right_panel_action.setChecked(True)
        right_panel_action.toggled.connect(self.right_panel.setVisible)
        right_panel_action.toggled.connect(lambda visible: self._on_panel_visibility_changed(self.right_panel, visible))
        self.view_menu.addAction(right_panel_action)
        self._panel_view_actions[self.right_panel] = right_panel_action

        output_panel_action = QAction("Output", self)
        output_panel_action.setCheckable(True)
        output_panel_action.setChecked(True)
        output_panel_action.toggled.connect(self.output_panel.setVisible)
        output_panel_action.toggled.connect(lambda visible: self._on_panel_visibility_changed(self.output_panel, visible))
        self.view_menu.addAction(output_panel_action)
        self._panel_view_actions[self.output_panel] = output_panel_action
        ascii_columns_action = QAction("Show ASCII Columns", self)
        ascii_columns_action.setCheckable(True)
        ascii_columns_action.setChecked(False)
        ascii_columns_action.toggled.connect(self._set_ascii_columns_visible)
        self.view_menu.addAction(ascii_columns_action)

        self.view_menu.addSeparator()

        self.symbol_table = QTableWidget(0, 3)
        self.symbol_table.setHorizontalHeaderLabels(["Symbol", "Kind", "Address/Info"])
        self.symbol_table.verticalHeader().setVisible(False)
        self.symbol_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.symbol_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.symbol_table.setFont(self._default_font())
        symbol_header = self.symbol_table.horizontalHeader()
        symbol_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        symbol_header.setStretchLastSection(True)
        symbol_dock = QDockWidget("Symbols", self)
        symbol_dock.setObjectName("SymbolsDock")
        symbol_dock.setWidget(self.symbol_table)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, symbol_dock)
        symbol_dock_action = symbol_dock.toggleViewAction()
        symbol_dock_action.setText("Symbols")
        self.view_menu.addAction(symbol_dock_action)

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
        self.memory_table.setFont(self._default_font())
        memory_header = self.memory_table.horizontalHeader()
        memory_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        memory_header.setStretchLastSection(True)
        self.memory_table.setColumnHidden(2, True)
        self._update_memory_column_modes(ascii_visible=False)

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
        memory_dock.setObjectName("MemoryDock")
        memory_dock.setWidget(memory_panel)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, memory_dock)
        memory_dock_action = memory_dock.toggleViewAction()
        memory_dock_action.setText("Memory View")
        self.view_menu.addAction(memory_dock_action)

        self.breakpoints_model = BreakpointsTableModel(self.breakpoint_manager)
        self.breakpoints_view = QTableView()
        self.breakpoints_view.setModel(self.breakpoints_model)
        self.breakpoints_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.breakpoints_view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.breakpoints_view.setAlternatingRowColors(True)
        self.breakpoints_view.setEditTriggers(QAbstractItemView.EditTrigger.AllEditTriggers)
        self.breakpoints_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.breakpoints_view.verticalHeader().setVisible(False)
        self.breakpoints_view.clicked.connect(self.on_breakpoints_table_clicked)
        breakpoints_dock = QDockWidget("Breakpoints", self)
        breakpoints_dock.setObjectName("BreakpointsDock")
        breakpoints_dock.setWidget(self.breakpoints_view)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, breakpoints_dock)
        self.breakpoints_dock = breakpoints_dock
        breakpoints_dock_action = breakpoints_dock.toggleViewAction()
        breakpoints_dock_action.setText("Breakpoints")
        self.view_menu.addAction(breakpoints_dock_action)

        status = QStatusBar()
        self.setStatusBar(status)
        status.setStyleSheet("QStatusBar { padding: 6px 10px; }")
        self.state_label = QLabel("Ready")
        self.line_label = QLabel("Line: -")
        status.addWidget(self.state_label)
        status.addPermanentWidget(self.line_label)

        self._apply_dracula_theme()
        self.breakpoint_manager.changed.connect(self._on_breakpoints_changed)


    def _build_output_panel(self, text_edit: QPlainTextEdit, clear_handler) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        controls = QHBoxLayout()
        controls.setContentsMargins(8, 6, 8, 0)
        controls.addStretch(1)
        clear_button = QToolButton()
        clear_button.setText("Clear")
        clear_button.setAutoRaise(True)
        clear_button.clicked.connect(clear_handler)
        controls.addWidget(clear_button)
        layout.addLayout(controls)
        layout.addWidget(text_edit)
        return container

    def _build_center_controls(self) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        layout.setAlignment(Qt.AlignmentFlag.AlignLeft)

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

        self.play_button.setToolTip("Play (F5)")
        self.pause_button.setToolTip("Pause (Shift+F5)")
        self.step_button.setToolTip("Step (F10)")
        self.reset_button.setToolTip("Reset (Ctrl+Shift+F5)")

        layout.addWidget(self.play_button)
        layout.addWidget(self.pause_button)
        layout.addWidget(self.step_button)
        layout.addWidget(self.reset_button)

        layout.addStretch(1)
        mode_label = QLabel("Mode")
        layout.addWidget(mode_label)
        self.mode_select = QComboBox()
        self.mode_select.addItems(["Freestanding (_start)", "Snippet/Function"])
        self.mode_select.currentIndexChanged.connect(self._on_mode_changed)
        layout.addWidget(self.mode_select)
        return widget

    def _build_editor_footer(self) -> QHBoxLayout:
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 8, 0, 0)
        layout.addStretch(1)
        rate_label = QLabel("Steps/s")
        layout.addWidget(rate_label)
        self.rate_spin = QSpinBox()
        self.rate_spin.setRange(1, 1000)
        self.rate_spin.setValue(5)
        self.rate_spin.valueChanged.connect(self._update_timer_interval)
        layout.addWidget(self.rate_spin)
        return layout

    def _current_file_key(self) -> str:
        return self.current_file or "__unsaved__"

    def _set_current_file(self, path: Optional[str]) -> None:
        self.current_file = os.path.abspath(path) if path else None
        self.editor.set_current_file(self._current_file_key())
        if self.current_file:
            self.setWindowTitle(f"ASM Debugger - {self.current_file}")
        else:
            self.setWindowTitle("ASM Debugger")

    def _config_path(self) -> str:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base_dir, ".asm_debugger_layout.json")

    def _breakpoints_path(self) -> str:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base_dir, ".asm_debugger_breakpoints.json")

    def _default_layout_path(self) -> str:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base_dir, ".asm_debugger_layout.default.json")

    def _load_layout(self) -> None:
        path = self._config_path()
        if not os.path.exists(path):
            path = self._default_layout_path()
            if not os.path.exists(path):
                return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            geo = data.get("geometry")
            if geo:
                self.restoreGeometry(bytes.fromhex(geo))
            state = data.get("state")
            if state:
                self.restoreState(bytes.fromhex(state))
            central_sizes = data.get("central_sizes")
            if central_sizes and hasattr(self, "central_splitter"):
                QTimer.singleShot(0, lambda sizes=list(central_sizes): self.central_splitter.setSizes(sizes))
            main_sizes = data.get("main_sizes")
            if main_sizes and hasattr(self, "main_splitter"):
                QTimer.singleShot(0, lambda sizes=list(main_sizes): self.main_splitter.setSizes(sizes))
            right_sizes = data.get("right_sizes")
            if right_sizes and hasattr(self, "right_splitter"):
                QTimer.singleShot(0, lambda sizes=list(right_sizes): self.right_splitter.setSizes(sizes))
            pinned = data.get("pinned_panels", {})
            if isinstance(pinned, dict):
                self._pending_pinned_state = {str(k): bool(v) for k, v in pinned.items()}
                QTimer.singleShot(0, self._apply_pinned_state)
            mode_index = data.get("mode_index")
            if mode_index is not None:
                self.mode_select.setCurrentIndex(int(mode_index))
            rate = data.get("rate")
            if rate:
                self.rate_spin.setValue(int(rate))
            mem_base = data.get("memory_base")
            if mem_base:
                self.memory_base.setText(mem_base)
            mem_rows = data.get("memory_rows")
            if mem_rows:
                self.memory_rows.setValue(int(mem_rows))
            recent = data.get("recent_files", [])
            if isinstance(recent, list):
                self.recent_files = [path for path in recent if isinstance(path, str)]
                self._rebuild_recent_menu()
        except (OSError, ValueError, json.JSONDecodeError):
            # If the layout file is missing, unreadable, or malformed, ignore the error
            # and continue with the default window layout.
            pass

    def _apply_pinned_state(self) -> None:
        if not self._pending_pinned_state:
            return
        for panel, name in self._panel_names.items():
            if name in self._pending_pinned_state:
                pinned = self._pending_pinned_state[name]
                self._set_panel_pinned(panel, pinned)
                if not pinned and panel.isVisible():
                    self._collapse_panel(panel)
        self._pending_pinned_state = None
        if hasattr(self, "editor"):
            self.editor.setFocus(Qt.FocusReason.OtherFocusReason)

    def _save_layout(self) -> None:
        data = {}
        data["geometry"] = self.saveGeometry().toHex().data().decode("ascii")
        data["state"] = self.saveState().toHex().data().decode("ascii")
        if hasattr(self, "central_splitter"):
            data["central_sizes"] = self.central_splitter.sizes()
        if hasattr(self, "main_splitter"):
            data["main_sizes"] = self.main_splitter.sizes()
        if hasattr(self, "right_splitter"):
            data["right_sizes"] = self.right_splitter.sizes()
        data["mode_index"] = self.mode_select.currentIndex()
        data["rate"] = self.rate_spin.value()
        data["memory_base"] = self.memory_base.text()
        data["memory_rows"] = self.memory_rows.value()
        data["recent_files"] = self.recent_files
        data["pinned_panels"] = {name: self._pinnable_panels.get(panel, True) for panel, name in self._panel_names.items()}
        try:
            with open(self._config_path(), "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except OSError:
            pass

    def _load_breakpoints(self) -> None:
        path = self._breakpoints_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.breakpoint_manager.load_json(data)
        except (OSError, ValueError, json.JSONDecodeError):
            pass

    def _save_breakpoints(self) -> None:
        try:
            with open(self._breakpoints_path(), "w", encoding="utf-8") as f:
                json.dump(self.breakpoint_manager.to_json(), f, indent=2)
        except OSError:
            pass

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._save_layout()
        self._save_breakpoints()
        super().closeEvent(event)

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

    def _default_font(self) -> QFont:
        preferred = [
            "JetBrains Mono",
            "Cascadia Code",
            "Fira Code",
            "IBM Plex Mono",
            "Source Code Pro",
            "Inconsolata",
            "DejaVu Sans Mono",
            "Consolas",
            "Menlo",
            "Monaco",
        ]
        available = set(QFontDatabase.families())
        for name in preferred:
            if name in available:
                return QFont(name, 11)
        return QFont("Monospace", 11)

    def _apply_dracula_theme(self) -> None:
        base_bg = QColor("#282a36")
        text_fg = QColor("#f8f8f2")
        highlight_bg = QColor("#44475a")
        highlight_fg = QColor("#f8f8f2")
        panel_bg = QColor("#1e1f29")
        border = QColor("#3c3f58")

        for edit in (self.editor, self.log_output, self.syscall_output, self.extern_output):
            palette = edit.palette()
            palette.setColor(QPalette.ColorRole.Base, base_bg)
            palette.setColor(QPalette.ColorRole.Text, text_fg)
            palette.setColor(QPalette.ColorRole.Highlight, highlight_bg)
            palette.setColor(QPalette.ColorRole.HighlightedText, highlight_fg)
            edit.setPalette(palette)
            edit.setStyleSheet(
                "QPlainTextEdit {"
                f" background-color: {base_bg.name()};"
                f" color: {text_fg.name()};"
                f" selection-background-color: {highlight_bg.name()};"
                f" selection-color: {highlight_fg.name()};"
                " }"
            )
        if isinstance(self.editor, CodeEditor):
            self.editor.set_line_number_colors(panel_bg, QColor("#6272a4"))

        selection_style = (
            "QTableWidget, QTableView {"
            f" background-color: {panel_bg.name()};"
            f" color: {text_fg.name()};"
            f" gridline-color: {border.name()};"
            "}"
            "QHeaderView::section {"
            f" background-color: {border.name()};"
            f" color: {text_fg.name()};"
            " padding: 4px;"
            "}"
            "QTableWidget::item:selected, QTableView::item:selected {"
            f" background: {highlight_bg.name()};"
            f" color: {highlight_fg.name()};"
            "}"
        )
        tables = [
            self.register_table,
            self.flag_table,
            self.stack_table,
            self.symbol_table,
            self.memory_table,
            self.cheat_table,
            self.syscall_table,
        ]
        for table in tables:
            table.setStyleSheet(selection_style)
        if hasattr(self, "breakpoints_view"):
            self.breakpoints_view.setStyleSheet(selection_style)

        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, panel_bg)
        palette.setColor(QPalette.ColorRole.Base, base_bg)
        palette.setColor(QPalette.ColorRole.Text, text_fg)
        palette.setColor(QPalette.ColorRole.Button, panel_bg)
        palette.setColor(QPalette.ColorRole.ButtonText, text_fg)
        palette.setColor(QPalette.ColorRole.WindowText, text_fg)
        palette.setColor(QPalette.ColorRole.Highlight, highlight_bg)
        palette.setColor(QPalette.ColorRole.HighlightedText, highlight_fg)
        self.setPalette(palette)

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
        self.cheat_table.setFont(self._default_font())
        cheat_header = self.cheat_table.horizontalHeader()
        cheat_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        cheat_header.setStretchLastSection(True)
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
        self.syscall_table.setFont(self._default_font())
        syscall_header = self.syscall_table.horizontalHeader()
        syscall_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        syscall_header.setStretchLastSection(True)
        layout.addWidget(self.syscall_table)
        self._populate_syscall_sheet()
        return widget

    def _on_breakpoints_changed(self) -> None:
        if isinstance(self.editor, CodeEditor):
            self.editor.line_number_area.update()
        self._save_breakpoints()

    def on_gutter_breakpoint_toggle(self, line_no: int) -> None:
        self.breakpoint_manager.toggle_line(self._current_file_key(), line_no)

    def toggle_breakpoint_at_cursor(self) -> None:
        line_no = self.editor.textCursor().blockNumber() + 1
        self.breakpoint_manager.toggle_line(self._current_file_key(), line_no)

    def break_here(self) -> None:
        line_no = self.editor.textCursor().blockNumber() + 1
        self.breakpoint_manager.add_line(self._current_file_key(), line_no, temporary=True)
        if self.run_state != "Running":
            self.play()

    def add_conditional_breakpoint(self) -> None:
        dialog = ConditionalBreakpointDialog(self)
        result = dialog.get_data()
        if not result:
            return
        kind, name, value = result
        if kind == "Register":
            self.breakpoint_manager.add_register_condition(name, value)
        else:
            self.breakpoint_manager.add_flag_condition(name, value)

    def on_breakpoints_table_clicked(self, index) -> None:
        bp = self.breakpoints_model.breakpoint_at(index.row())
        if not bp:
            return
        if index.column() == 0:
            return
        if index.column() == 5:
            self.breakpoint_manager.remove(bp.id)
            return
        if bp.file_path and bp.line:
            if not os.path.exists(bp.file_path):
                self.log(f"Breakpoint file not found: {bp.file_path}")
                return
            if self.current_file != bp.file_path:
                if not self._open_file_path(bp.file_path):
                    return
            self._jump_to_line(bp.line)

    def _open_file_path(self, path: str) -> bool:
        try:
            with open(path, "r", encoding="utf-8") as file:
                self.editor.setPlainText(file.read())
            self._set_current_file(path)
            self.source_dirty = True
            self.log(f"Opened {path}")
            self._add_recent_file(path)
            return True
        except OSError as exc:
            QMessageBox.warning(self, "Open Failed", str(exc))
            return False

    def _jump_to_line(self, line_no: int) -> None:
        block = self.editor.document().findBlockByNumber(line_no - 1)
        if not block.isValid():
            return
        cursor = QTextCursor(block)
        self.editor.setTextCursor(cursor)
        self.editor.centerCursor()

    def on_text_changed(self) -> None:
        self.source_dirty = True

    def new_file(self) -> None:
        self.editor.clear()
        self._set_current_file(None)
        self.source_dirty = True
        self.log("New file created.")

    def open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open .asm", "", "ASM Files (*.asm);;All Files (*)")
        if not path:
            return
        self._open_file_path(path)

    def save_file(self) -> None:
        if not self.current_file:
            self.save_file_as()
            return
        try:
            with open(self.current_file, "w", encoding="utf-8") as file:
                file.write(self.editor.toPlainText())
            self.source_dirty = False
            self.log(f"Saved {self.current_file}")
            self._add_recent_file(self.current_file)
        except OSError as exc:
            QMessageBox.warning(self, "Save Failed", str(exc))

    def save_file_as(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save .asm", "", "ASM Files (*.asm);;All Files (*)")
        if not path:
            return
        self._set_current_file(path)
        self.save_file()

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
        entry_point = self._resolve_entry_point()
        if entry_point is not None:
            self.cpu.set_reg("EIP", entry_point)
        self.emulator = Emulator(self.cpu, self.program)
        self.prev_registers = {}
        self.prev_stack_values = {}
        self.source_dirty = False
        self._skip_breakpoint_id = None
        self.breakpoint_manager.set_valid_lines(
            self._current_file_key(),
            {instr.line_no for instr in self.program.instructions},
        )
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

    def _check_breakpoints_before_step(self) -> bool:
        if not self.program.instructions:
            return False
        eip = self.cpu.get_reg("EIP")
        if not (0 <= eip < len(self.program.instructions)):
            return False
        line_no = self.program.instructions[eip].line_no
        should_break, bp_id, reason = self.breakpoint_manager.should_break(
            self._current_file_key(), line_no, self.cpu
        )
        if not should_break or bp_id is None:
            return False
        if self._skip_breakpoint_id == bp_id:
            self._skip_breakpoint_id = None
            return False
        removed = self.breakpoint_manager.increment_hit(bp_id)
        bp = self.breakpoint_manager.get(bp_id)
        if bp and bp.type in {BreakpointType.LINE, BreakpointType.TEMPORARY_LINE} and not removed:
            self._skip_breakpoint_id = bp_id
        else:
            self._skip_breakpoint_id = None
        self.timer.stop()
        self.set_state("Paused")
        if reason:
            self.log(f"Breakpoint hit: {reason}")
        else:
            self.log("Breakpoint hit.")
        self._update_views()
        return True

    def step_once(self) -> None:
        self.timer.stop()
        if not self.ensure_program():
            return
        if self.emulator.halted:
            self.log("Execution halted. Reset to run again.")
            self.set_state("Halted")
            return
        if self._check_breakpoints_before_step():
            return
        outcome = self.emulator.step()
        self.handle_step_outcome(outcome)
        self._update_views()
        if not outcome.error and not outcome.halted:
            self.set_state("Paused")

    def on_timer_step(self) -> None:
        if self._check_breakpoints_before_step():
            return
        outcome = self.emulator.step()
        self.handle_step_outcome(outcome)
        self._update_views()
        if outcome.error or outcome.halted:
            self.timer.stop()

    def handle_step_outcome(self, outcome: StepOutcome) -> None:
        if outcome.output:
            if outcome.output_target == "extern":
                self.extern_output.appendPlainText(outcome.output)
            else:
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

    def clear_log_output(self) -> None:
        self.log_output.clear()

    def clear_syscall_output(self) -> None:
        self.syscall_output.clear()

    def clear_extern_output(self) -> None:
        self.extern_output.clear()

    def reset_state(self) -> None:
        self.timer.stop()
        if self.source_dirty or not self.program.instructions:
            if not self.ensure_program():
                return
            self.log("CPU state reset.")
            return
        self.cpu.reset()
        self.cpu.load_data(self.program.data_bytes)
        entry_point = self._resolve_entry_point()
        if entry_point is not None:
            self.cpu.set_reg("EIP", entry_point)
        self.emulator = Emulator(self.cpu, self.program)
        self.prev_registers = {}
        self.prev_stack_values = {}
        self._skip_breakpoint_id = None
        self.set_state("Ready")
        self._update_views()
        self.log("CPU state reset.")

    def ensure_program(self) -> bool:
        was_dirty = self.source_dirty
        if not self._autosave_if_needed():
            return False
        if was_dirty or not self.program.instructions:
            return self.parse_current_program()
        return True

    def _autosave_if_needed(self) -> bool:
        if not self.source_dirty:
            return True
        if self.current_file:
            self.save_file()
        else:
            self.save_file_as()
        return not self.source_dirty

    def _update_timer_interval(self) -> None:
        steps = self.rate_spin.value()
        interval_ms = max(1, int(1000 / steps))
        self.timer.setInterval(interval_ms)

    def _adjust_step_rate(self, delta: int) -> None:
        new_value = min(self.rate_spin.maximum(), max(self.rate_spin.minimum(), self.rate_spin.value() + delta))
        self.rate_spin.setValue(new_value)

    def _update_views(self) -> None:
        self.updating_views = True
        try:
            self._update_register_view()
            self._update_flag_view()
            self._update_stack_view()
            self._update_memory_view()
            self._highlight_current_line()
            self._update_status()
        finally:
            self.updating_views = False

    def _update_register_view(self) -> None:
        ascii_visible = not self.register_table.isColumnHidden(3)
        for row, reg in enumerate(REGISTER_ORDER):
            name_item = QTableWidgetItem(reg)
            name_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.register_table.setItem(row, 0, name_item)
            value = self.cpu.get_reg(reg)
            value_item = QTableWidgetItem(f"0x{value:08X}")
            value_item.setData(Qt.ItemDataRole.UserRole, reg)
            value_item.setToolTip(str(value))
            dec_item = QTableWidgetItem(str(value))
            dec_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            prev_value = self.prev_registers.get(reg)
            if prev_value is not None and prev_value != value:
                value_item.setBackground(QColor("#ffb86c"))
                value_item.setForeground(QColor("#1a1b26"))
                dec_item.setBackground(QColor("#ffb86c"))
                dec_item.setForeground(QColor("#1a1b26"))
            self.register_table.setItem(row, 1, value_item)
            self.register_table.setItem(row, 2, dec_item)
            if ascii_visible:
                ascii_item = QTableWidgetItem(self._format_ascii_dword(value))
                ascii_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
                if prev_value is not None and prev_value != value:
                    ascii_item.setBackground(QColor("#ffb86c"))
                    ascii_item.setForeground(QColor("#1a1b26"))
                self.register_table.setItem(row, 3, ascii_item)
        self.prev_registers = {reg: self.cpu.get_reg(reg) for reg in REGISTER_ORDER}

    def _update_flag_view(self) -> None:
        for row, flag in enumerate(FLAG_ORDER):
            name_item = QTableWidgetItem(flag)
            name_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.flag_table.setItem(row, 0, name_item)
            value = self.cpu.flags.get(flag, 0)
            value_item = QTableWidgetItem(str(value))
            value_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.flag_table.setItem(row, 1, value_item)
        self._resize_flag_table()

    def _resize_flag_table(self) -> None:
        self.flag_table.resizeRowsToContents()
        total_height = self.flag_table.horizontalHeader().height()
        for row in range(self.flag_table.rowCount()):
            total_height += self.flag_table.rowHeight(row)
        total_height += self.flag_table.frameWidth() * 2
        self.flag_table.setFixedHeight(total_height)

    def _update_stack_view(self) -> None:
        esp = self.cpu.get_reg("ESP")
        ebp = self.cpu.get_reg("EBP")
        base = clamp_u32(esp - 32)
        rows = self.stack_table.rowCount()
        ascii_visible = not self.stack_table.isColumnHidden(3)
        for i in range(rows):
            addr = clamp_u32(base + i * 4)
            value = self.cpu.read_mem(addr, 4)
            addr_item = QTableWidgetItem(f"0x{addr:08X}")
            addr_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            value_item = QTableWidgetItem(f"0x{value:08X}")
            value_item.setData(Qt.ItemDataRole.UserRole, addr)
            dec_item = QTableWidgetItem(str(value))
            dec_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            marker_text = []
            if addr == esp:
                marker_text.append("ESP")
            if addr == ebp:
                marker_text.append("EBP")
            marker_item = QTableWidgetItem(", ".join(marker_text))
            marker_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.stack_table.setItem(i, 0, addr_item)
            self.stack_table.setItem(i, 1, value_item)
            self.stack_table.setItem(i, 2, dec_item)
            self.stack_table.setItem(i, 4, marker_item)
            if addr == esp:
                highlight = QColor("#f286c4")
                addr_item.setBackground(highlight)
                value_item.setBackground(highlight)
                dec_item.setBackground(highlight)
                marker_item.setBackground(highlight)
            prev_value = self.prev_stack_values.get(addr)
            if prev_value is not None and prev_value != value:
                change_bg = QColor("#ffb86c")
                value_item.setBackground(change_bg)
                value_item.setForeground(QColor("#1a1b26"))
                dec_item.setBackground(change_bg)
                dec_item.setForeground(QColor("#1a1b26"))
            if ascii_visible:
                ascii_item = QTableWidgetItem(self._format_ascii_dword(value))
                ascii_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
                if addr == esp:
                    ascii_item.setBackground(highlight)
                if prev_value is not None and prev_value != value:
                    ascii_item.setBackground(change_bg)
                    ascii_item.setForeground(QColor("#1a1b26"))
                self.stack_table.setItem(i, 3, ascii_item)
        self.prev_stack_values = {clamp_u32(base + i * 4): self.cpu.read_mem(clamp_u32(base + i * 4), 4) for i in range(rows)}

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
            hex_item = QTableWidgetItem(hex_bytes)
            hex_item.setTextAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter)
            self.memory_table.setItem(row, 1, hex_item)
            self.memory_table.setItem(row, 2, QTableWidgetItem(ascii_text))

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
                    selection.format.setForeground(QColor("#1e1f29"))
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

    def _format_ascii_dword(self, value: int) -> str:
        # Interpret the 32-bit word as little-endian bytes for ASCII display.
        # This matches the x86 target of this debugger; adjust if other
        # architectures (with different endianness) are supported in future.
        data = (value & 0xFFFFFFFF).to_bytes(4, "little", signed=False)
        return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)

    def _set_ascii_columns_visible(self, visible: bool) -> None:
        if hasattr(self, "register_table"):
            self.register_table.setColumnHidden(3, not visible)
            if visible:
                self._update_register_view()
        if hasattr(self, "register_table"):
            # Hide both Dec (2) and ASCII (3) columns together for registers
            self.register_table.setColumnHidden(2, not visible)
            self.register_table.setColumnHidden(3, not visible)
        if hasattr(self, "stack_table"):
            # Hide both Dec (2) and ASCII (3) columns together for the stack
            self.stack_table.setColumnHidden(2, not visible)
            self.stack_table.setColumnHidden(3, not visible)
        if hasattr(self, "memory_table"):
            # Memory table has only one extra column: ASCII at index 2
            self.memory_table.setColumnHidden(2, not visible)
            self._update_memory_column_modes(ascii_visible=visible)

    def _update_memory_column_modes(self, ascii_visible: bool) -> None:
        if not hasattr(self, "memory_table"):
            return
        header = self.memory_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        if not ascii_visible:
            QTimer.singleShot(0, self._expand_memory_hex_column)

    def _expand_memory_hex_column(self) -> None:
        if not hasattr(self, "memory_table"):
            return
        if not self.memory_table.isColumnHidden(2):
            return
        available = self.memory_table.viewport().width()
        address_width = self.memory_table.columnWidth(0)
        target = max(120, available - address_width - 6)
        self.memory_table.setColumnWidth(1, target)
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
