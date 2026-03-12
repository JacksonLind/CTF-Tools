"""
Result panel: findings tree (top-right) with severity badges, confidence scores,
flag-match highlighting, and per-file "Analyze with AI" button.
"""
from __future__ import annotations

from typing import List, Callable, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem,
    QPushButton, QLabel, QTextEdit, QMenu, QApplication,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QAction

from core.report import Finding
from ui.tool_suggester_panel import SuggestedToolsPanel

_SEVERITY_COLORS = {
    "HIGH":   ("#cc0000", "#ffeeee"),
    "MEDIUM": ("#886600", "#fffaee"),
    "LOW":    ("#004488", "#eeeeff"),
    "INFO":   ("#333333", "#f8f8f8"),
}


class ResultPanel(QWidget):
    """Shows the findings tree and triggers hex viewer jumps."""

    finding_selected = pyqtSignal(object)   # emits Finding
    pin_finding_requested = pyqtSignal(object)  # emits Finding for Transform Pipeline

    def __init__(self, ai_client=None, parent=None):
        super().__init__(parent)
        self._ai_client = ai_client
        self._current_file: str = ""
        self._findings: List[Finding] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Header row
        hdr = QHBoxLayout()
        self._file_label = QLabel("No file selected")
        self._file_label.setStyleSheet("font-weight: bold;")
        hdr.addWidget(self._file_label)
        hdr.addStretch()

        self._ai_btn = QPushButton("🤖 Analyze with AI")
        self._ai_btn.setEnabled(False)
        self._ai_btn.setToolTip("Set API key in Settings to enable AI analysis")
        self._ai_btn.clicked.connect(self._analyze_with_ai)
        hdr.addWidget(self._ai_btn)
        layout.addLayout(hdr)

        # Findings tree with context menu
        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Severity", "Analyzer", "Title", "Confidence", "Offset"])
        self._tree.setColumnWidth(0, 80)
        self._tree.setColumnWidth(1, 110)
        self._tree.setColumnWidth(2, 250)
        self._tree.setColumnWidth(3, 70)
        self._tree.setColumnWidth(4, 80)
        self._tree.itemSelectionChanged.connect(self._on_selection)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._finding_context_menu)
        layout.addWidget(self._tree)

        # Detail box
        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setMaximumHeight(140)
        self._detail.setPlaceholderText("Select a finding to see details…")
        layout.addWidget(self._detail)

        # AI output
        self._ai_output = QTextEdit()
        self._ai_output.setReadOnly(True)
        self._ai_output.setMaximumHeight(150)
        self._ai_output.setPlaceholderText("AI analysis output will appear here…")
        layout.addWidget(self._ai_output)

        # Suggested Tools panel
        self._tool_suggester = SuggestedToolsPanel()
        self._tool_suggester.setMaximumHeight(200)
        layout.addWidget(self._tool_suggester)

    def set_ai_client(self, ai_client) -> None:
        self._ai_client = ai_client
        enabled = ai_client is not None and ai_client.available
        self._ai_btn.setEnabled(enabled)
        if enabled:
            self._ai_btn.setToolTip("Query Claude AI for analysis of this file's findings")

    def show_findings(self, file_path: str, findings: List[Finding]) -> None:
        self._current_file = file_path
        self._findings = findings
        self._file_label.setText(f"Findings for: {file_path}")
        self._tree.clear()
        self._detail.clear()
        self._ai_output.clear()

        for f in sorted(findings, key=lambda x: (-x.confidence, x.severity)):
            if f.duplicate_of:
                continue  # skip duplicates
            sev_fg, sev_bg = _SEVERITY_COLORS.get(f.severity, ("#000", "#fff"))
            badge = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "🟢"}.get(f.severity, "")
            item = QTreeWidgetItem([
                f"{badge} {f.severity}",
                f.analyzer,
                f.title,
                f"{f.confidence:.2f}",
                f"0x{f.offset:x}" if f.offset >= 0 else "-",
            ])
            item.setForeground(0, QColor(sev_fg))
            item.setBackground(0, QColor(sev_bg))
            if f.flag_match:
                item.setForeground(2, QColor("darkred"))
                item.setFont(2, QFont("", -1, QFont.Weight.Bold))
            item.setData(0, Qt.ItemDataRole.UserRole, f)
            self._tree.addTopLevelItem(item)

        self._tool_suggester.refresh(findings)

    def _on_selection(self) -> None:
        items = self._tree.selectedItems()
        if not items:
            return
        f: Finding = items[0].data(0, Qt.ItemDataRole.UserRole)
        if f:
            self._detail.setPlainText(f.detail)
            self.finding_selected.emit(f)

    def _finding_context_menu(self, pos) -> None:
        item = self._tree.itemAt(pos)
        if not item:
            return
        f: Optional[Finding] = item.data(0, Qt.ItemDataRole.UserRole)
        if not f:
            return
        menu = QMenu(self)
        copy_act = menu.addAction("📋 Copy detail")
        pin_act = menu.addAction("📌 Pin to Transform Pipeline")
        action = menu.exec(self._tree.mapToGlobal(pos))
        if action == copy_act:
            QApplication.clipboard().setText(f.detail)
        elif action == pin_act:
            self.pin_finding_requested.emit(f)

    def _analyze_with_ai(self) -> None:
        if not self._ai_client or not self._ai_client.available:
            return
        visible = [f for f in self._findings if not f.duplicate_of]
        summary = "\n".join(
            f"[{f.severity}] {f.analyzer}: {f.title} — {f.detail[:150]}"
            for f in visible[:30]
        )
        # Build hex context around highest-confidence finding
        best = max(visible, key=lambda f: f.confidence, default=None)
        hex_ctx = ""
        if best and best.offset >= 0:
            try:
                with open(self._current_file, "rb") as fh:
                    fh.seek(max(0, best.offset))
                    raw = fh.read(256)
                hex_ctx = " ".join(f"{b:02x}" for b in raw)
            except Exception:
                pass

        self._ai_output.setPlainText("Querying AI… please wait.")
        response = self._ai_client.analyze_findings(self._current_file, summary, hex_ctx)
        self._ai_output.setPlainText(response or "No response from AI.")
