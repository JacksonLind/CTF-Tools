#!/usr/bin/env python3
"""
CTF Hunter — entry point.
Run: python main.py
"""
from __future__ import annotations

import sys
import os

# Ensure ctf_hunter package root is on the path when running from the project directory
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from ui.main_window import MainWindow


_STYLESHEET = """
/* ── Global clean-up ──────────────────────────────────────────── */
QMainWindow, QWidget {
    font-size: 13px;
}

QToolBar {
    spacing: 4px;
    padding: 2px 4px;
}
QToolBar QLabel {
    padding: 0 2px;
}

QTabWidget::pane {
    border: 1px solid #c0c0c0;
    border-radius: 3px;
}
QTabBar::tab {
    padding: 5px 12px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    font-weight: bold;
}

QTreeWidget {
    alternate-background-color: #f7f7f7;
}
QTreeWidget::item {
    padding: 2px 0;
}

QGroupBox {
    font-weight: bold;
    border: 1px solid #d0d0d0;
    border-radius: 4px;
    margin-top: 8px;
    padding-top: 14px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}

QTextEdit[readOnly="true"] {
    background-color: #fafafa;
    border: 1px solid #d8d8d8;
    border-radius: 3px;
}

QPushButton {
    padding: 4px 10px;
    border: 1px solid #c0c0c0;
    border-radius: 3px;
    background: #f5f5f5;
}
QPushButton:hover {
    background: #e8e8e8;
}
QPushButton:pressed {
    background: #d8d8d8;
}
QPushButton:checked {
    background: #ddeeff;
    border-color: #88b0dd;
}

QComboBox {
    padding: 3px 6px;
    border: 1px solid #c0c0c0;
    border-radius: 3px;
}

QSplitter::handle {
    background: #e0e0e0;
}
QSplitter::handle:horizontal {
    width: 3px;
}
QSplitter::handle:vertical {
    height: 3px;
}

QStatusBar {
    font-size: 11px;
    color: #666;
}

QDockWidget {
    font-weight: bold;
}
QDockWidget::title {
    padding: 4px;
    background: #f0f0f0;
}
"""


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("CTF Hunter")
    app.setOrganizationName("CTFTools")
    app.setStyle("Fusion")
    app.setStyleSheet(_STYLESHEET)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
