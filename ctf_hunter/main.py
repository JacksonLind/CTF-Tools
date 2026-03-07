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


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("CTF Hunter")
    app.setOrganizationName("CTFTools")
    app.setStyle("Fusion")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
