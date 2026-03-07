"""
Watchfolder: monitors a directory and emits Qt signals for new files.
Uses the watchdog library for cross-platform filesystem events.
"""
from __future__ import annotations

import os
from PyQt6.QtCore import QObject, pyqtSignal
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent


class _Handler(FileSystemEventHandler):
    def __init__(self, callback):
        super().__init__()
        self._callback = callback

    def on_created(self, event):
        if not event.is_directory:
            self._callback(event.src_path)


class WatchfolderManager(QObject):
    """Emits `file_detected` signal when a new file appears in the watched directory."""

    file_detected = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._observer: Observer | None = None
        self._path: str = ""

    def start(self, directory: str) -> None:
        self.stop()
        self._path = directory
        handler = _Handler(lambda p: self.file_detected.emit(p))
        self._observer = Observer()
        self._observer.schedule(handler, directory, recursive=False)
        self._observer.start()

    def stop(self) -> None:
        if self._observer and self._observer.is_alive():
            self._observer.stop()
            self._observer.join()
        self._observer = None

    @property
    def active(self) -> bool:
        return self._observer is not None and self._observer.is_alive()

    @property
    def watched_path(self) -> str:
        return self._path
