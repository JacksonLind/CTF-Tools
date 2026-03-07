#!/usr/bin/env python3
"""
Build script: packages CTF Hunter into a single executable using PyInstaller.
Run: python build.py
"""
from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent


def main() -> None:
    dist_path = ROOT / "dist"
    build_path = ROOT / "build_pyinstaller"

    args = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name", "ctf_hunter",
        "--distpath", str(dist_path),
        "--workpath", str(build_path),
        "--specpath", str(build_path),
        "--add-data", f"{ROOT / 'wordlists'}{os.pathsep}wordlists",
        "--paths", str(ROOT),
        str(ROOT / "main.py"),
    ]

    # Platform-specific extras
    if platform.system() == "Windows":
        # Optionally add an icon
        icon_path = ROOT / "icon.ico"
        if icon_path.exists():
            args += ["--icon", str(icon_path)]

    print("Running PyInstaller…")
    print(" ".join(str(a) for a in args))
    result = subprocess.run(args, cwd=str(ROOT))
    if result.returncode == 0:
        exe_name = "ctf_hunter.exe" if platform.system() == "Windows" else "ctf_hunter"
        print(f"\nBuild complete! Executable: {dist_path / exe_name}")
    else:
        print("\nBuild FAILED.")
        sys.exit(1)


if __name__ == "__main__":
    main()
