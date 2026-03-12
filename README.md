# CTF Hunter

A desktop GUI tool for analyzing CTF (Capture The Flag) challenge files. CTF Hunter automatically detects file types and runs 16 specialized analyzers to uncover flags, hidden data, cryptographic patterns, steganography, and forensic artifacts.

---

## Features

### Automatic File Analysis
Drop any file into CTF Hunter and it immediately identifies the file type via magic bytes and MIME detection, then dispatches the relevant analyzers. Five analyzers always run regardless of file type (Generic, Encoding, Crypto, Classical Cipher, and Forensics Timeline), while the remaining 11 analyzers are selected based on the detected file format.

### Analyzers

| Analyzer | What It Does |
|----------|-------------|
| **Generic** | Entropy detection, magic/extension mismatch, null-byte clusters, string extraction with flag pattern matching |
| **Encoding** | Base64/32/85, hex, ROT13, Morse code, binary-to-ASCII, XOR key guessing |
| **Classical Cipher** | Caesar, ROT13, Atbash, Vigenère (Kasiski), Beaufort, Rail Fence, Columnar Transposition, Playfair, Substitution (hill-climbing with bigram frequency scoring and Index of Coincidence) |
| **Crypto** | MD5, SHA1, SHA256, SHA512, NTLM, MySQL, bcrypt hash identification and cracking; Cisco Type 7 decoding; known-plaintext XOR recovery |
| **Binary** | ELF/PE header parsing, packed section detection, overlay data, suspicious imports, XOR brute-force, Base64/ROT13/hex flag decoding, entropy-guided decompression |
| **Image** | EXIF metadata extraction, appended data detection, LSB chi-square testing, palette anomaly detection |
| **Image Format** | Deep PNG/JPEG/GIF/BMP binary parsing, chunk structure validation, unknown chunk detection, extra data after image end |
| **Audio** | ID3/metadata extraction, silence block detection, WAV LSB extraction |
| **Steganalysis** | Comprehensive steganography detection for images, audio, video, text, PDF, ZIP, and binary files; LSB analysis, phase coding, echo hiding, frequency domain inspection, metadata inspection, appended data; post-processing pipeline (Base64 → hex → ROT13 → XOR → reversal → zlib decompression) |
| **Archive** | ZIP comment extraction, encrypted entry detection, password cracking, path traversal detection, nested archive handling |
| **Document** | PDF JavaScript and embedded stream detection, DOCX macro/VBA analysis, OLE object parsing (DOC/XLS/PPT) |
| **Filesystem** | Disk image analysis via Sleuth Kit (pytsk3), deleted file recovery, hidden partition detection, raw file carving |
| **PCAP** | Protocol summary, TCP stream reassembly, HTTP extraction, credential sniffing, file carving, DNS covert channel detection |
| **Database** | SQLite table enumeration, schema inspection, flag pattern search across all fields |
| **Disassembly** | x86/x64/ARM disassembly via Capstone; optional AI-powered assembly summary |
| **Forensics Timeline** | Extracts timestamps from filesystem metadata, EXIF, PDF, DOCX, OLE, and ZIP; reconstructs a unified chronological timeline |

### Analysis Modes
- **Fast** – Runs only the most targeted checks for quick results.
- **Deep** – Runs exhaustive checks including brute-force decoding, extended steganography analysis, and broader entropy scanning.

### AI Integration (Optional)
When configured with a Claude API key, CTF Hunter can generate attack plans from a challenge description, summarize disassembled code, and provide holistic hypotheses across all findings.

### External Tool Suggestions
After analysis, CTF Hunter maps its findings to relevant external CTF tools (e.g., `zsteg`, `steghide`, `john`, `fcrackzip`) and shows which ones are installed on your system along with suggested usage commands.

### Additional Features
- **Flag Summary tab** – Aggregates all flag-match findings for quick copy-to-clipboard access.
- **Hex Viewer** – Byte-level display with ASCII sidebar and color highlighting.
- **Steg Viewer** – Visualizes LSB layers and steganographic extractions.
- **Timeline tab** – Chronological visualization of extracted timestamps.
- **Network Console** – Packet inspection for PCAP analysis.
- **Challenge Panel** – Input a CTF challenge description for AI-powered attack plan generation.
- **Watch Folder** – Monitors a directory and automatically analyzes new files as they appear.
- **Session Save/Load** – Save an analysis session (findings, notes, flag pattern) to a `.ctfs` JSON file and reload it later.
- **Drag-and-drop** file loading.

---

## Supported File Types

Images (PNG, JPEG, GIF, BMP), audio (WAV, MP3), video, archives (ZIP), documents (PDF, DOCX, DOC, XLS, PPT), executables (ELF, PE), packet captures (PCAP), SQLite databases, disk images, and generic binary files.

---

## Installation

**Requirements:** Python 3.9+

```bash
cd ctf_hunter
pip install -r requirements.txt
```

---

## Usage

```bash
cd ctf_hunter
python main.py
```

This launches the GUI. Load files by dragging and dropping them onto the file list, or use the **Open** button in the toolbar. Click **Analyze** to run all applicable analyzers. Results appear in the findings tree, organized by severity (HIGH, MEDIUM, LOW, INFO).

### Optional: AI features

1. Open **Settings** from the toolbar.
2. Enter your [Anthropic API key](https://console.anthropic.com/).
3. The Challenge Panel and Disassembly analyzer will now offer AI-generated insights.

### Optional: Custom wordlist for hash/archive cracking

By default, CTF Hunter uses a bundled `rockyou_top1000.txt` wordlist (top 1,000 RockYou passwords). To use a custom wordlist, set the path in **Settings**.

---

## Building a Standalone Executable

```bash
cd ctf_hunter
python build.py
```

This uses PyInstaller to produce a single executable in `dist/` (e.g., `dist/ctf_hunter` on Linux/macOS or `dist/ctf_hunter.exe` on Windows). The wordlist is bundled automatically.

---

## Project Structure

```
ctf_hunter/
├── main.py                  # Entry point – launches the PyQt6 GUI
├── build.py                 # PyInstaller packaging script
├── requirements.txt         # Python dependencies
├── core/
│   ├── dispatcher.py        # File-type detection and analyzer routing
│   ├── ai_client.py         # Claude API integration
│   ├── tool_suggester.py    # External CTF tool recommendations
│   ├── deduplicator.py      # Removes duplicate findings
│   ├── external.py          # Wrappers for strings, file, exiftool, tshark
│   ├── report.py            # Finding and Session data classes
│   └── watchfolder.py       # Directory monitoring
├── analyzers/               # One file per analyzer (see table above)
├── ui/                      # PyQt6 UI components
└── wordlists/
    └── rockyou_top1000.txt  # Bundled password list for cracking
```
