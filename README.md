# CTF Hunter

A desktop GUI tool for analyzing CTF (Capture The Flag) challenge files. CTF Hunter automatically detects file types and runs 18 specialized analyzers to uncover flags, hidden data, cryptographic patterns, steganography, and forensic artifacts. An integrated intelligence pipeline then scores every finding by confidence, correlates results across files, generates attack hypotheses, and can auto-produce exploit scripts — all without leaving the application.

---

## Features

### Automatic File Analysis
Drop any file into CTF Hunter and it immediately identifies the file type via magic bytes and MIME detection, then dispatches the relevant analyzers. Five analyzers always run regardless of file type (Generic, Encoding, Crypto, Classical Cipher, and Forensics Timeline), while the remaining analyzers are selected based on the detected file format.

### Analyzers

| Analyzer | Triggered By | What It Does |
|----------|-------------|--------------|
| **Generic** | Always | Entropy detection, magic/extension mismatch, null-byte clusters, string extraction with flag pattern matching |
| **Encoding** | Always | Base64/32/85, hex, ROT13, Morse code, binary-to-ASCII, XOR key guessing |
| **Classical Cipher** | Always | Caesar, ROT13, Atbash, Vigenère (Kasiski), Beaufort, Rail Fence, Columnar Transposition, Playfair, Substitution (hill-climbing with bigram frequency scoring and Index of Coincidence) |
| **Crypto** | Always | MD5, SHA1, SHA256, SHA512, NTLM, MySQL, bcrypt hash identification and cracking; Cisco Type 7 decoding; known-plaintext XOR recovery |
| **Forensics Timeline** | Always | Extracts timestamps from filesystem metadata, EXIF, PDF, DOCX, OLE, and ZIP; reconstructs a unified chronological timeline |
| **RSA Crypto** | PEM/DER files, files containing large integers | Small public-exponent attacks (e=3, Håstad broadcast), Wiener's attack (continued fractions), common-modulus attack, factordb.com API lookup, LSB oracle hint; recovers plaintext when an attack succeeds |
| **Binary** | ELF, PE executables | ELF/PE header parsing, packed section detection, overlay data, suspicious imports, XOR brute-force, Base64/ROT13/hex flag decoding, entropy-guided decompression |
| **Image** | PNG, JPEG, GIF, BMP | EXIF metadata extraction, appended data detection, LSB chi-square testing, palette anomaly detection |
| **Image Format** | PNG, JPEG, GIF, BMP | Deep binary parsing, chunk structure validation, unknown chunk detection, extra data after image end |
| **Audio** | WAV, MP3 | ID3/metadata extraction, silence block detection, WAV LSB extraction |
| **Steganalysis** | Images, audio, video, PDF, ZIP, text, binary | LSB analysis, phase coding, echo hiding, frequency domain inspection, metadata inspection, appended data; post-processing pipeline (Base64 → hex → ROT13 → XOR → reversal → zlib decompression) |
| **Archive** | ZIP and compressed files | ZIP comment extraction, encrypted entry detection, password cracking, path traversal detection, nested archive handling |
| **Document** | PDF, DOCX, DOC, XLS, PPT | PDF JavaScript and embedded stream detection, DOCX macro/VBA analysis, OLE object parsing |
| **Filesystem** | Disk images | Disk image analysis via Sleuth Kit (pytsk3), deleted file recovery, hidden partition detection, raw file carving |
| **PCAP** | Packet captures | Protocol summary, TCP stream reassembly, HTTP extraction, credential sniffing, file carving, DNS covert channel detection |
| **Database** | SQLite databases | Table enumeration, schema inspection, flag pattern search across all fields |
| **Disassembly** | ELF, PE executables | x86/x64/ARM disassembly via Capstone; optional AI-powered assembly summary |
| **Dynamic (Frida)** | ELF, PE executables — *explicit only* | Runtime instrumentation via Frida: hooks dangerous imports (`system`, `execve`, `gets`, etc.), detects self-modifying/RWX memory regions, traces file opens and exported `.so` function calls; requires `frida` and `frida-tools` (optional) |

### Analysis Modes
- **Fast** – Runs only the most targeted checks for quick results.
- **Deep** – Runs exhaustive checks including brute-force decoding, extended steganography analysis, and broader entropy scanning.

### Intelligence Pipeline

After the analyzers finish, CTF Hunter runs a multi-stage intelligence pipeline on the collected findings:

1. **Confidence Scoring** – Every finding is scored 0–1 based on corroboration (multiple independent analyzers flagging the same byte range), flag-pattern matches in decoded output, entropy reduction after decoding, and penalties for high-entropy or non-printable garbage.

2. **Content Re-dispatch** – Extracted blobs (decoded Base64 strings, decompressed streams, carved files, etc.) are classified by magic bytes and encoding, then re-routed through the appropriate analyzers automatically, enabling multi-layer analysis without any manual steps.

3. **Hypothesis Engine** – Applies 30 built-in CTF attack-pattern rules to the scored findings, producing ranked attack hypotheses without requiring an API key. Each hypothesis includes:
   - A category badge (pwn, rev, crypto, steg, forensics, web)
   - A confidence score
   - The findings that support it
   - What to look for next to confirm it
   - Concrete shell commands / tool invocations
   - An ordered transform-pipeline suggestion

4. **Exploit Generator** – When a `pwn`-category hypothesis reaches ≥ 0.6 confidence, CTF Hunter automatically generates a ready-to-run pwntools exploit script. Supported vulnerability classes:
   - Stack buffer overflow with ROP chain (win-function or ret2libc)
   - Format string exploitation
   - RSA attacks (small-e cube-root, factorable-N decryption, common-modulus recovery)

5. **Workspace Correlator** – Runs pairwise cross-file analysis on all loaded files to surface relationships such as shared strings, hash values that appear in a companion file, and password hints that match encrypted archives in the same session.

### AI Integration (Optional)
When configured with a Claude API key, CTF Hunter extends the intelligence pipeline:
- The **Hypothesis Engine** sends the top 15 findings to Claude for additional AI-generated hypotheses beyond the 30 built-in rules.
- The **Challenge Panel** generates a structured attack plan from a free-text challenge description.
- The **Disassembly** analyzer produces a human-readable AI summary of disassembled code.
- The **Transform Pipeline** can submit its final output to Claude as a hypothesis for contextual reasoning.

### External Tool Suggestions
After analysis, CTF Hunter maps its findings to relevant external CTF tools (e.g., `zsteg`, `steghide`, `john`, `fcrackzip`) and shows which ones are installed on your system along with suggested usage commands.

### UI Panels and Tabs

| Panel / Tab | What It Does |
|-------------|--------------|
| **Findings Tree** | All findings organized by file and severity (HIGH → MEDIUM → LOW → INFO); click any finding to pin it to the Transform Pipeline |
| **Flag Summary** | Aggregates all flag-match findings for quick copy-to-clipboard access |
| **Attack Plan** | Ranked hypothesis cards with category badge, confidence bar, present/missing findings, suggested commands, and a **Generate Exploit** button for pwn-category hypotheses |
| **Hex Viewer** | Byte-level display with ASCII sidebar and color highlighting |
| **Steg Viewer** | Visualizes LSB bit-planes and steganographic extractions |
| **File Intel** | Per-file MD5/SHA1/SHA256/SHA512 hashes, interactive entropy chart, configurable strings extractor, and a quick-decode playground |
| **Transform Pipeline** | Chainable encoding transforms with live hex+ASCII preview; supports Base64 encode/decode, Hex encode/decode, XOR (hex or text key), ROT-N, Zlib compress/decompress, AES-ECB/CBC decrypt, Reverse Bytes, integer base conversion, URL encode/decode, and Regex Extract; pipelines can be saved/loaded as JSON |
| **Timeline** | Chronological visualization of all extracted timestamps across loaded files |
| **Network Console** | Packet inspection for PCAP analysis |
| **Tool Suggester** | Shows relevant external tools for current findings, with install status and usage examples |
| **Challenge Panel** | Free-text input for AI-generated attack plans from challenge descriptions |
| **Session Diff** | Side-by-side comparison of two saved sessions; new findings highlighted green, removed in red, modified in yellow |

### Additional Features
- **Watch Folder** – Monitors a directory and automatically analyzes new files as they appear.
- **Session Save/Load** – Save an analysis session (findings, notes, flag pattern) to a `.ctfs` JSON file and reload it later.
- **Drag-and-drop** file loading.
- **Dynamic analysis** – An explicit **Run Dynamic Analysis** button in the Binary analyzer tab launches Frida instrumentation on ELF/PE files (requires optional `frida` and `frida-tools` packages).

---

## Supported File Types

Images (PNG, JPEG, GIF, BMP), audio (WAV, MP3), video, archives (ZIP, gzip, zlib), documents (PDF, DOCX, DOC, XLS, PPT), executables (ELF, PE), packet captures (PCAP), SQLite databases, PEM/DER crypto key files, disk images, and generic binary files.

---

## Installation

**Requirements:** Python 3.9+

```bash
cd ctf_hunter
pip install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `PyQt6` | Desktop GUI |
| `Pillow` | Image processing for steganalysis |
| `mutagen` | Audio metadata extraction |
| `python-magic` | File-type detection via magic bytes |
| `numpy` | Entropy and statistical analysis |
| `scapy` | PCAP parsing and protocol analysis |
| `capstone` | x86/x64/ARM disassembly |
| `r2pipe` | Radare2 Python bindings (the `radare2` binary must also be installed at the system level: `apt install radare2` or `brew install radare2`) |
| `anthropic` | Claude AI client |
| `watchdog` | Watch-folder directory monitoring |
| `pyzipper` | ZIP archive analysis and cracking |
| `olefile` | OLE/Office file parsing |
| `PyMuPDF` | PDF parsing |
| `pyinstaller` | Standalone executable packaging |
| `bcrypt` | bcrypt hash cracking |

### Optional Dependencies

These are **not** installed by default. Edit `requirements.txt` to enable them:

| Package | Enables |
|---------|---------|
| `pycryptodome` | RSA key parsing and AES-ECB/CBC transforms in the Transform Pipeline; the RSA analyzer and AES transforms degrade gracefully without it |
| `frida`, `frida-tools` | Dynamic binary instrumentation (Frida analyzer) |
| `pytsk3` | Disk image forensics via The Sleuth Kit |

---

## Usage

```bash
cd ctf_hunter
python main.py
```

This launches the GUI. Load files by dragging and dropping them onto the file list, or use the **Open** button in the toolbar. Click **Analyze** to run all applicable analyzers. Results appear in the findings tree, organized by severity (HIGH, MEDIUM, LOW, INFO).

### Workflow

1. **Load files** – Drag files onto the file list or click **Open**. Multiple files can be loaded at once; the Workspace Correlator will cross-reference them automatically.
2. **Set flag pattern** (optional) – Enter the competition's flag format (e.g. `picoCTF\{[^}]+\}`) in the flag-pattern field so every analyzer uses the correct regex.
3. **Choose analysis mode** – Select **Fast** or **Deep** from the toolbar.
4. **Analyze** – Click **Analyze**. Progress is shown per-analyzer.
5. **Review findings** – Browse the Findings Tree. Click a finding to inspect its detail and optionally pin it to the Transform Pipeline for further decoding.
6. **Check Attack Plan** – Open the **Attack Plan** tab to see ranked hypotheses and suggested next steps. For pwn-category hypotheses, click **Generate Exploit** to produce a pwntools script.
7. **Use Transform Pipeline** – Chain encoding transforms (Base64 → XOR → Zlib, etc.) to manually decode suspicious data. The output feeds back into the hypothesis engine if desired.

### Optional: AI features

1. Open **Settings** from the toolbar.
2. Enter your [Anthropic API key](https://console.anthropic.com/).
3. The Challenge Panel, Hypothesis Engine, and Disassembly analyzer will now include AI-generated insights.

### Optional: Custom wordlist for hash/archive cracking

By default, CTF Hunter uses a bundled `rockyou_top1000.txt` wordlist (top 1,000 RockYou passwords). To use a full RockYou list or any custom wordlist, set the path in **Settings**.

### Optional: Dynamic Analysis with Frida

1. Install Frida: `pip install frida frida-tools`
2. Load an ELF or PE binary.
3. Run a standard analysis first; then click **Run Dynamic Analysis** in the Binary analyzer panel.
4. CTF Hunter spawns the binary under Frida, injects a JavaScript agent, and reports dangerous function calls, RWX memory regions, file opens, and exported function invocations as findings.

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
├── main.py                        # Entry point – launches the PyQt6 GUI
├── build.py                       # PyInstaller packaging script
├── requirements.txt               # Python dependencies
├── core/
│   ├── dispatcher.py              # File-type detection and analyzer routing
│   ├── ai_client.py               # Claude API integration
│   ├── confidence.py              # Confidence scoring for all findings
│   ├── content_classifier.py      # Classifies extracted blobs (magic bytes, encoding, entropy)
│   ├── content_redispatcher.py    # Re-routes extracted content through appropriate analyzers
│   ├── deduplicator.py            # Removes duplicate findings
│   ├── exploit_generator.py       # Auto-generates pwntools and RSA exploit scripts
│   ├── extracted_content.py       # Data class for content extracted by analyzers
│   ├── external.py                # Wrappers for strings, file, exiftool, tshark
│   ├── hypothesis_engine.py       # 30-rule attack-path hypothesis engine (+ AI path)
│   ├── report.py                  # Finding and Session data classes
│   ├── session_diff.py            # Diffs two sessions to surface new/removed/changed findings
│   ├── tool_suggester.py          # External CTF tool recommendations
│   ├── watchfolder.py             # Directory monitoring
│   └── workspace_correlator.py    # Cross-file pairwise finding correlation
├── analyzers/
│   ├── base.py                    # Analyzer base class
│   ├── archive.py                 # ZIP / compressed-file analysis
│   ├── audio.py                   # Audio metadata and LSB extraction
│   ├── binary.py                  # ELF/PE static analysis
│   ├── classical_cipher.py        # Classical cipher detection and solving
│   ├── crypto.py                  # Hash identification, cracking, XOR recovery
│   ├── crypto_rsa.py              # RSA attack suite (Wiener, small-e, factordb, etc.)
│   ├── database.py                # SQLite analysis
│   ├── disassembly.py             # Capstone disassembly (+ AI summary)
│   ├── document.py                # PDF / Office document analysis
│   ├── dynamic_frida.py           # Runtime Frida instrumentation (explicit only)
│   ├── encoding.py                # Encoding detection and decoding
│   ├── filesystem.py              # Disk image forensics via Sleuth Kit
│   ├── forensics_timeline.py      # Timestamp extraction and timeline reconstruction
│   ├── generic.py                 # Universal entropy/string/flag analysis
│   ├── image.py                   # Image metadata and LSB analysis
│   ├── image_format.py            # Deep PNG/JPEG/GIF/BMP format parsing
│   ├── pcap.py                    # Packet capture analysis
│   └── steganalysis.py            # Comprehensive steganography detection
├── ui/
│   ├── main_window.py             # Main application window and dock layout
│   ├── attack_plan_tab.py         # Hypothesis cards with exploit generation
│   ├── challenge_panel.py         # AI attack-plan input panel
│   ├── diff_view.py               # Syntax-highlighted diff widget
│   ├── file_intel.py              # File hashes, entropy chart, strings, decode playground
│   ├── flag_summary.py            # Aggregated flag matches with copy-to-clipboard
│   ├── help_tab.py                # In-app help and keyboard shortcuts
│   ├── hex_viewer.py              # Byte-level hex + ASCII viewer
│   ├── network_console.py         # Packet inspection for PCAP files
│   ├── result_panel.py            # Findings tree with severity grouping
│   ├── session.py                 # Session save/load (.ctfs JSON)
│   ├── session_diff_panel.py      # Side-by-side session comparison panel
│   ├── settings_dialog.py         # API key, wordlist path, and preferences
│   ├── steg_viewer.py             # LSB bit-plane and steg-extraction visualizer
│   ├── timeline_tab.py            # Chronological timestamp visualization
│   ├── tool_suggester_panel.py    # External tool recommendations panel
│   └── transform_pipeline.py      # Chainable encoding-transform pipeline
└── wordlists/
    └── rockyou_top1000.txt        # Bundled password list for cracking
```
