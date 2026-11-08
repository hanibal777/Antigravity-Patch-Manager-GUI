# Antigravity Patch Manager GUI

A Windows 10/11 desktop interface for the Antigravity patch manager. The GUI wraps the
verified patching engine in [`manager.py`](manager.py) with a native Tkinter window, so
component status, patching, and restoration can be driven from a graphical interface
instead of the terminal.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Running from Source](#running-from-source)
- [Portable Windows Executable](#portable-windows-executable)
- [Building the Executable](#building-the-executable)
- [Project Layout](#project-layout)
- [Security Note](#security-note)
- [Credits and Attribution](#credits-and-attribution)
- [License](#license)

---

## <a id="features"></a>Features

- **Windows 10/11 desktop interface** — a native Tkinter window with a clean card layout,
  no browser or web runtime involved.
- **Four component status rows** — one row per supported target:
  - Antigravity IDE
  - Antigravity IDE Extension
  - Antigravity Manager
  - Antigravity CLI
- **Component detection and diagnostics** — each row shows the detected installation path,
  the current state (`PATCHED`, `UNPATCHED`, `NOT FOUND`, `UNSUPPORTED`, `ERROR`,
  `UNKNOWN`), and short diagnostic details. A per-row **Check** button re-runs detection.
- **Activity logs with Copy and Clear** — every operation is written to a timestamped
  activity log panel. **Copy** places the log contents on the Windows clipboard and
  **Clear** empties the panel.
- **Existing Backup/Restore support** — patching and restoration use the same backup
  verification, pre-write rescan, post-write verification, rollback, and `fsync`
  behavior as the command-line engine. Restoring a component returns it to its original
  state from the backup created before patching.
- **Python/Tkinter architecture** — the GUI is a thin front end; all discovery, gate
  verification, binary patching, and file restoration are delegated to the core engine.

---

## <a id="requirements"></a>Requirements

- Windows 10 or Windows 11 (x64).
- Python 3.8 or newer, with Tkinter available (included in the standard Windows
  Python installer).
- No third-party packages are required to run the GUI.

---

## <a id="running-from-source"></a>Running from Source

From the repository root:

```bash
python gui.py
```

The launcher starts the desktop window. The command-line interface of the core engine
remains available through [`manager.py`](manager.py) for scripted use.

---

## <a id="portable-windows-executable"></a>Portable Windows Executable

A portable Windows executable can be produced with PyInstaller. The resulting build is a
single self-contained executable that does not require a separate Python installation on
the target machine. Build artifacts are excluded from version control by
[`.gitignore`](.gitignore).

---

## <a id="building-the-executable"></a>Building the Executable

### Prerequisites

- Windows 10 or Windows 11 (x64).
- Python 3.8 or newer with Tkinter.
- PyInstaller installed in the build environment:

  ```bash
  pip install pyinstaller
  ```

### Verified build instructions

Run the following from the repository root:

```bash
pyinstaller --noconfirm --onefile --windowed --name AntigravityPatchManager gui.py
```

- `--onefile` produces a single portable executable.
- `--windowed` suppresses the console window for the GUI.
- The output is written to the `dist/` directory.

The `build/`, `dist/`, and `*.spec` paths are ignored by Git, so build output is never
committed.

---

## <a id="project-layout"></a>Project Layout

| Path | Purpose |
| :--- | :--- |
| [`gui.py`](gui.py) | Entry point that launches the desktop GUI. |
| [`ag_gui/app.py`](ag_gui/app.py) | Tkinter window, component rows, and activity log panel. |
| [`ag_gui/backend.py`](ag_gui/backend.py) | GUI backend adapter that delegates to the core engine. |
| [`manager.py`](manager.py) | Core patching engine and scriptable command-line interface. |
| [`tests/`](tests) | Regression and transaction tests. |
| [`docs/upstream/`](docs/upstream) | Original upstream documentation. |

---

## <a id="security-note"></a>Security Note

This GUI build focuses on patching and restoration only. The account management, OAuth
token access, and quota-monitoring code present in the upstream project has been removed
from this repository. No credentials, tokens, or profile data are read, stored, or
displayed by the GUI.

---

## <a id="credits-and-attribution"></a>Credits and Attribution

- **Original author:** QNIX-Dev
- **Upstream repository:**
  <https://github.com/QNIX-Dev/eligibility-antigravity-patcher>
- **Original documentation:** the unmodified upstream documentation is preserved in
  [`docs/upstream/`](docs/upstream) — see
  [`docs/upstream/README.md`](docs/upstream/README.md) (Russian) and
  [`docs/upstream/README.en.md`](docs/upstream/README.en.md) (English).

This project builds on the patching engine and documentation created by QNIX-Dev and is
distributed under the same MIT license.

---

## <a id="license"></a>License

Released under the MIT License. See [`LICENSE`](LICENSE) for the full text.

Copyright (c) 2026 QNIX-Dev
