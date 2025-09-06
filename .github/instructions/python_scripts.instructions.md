---
description: Conventions for scripts in python_scripts
applyTo: "python_scripts/**/*.py"
---

When creating or editing scripts under `python_scripts/`, follow these rules:

- Always use the `script_base` framework:
  - `from script_base.script_manager import ScriptManager, Command`
  - `from script_base.utils import run_command, ensure_directory_exists, log_message`
- Structure commands as classes (subclass `Command`), implement `add_arguments` and `execute`.
- Register commands with `ScriptManager.register_command(...)` and run via a main entry point.
- CLI:
  - Use `--kebab-case` long flags, add short aliases when useful.
  - Provide clear help text, defaults, and mutually exclusive groups.
- External processes: call with `run_command(["tool", args...], check_output=...)`.
- Filesystem: ensure output dirs with `ensure_directory_exists`; log progress with `log_message`.
- Android-specific helpers:
  - Use `adb` via `run_command(["adb", ...])`.
  - Open folders: `open` (macOS) / `explorer` (Windows) / `xdg-open` (Linux).
  - Open in VS Code: `code -g file[:line]`.
- Caching/output layout: `${cache_files_dir:-.}/<feature>/<sanitized>_<YYYYMMDD_HHMMSS>/...`.
- Error handling: catch failures, print to stderr, avoid crashing on encoding by using `encoding="utf-8"`, `errors="replace"`.
