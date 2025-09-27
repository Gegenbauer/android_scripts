# Workspace code-generation instructions

Keep responses aligned with this project's conventions. Apply to all code-generation tasks in this workspace.

- Python scripts
  - Location: `python_scripts/`
  - Use `script_base` framework:
    - `from script_base.script_manager import ScriptManager, Command`
    - `from script_base.utils import run_command, ensure_directory_exists`
    - `from script_base.log import logger`
  - Each feature is a Command subclass with:
    - `add_arguments(self, parser)` for CLI
    - `execute(self, args)` for logic
  - Register commands via `ScriptManager.register_command` and run in `if __name__ == "__main__":`.
  - CLI style: kebab-case flags, helpful `--help`, use mutually exclusive groups when needed.
  - Shell calls: prefer `run_command([...])` (use `check_output=False` for fire-and-forget).
  - Files/dirs: ensure with `ensure_directory_exists`, log with `logger.info(...)`.

- Android utilities
  - Prefer `adb` via `run_command(["adb", ...])`.
  - Open file manager: macOS `open`, Windows `explorer`, Linux `xdg-open`.
  - Open VS Code files: `code -g file[:line]`.

- Caching convention
  - Prefer base dir from env `cache_files_dir` or `.`.
  - Use `<cache_root>/<feature>/<sanitized_key>_<timestamp>/...`.

- All code comments and log messages must be written in English.

- Robustness
  - Wrap external commands in try/except and print errors to stderr.
  - Read text with `encoding="utf-8"`, `errors="replace"` when uncertain.

- Python exception handling conventions
  - Only catch exceptions you can handle; prefer catching specific exception types and avoid bare excepts.
  - When logging exceptions, use `logger.error(f"adb pull permission error: {e}", e)` to ensure the full traceback is output.
  - If you cannot fully handle an exception after catching it, always `raise` it again so that upper layers can be aware and handle it.
  - Log content should include exception type, message, full stack trace, and optional context parameters.
  - Library/utility functions should only log and raise, not directly print or exit.
  - If you need to trace the call chain at the external call site, also use try/except and logger.error for logging.

- Frida JS/Python interaction specification
  - Frida JS scripts and Python should communicate, log, report progress, and output errors uniformly using send({type, message}), where type can be info, error, finish, etc., and message is a string.
  - Direct use of console.log is prohibited; all messages must be sent via send.
  - For specific style, refer to set_language.js.
