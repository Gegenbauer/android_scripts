# Workspace code-generation instructions

Keep responses aligned with this project's conventions. Apply to all code-generation tasks in this workspace.

- Python scripts
  - Location: `python_scripts/`
  - Use `script_base` framework:
    - `from script_base.script_manager import ScriptManager, Command`
    - `from script_base.utils import run_command, ensure_directory_exists, log_message`
  - Each feature is a Command subclass with:
    - `add_arguments(self, parser)` for CLI
    - `execute(self, args)` for logic
  - Register commands via `ScriptManager.register_command` and run in `if __name__ == "__main__":`.
  - CLI style: kebab-case flags, helpful `--help`, use mutually exclusive groups when needed.
  - Shell calls: prefer `run_command([...])` (use `check_output=False` for fire-and-forget).
  - Files/dirs: ensure with `ensure_directory_exists`, log with `log_message`.

- Android utilities
  - Prefer `adb` via `run_command(["adb", ...])`.
  - Open file manager: macOS `open`, Windows `explorer`, Linux `xdg-open`.
  - Open VS Code files: `code -g file[:line]`.

- Caching convention
  - Prefer base dir from env `cache_files_dir` or `.`.
  - Use `<cache_root>/<feature>/<sanitized_key>_<timestamp>/...`.


- Robustness
  - Wrap external commands in try/except and print errors to stderr.
  - Read text with `encoding="utf-8"`, `errors="replace"` when uncertain.

- Python 异常处理规范
  - 只捕获能处理的异常，优先 except 具体异常类型，避免裸 except。
  - 日志打印异常时，使用 `logger.exception(...)` 或 `logger.error(..., exc_info=True)`，确保输出完整 traceback。
  - 捕获异常后如不能完全处理，务必 `raise` 重新抛出，让上层能感知和处理。
  - 日志内容应包含异常类型、信息、完整堆栈，可选上下文参数。
  - 库/工具函数只做日志和 raise，不直接 print 或 exit。
  - 外部调用处如需定位调用链，也应用 try/except 并 logger.exception 打印。
