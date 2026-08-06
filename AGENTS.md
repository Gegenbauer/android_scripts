# Project Guide for this Repository

This document is the authoritative guide for working on this codebase. It consolidates the
repo conventions (originally defined under `.github/`) with the actual project layout.
For any Python code you write here, follow the rules below strictly.

## Repository Layout

- `command/` — CLI command implementations. Android commands live in `command/android/`
  and inherit from `AdbCommand` (defined in `command/android/base.py`).
- `android_util_impls/` — reusable Android device operations (e.g. `package_manager_util.py`,
  `activity_manager_util.py`, `base.py`, `manager.py`).
- `script_base/` — shared framework: `script_manager.py`, `utils.py`, `log.py`, `env_setup.py`,
  `platforms.py`, `frida_utils.py`.
- `adb.py` — root CLI entry point that registers all commands via `ScriptManager`.
- Other root-level scripts (`git.py`, `view.py`, `export_bitmaps.py`, etc.) are standalone tools.

## Python Style (Google Python Style Guide)

All Python code in this project must strictly follow the
[Google Python Style Guide](https://google.github.io/styleguide/pyguide.html):

- Function and class definitions must be grouped at the top of the file, after imports and the
  module-level docstring, before any executable code.
- Imports are always at the top of the file, in the order: standard library, third-party, local.
- Use `snake_case` for functions/variables, `CapWords` for classes.
- Use 4 spaces for indentation.
- Each function and class must have a docstring.
- No executable code (other than function/class definitions) should appear before all
  function/class definitions.
- Limit lines to 80 characters when possible.
- Place module-level constants after imports and before function/class definitions.
- Do not insert functions or classes in the middle of other definitions or after executable code.

## CLI Style Guide

- **Long options**: use `--kebab-case` for all long options (e.g. `--device-path`,
  `--convert-mat`).
- **Short options**: provide a short, single-letter option (e.g. `-p`) ONLY for high-frequency,
  core, or required parameters. Avoid short options for boolean flags or functional modifiers
  (use `--no-open`, `--force`, etc. instead).
- **Help text**: always provide clear, concise help text via `help="..."` for every argument.
- Use `parser.add_mutually_exclusive_group()` for mutually exclusive options.
- Set explicit defaults and use `required=True` for required arguments.

## Project Conventions

- **Base classes & utilities (must reuse)**
  - Import from `script_base`: `from script_base.script_manager import ScriptManager, Command`,
    `from script_base.utils import run_command, ensure_directory_exists`,
    `from script_base.log import logger`.
  - Do not implement your own command dispatch, logging, or directory creation.
  - For Android-related commands, prioritize using existing methods from
    `android_util_impls/base.py` (AndroidUtilBase), `android_util_impls/package_manager_util.py`,
    `android_util_impls/activity_manager_util.py`, `script_base/utils.py`, and
    `script_base/frida_utils.py`. Always check these modules first before implementing new
    functionality — avoid duplicating existing methods.
- **Command structure**: each command inherits from `Command` and implements
  `add_arguments(self, parser)` and `execute(self, args)`. Android commands inherit from
  `AdbCommand` and implement `add_custom_arguments(self, parser)` and
  `execute_on_device(self, args, android_util)`. Use clear English docstrings.
- **CLI design**: `--kebab-case` long args, optional short aliases, mutually exclusive groups,
  explicit defaults, complete help text.
- **Utility usage**: shell/external commands → `run_command(["cmd", "arg"], check_output=...)`;
  use `check_output=False` when output is not needed; on error let the utility raise.
  Use `ensure_directory_exists(path)` for directories. Use `logger.info(...)` for logging.
- **Logging**: log messages must be written in English and be user-friendly and concise.

## Cache / Output Directory Conventions

- The local cache root should first read the `cache_files_dir` environment variable, otherwise
  use the current directory `.`.
- Recommended organization: `<cache_root>/<feature_name>/<sanitized_key>_<timestamp>/...`.
- `timestamp` should use `datetime.now().strftime("%Y%m%d_%H%M%S")`.

## Exception Handling & Robustness

- Add try/except around key external commands; log errors and provide next-step hints when
  possible.
- When reading files, prefer `encoding="utf-8"` and set `errors="replace"` to avoid crashes on
  invalid characters.

## Root / Permission Handling

- Before executing an operation that requires root (e.g. reading `/data/system/packages.xml`),
  check `android_util.is_adb_running_as_root()` / `is_rooted()` first. If root is unavailable,
  inform the user (e.g. suggest running `adb root`) instead of silently failing or crashing.

## Frida Integration

- All Frida JS scripts must export functions with **lowercase names** in `rpc.exports`
  (e.g. `rpc.exports = { exportbitmaps: ... }`), and Python must call RPC methods with lowercase
  names (e.g. `executor.call_rpc('exportbitmaps', ...)`).
- All Python code interacting with Frida must use `script_base/frida_utils.py` (never use the
  `frida` package directly in business scripts).
- Python scripts whose sole purpose is to provide a callable function for Frida (not a CLI tool)
  do NOT need argparse/ScriptManager — just provide a main function and optionally a test block
  under `if __name__ == "__main__":`.
- Frida JS ↔ Python communication must use `send({type, message})` where `type` is
  `info`/`error`/`finish`/etc. and `message` is a string. Direct `console.log` is prohibited.
- For style reference see `set_language.js`.

## Pre-commit Checklist

- [ ] Uses the `ScriptManager`/`Command` (or `AdbCommand`) system
- [ ] Reuses utilities: `run_command` / `ensure_directory_exists` / `logger`
- [ ] Argument naming, help text, and mutually exclusive groups follow CLI conventions
- [ ] Key external commands have exception handling
- [ ] Root-requiring operations check root availability first and inform the user otherwise
- [ ] Output is user-friendly (in English) and as concise as possible
- [ ] All code comments and log messages are written in English
