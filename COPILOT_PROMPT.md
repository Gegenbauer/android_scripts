# GitHub Copilot Prompt (Custom for this Repository)

Goal: When writing new scripts under `python_scripts/`, strictly follow the conventions below, always reusing the `script_base` base classes and utility functions. Overall style should reference `git.py`.

---

You are GitHub Copilot. Please generate scripts according to the following requirements:

- Script Location
  - All new scripts must be placed in the `python_scripts/` directory.
  - The entry point must be `if __name__ == "__main__":`, using `ScriptManager` to register and run commands.

- Base Classes & Utilities (Must Reuse)
  - Import from `script_base`:
    - `from script_base.script_manager import ScriptManager, Command`
    - `from script_base.utils import run_command, ensure_directory_exists`
    - `from script_base.log import logger`
  - Do not implement your own command dispatch, logging, or directory creation—always reuse the above utilities.

- Command Style
  - Each subcommand should inherit from `Command` and implement:
    - `add_arguments(self, parser: argparse.ArgumentParser)` to define CLI arguments
    - `execute(self, args: argparse.Namespace)` to implement business logic
  - Use clear English docstrings to describe the command's purpose, parameters, and behavior; `ScriptManager` will use this as help info.
  - Example command registration:
    - `manager.register_command("your-command", YourCommand(), help_text="One-line summary")`

- CLI Design Guidelines
  - Use `--kebab-case` for long arguments, and optionally add short aliases (e.g., `-p`).
  - Use `parser.add_mutually_exclusive_group()` for mutually exclusive options.
  - Set explicit defaults, provide complete help text, and use `required=True` for required arguments.

- Unified Utility Usage
  - Shell/external commands: Prefer `run_command(["cmd", "arg"], check_output=...)`.
    - Use `check_output=False` if you only need to execute and ignore output.
    - On error, let the utility function raise and print stderr.
  - Directories: Use `ensure_directory_exists(path)` to ensure existence.
  - Logging: Use `logger in script_base.log: logger.info("This is a log message.")`.

- Android Device Operations (Sample Conventions)
  - ADB pull: `run_command(["adb", "pull", remote, local], check_output=False)`.
  - Open file manager:
    - macOS: `open path`; Windows: `explorer path`; Linux: `xdg-open path` (use `run_command`).
  - Open VSCode: `run_command(["code", "-g", f"{file}:{line}"])`, line number optional.

- Cache/Output Directory Conventions
  - The local cache root directory should first read the `cache_files_dir` environment variable, otherwise use the current directory `.`.
  - Recommended organization: `<cache_root>/<feature_name>/<sanitized_key>_<timestamp>/...`.
  - `timestamp` should use `datetime.now().strftime("%Y%m%d_%H%M%S")`.

- Exception Handling & Robustness
  - Add try/except for key external commands; print errors to `stderr` and provide next-step hints when possible.
  - When reading files, prefer `encoding="utf-8"` and set `errors="replace"` to avoid crashes from invalid characters.

- Frida integration
  - All Frida JS scripts **must export functions with lowercase names** in `rpc.exports` (e.g., `rpc.exports = { exportbitmaps: ... }`).
  - When calling Frida RPC methods from Python, **always use lowercase method names** (e.g., `executor.call_rpc('exportbitmaps', ...)`).
  - All Python code that interacts with Frida **must use the shared frida_utils.py module** (do not use frida directly in business scripts).
  - For Python scripts whose sole purpose is to provide a callable function for Frida script invocation (not a CLI tool), you **do not need to implement command-line argument parsing or ScriptManager/Command**. Just provide a main function, utility functions, and (optionally) a test block under `if __name__ == "__main__":`.
  - Example usage:
    ```python
    from script_base.frida_utils import FridaScriptExecutor
    executor = FridaScriptExecutor('your_script.js', device_id=device.id)
    executor.run_script(pid, [("exportbitmaps", (), True)])
    ```
  - Frida JS/Python interaction specification:
    - Frida JS scripts and Python should communicate, log, report progress, and output errors uniformly using send({type, message}), where type can be info, error, finish, etc., and message is a string.
    - Direct use of console.log is prohibited; all messages must be sent via send.
    - For specific style, refer to set_language.js.

- Skeleton Template (Reference for New Scripts)
  - Add shebang at the top: `#!/usr/bin/env python3`.
  - Typical structure:

```
#!/usr/bin/env python3
import argparse
import os
import sys
from datetime import datetime
from script_base.script_manager import ScriptManager, Command
from script_base.utils import run_command, ensure_directory_exists
from script_base.log import logger

class YourCommand(Command):
    """One-line description of the command's purpose.

    More detailed multi-line description:
    - Parameter explanations
    - Behavioral notes
    """
    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument("--path", "-p", type=str, required=True, help="Example parameter")
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--flag-a", action="store_true", help="Option A")
        group.add_argument("--flag-b", action="store_true", help="Option B")

    def execute(self, args: argparse.Namespace):
        ensure_directory_exists("/tmp")
        logger.info(f"Processing path: {args.path}")
        try:
            run_command(["echo", args.path], check_output=False)
        except Exception as e:
            logger.error(f"Command execution failed: {e}", e)
            return
        print("Done")

if __name__ == "__main__":
    manager = ScriptManager(description="Script collection: unified command-line tools based on script_base.")
    manager.register_command("your-command", YourCommand(), help_text="One-line summary")
    manager.run()
```

- Reference Files (Read these first and follow their style)
  - `python_scripts/script_base/script_manager.py`
  - `python_scripts/script_base/utils.py`
  - `python_scripts/script_base/script_impl_sample.py`
  - `python_scripts/git.py` (for style, structure, error handling)

- Pre-commit Checklist
  - [ ] Uses ScriptManager/Command system
  - [ ] Reuses utils: `run_command/ensure_directory_exists/logger`
  - [ ] Argument naming, help text, and mutually exclusive groups follow conventions
  - [ ] Key external commands have exception handling
  - [ ] Output is user-friendly (in English), and as concise as possible
  - [ ] All code comments and log messages must be written in English.
