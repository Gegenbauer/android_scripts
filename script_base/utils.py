import datetime
import os
import platform
import subprocess
from typing import Optional

from script_base.log import logger


def get_current_timestamp() -> int:
    """
    Get the current Unix timestamp.

    Returns:
        int: Current Unix timestamp.
    """
    return int(datetime.datetime.now().timestamp())


def ensure_directory_exists(path: str):
    """
    Ensure that the specified directory exists. If it does not exist, create it.

    Args:
        path (str): The directory path to ensure exists.
    """
    if not os.path.exists(path):
        os.makedirs(path)
        logger.debug(f"creating dir: {path}")


def run_command(command: list|str, cwd: str=None, check_output: bool=True, shell: bool=False, text: bool=True, ignore_command_error: bool=False) -> str:
    """
    Run a shell command and return its standard output.
    
    Args:
        command (list): The command and its arguments to execute.
        cwd (str, optional): The working directory for the command. If None, uses the current directory.
        check_output (bool, optional): Whether to return the command's standard output. Defaults to True.
        shell (bool, optional): Whether to execute the command in a shell. Defaults to False. If you need shell features like pipes or redirection, set to True.
                                If True, the command argument should be a string, not a list.
                                If False, the command argument should be a list, and the first argument must be an executable path.
        text (bool, optional): Whether to treat the output as text. Defaults to True.
        ignore_command_error (bool, optional): If True, do not raise exception on command error. Defaults to False.

    Returns:
        str: The standard output of the command, or an empty string if check_output is False.
    """
    input_params = {"command": command, "cwd": cwd, "check_output": check_output, "shell": shell, "text": text}
    logger.debug("input_params: " + str(input_params))
    try:
        # Use the more modern and robust subprocess.run
        # capture_output=True captures both stdout and stderr
        process = subprocess.run(
            command,
            cwd=cwd,
            shell=shell,
            text=text,
            capture_output=True,
            check=not ignore_command_error  # If not ignoring errors, let subprocess check and raise exceptions
        )

        if check_output:
            # process.stdout is never None; if no output, it will be an empty string ""
            return process.stdout.strip()
        else:
            return ""
        
    except subprocess.CalledProcessError as e:
        # The exception object e already contains stdout and stderr
        # If the error message contains (permission, permit) and (not, denied, no), raise a custom PermissionError for the caller to handle
        formalized_error_msg = e.stderr.lower()
        if any(x in formalized_error_msg for x in ["permission", "permit"]) and any(y in formalized_error_msg for y in ["not", "denied", "no"]):
            raise PermissionError(f"Permission error: {command} \n {e.stderr}")
        logger.error(
            f"Command execution failed: {command}, input_param=${input_params}\n"
            f"stdout:\n{e.stdout}\nstderr:\n{e.stderr}", exc=e
        )
        raise
    except FileNotFoundError as e:
        logger.error(f"Error: {e} Command '{command[0]}' not found. input_param=${input_params}. Please ensure it is installed and in PATH.", exc=e)
        raise
    except Exception as e:
        logger.error(f"Unknown error: {e}, input_param=${input_params}", exc=e)
        raise

    
# ===== 通用桌面端方法 =====
def open_in_file_manager(path: str):
    system = platform.system().lower()
    if system.startswith("win"):
        try:
            startfile = getattr(os, "startfile", None)
            if startfile:
                startfile(path)  # type: ignore[misc]
            else:
                run_command(["explorer", path], check_output=False)
        except Exception:
            run_command(["explorer", path], check_output=False)
            raise
    elif system == "darwin":
        run_command(["open", path], check_output=False)
    else:
        import shutil
        if shutil.which("nautilus"):
            run_command(["nautilus", path], check_output=False)
        elif shutil.which("thunar"):
            run_command(["thunar", path], check_output=False)
        elif shutil.which("dolphin"):
            run_command(["dolphin", path], check_output=False)
        elif shutil.which("pcmanfm"):
            run_command(["pcmanfm", path], check_output=False)
        else:
            run_command(["xdg-open", path], check_output=False)


def open_in_vscode(file_path: str, line: Optional[int]=None):
    target = file_path if line is None else f"{file_path}:{line}"
    try:
        run_command(["code", "-g", target], check_output=False)
    except Exception as e:
        logger.error(f"failed to open file in VSCode: {e}", e)
        raise


from typing import Optional


def cache_root_arg_to_path(cache_root_arg: Optional[str]) -> str:
    base = cache_root_arg if cache_root_arg else os.environ.get("cache_files_dir", ".")
    return os.path.abspath(base)


def sanitize_for_fs(path: str) -> str:
    s = path.strip()
    if s.endswith("/"):
        s = s[:-1]
    s = s.replace("\\", "/")
    s = s.replace("/", "_")
    s = s.replace(" ", "_")
    return s if s else "root"


def timestamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def find_key_contains(d: dict, key_part: str) -> Optional[str]:
    """
    Find a key in dict contains key_part (case insensitive).
    return None if not found.

    Args:
        d (dict): The dictionary to search.
        key_part (str): The substring to search for within the dictionary keys.
    """
    key_part_lower = key_part.lower()
    for k in d.keys():
        if key_part_lower in k.lower():
            return k
    return None
