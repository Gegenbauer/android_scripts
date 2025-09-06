import datetime
import os
import platform
import subprocess
from typing import Optional

from script_base.log import logger


def get_current_timestamp() -> int:
    """
    获取当前的 Unix 时间戳。

    Returns:
        int: 当前的 Unix 时间戳。
    """
    return int(datetime.datetime.now().timestamp())

def ensure_directory_exists(path: str):
    """
    确保指定的目录存在，如果不存在则创建。

    Args:
        path (str): 要检查或创建的目录路径。
    """
    if not os.path.exists(path):
        os.makedirs(path)
        logger.debug(f"创建目录: {path}")

def run_command(command: list, cwd: str = None, check_output: bool = True, shell: bool = False
                , text: bool = True, ignore_command_error: bool = False) -> str:
    """
    运行一个 shell 命令并返回其标准输出。
    
    Args:
        command (list): 要执行的命令及其参数。
        cwd (str, optional): 命令执行的工作目录。如果为 None，则使用当前目录。
        check_output (bool, optional): 是否检查命令的标准输出。默认为 True。
        shell (bool, optional): 是否在 shell 中执行命令。默认为 False。如果需要使用管道或重定向等 shell 特性，请设置为 True。
                                如果为 True，则 command 参数应为字符串而不是列表。
                                如果为 False，则 command 参数应为列表，第一个参数必须为一个可执行文件的路径。
        text (bool, optional): 是否将输出作为文本处理。默认为 False。

    Returns:
        str: 命令的标准输出，如果 check_output 为 False，则返回空字符串。
    """
    input_params = {"command": command, "cwd": cwd, "check_output": check_output, "shell": shell, "text": text}
    try:
        # 使用更现代、更健壮的 subprocess.run
        # capture_output=True 会同时捕获 stdout 和 stderr
        process = subprocess.run(
            command,
            cwd=cwd,
            shell=shell,
            text=text,
            capture_output=True,
            check=not ignore_command_error  # 如果不忽略错误，则让 subprocess 自动检查并抛出异常
        )

        if check_output:
            # process.stdout 永远不会是 None，如果没输出，它会是空字符串 ""
            return process.stdout.strip()
        else:
            return ""
            
    except subprocess.CalledProcessError as e:
        # 异常对象 e 中已经包含了 stdout 和 stderr
        # 获取异常，如果包含 (permission, permit) 和 (not, denied, no), 则抛出自定义的权限异常，由调用方捕获处理
        formalized_error_msg = e.stderr.lower()
        if any(x in formalized_error_msg for x in ["permission", "permit"]) and any(y in formalized_error_msg for y in ["not", "denied", "no"]):
            raise PermissionError(f"权限错误: {command} \n {e.stderr}")
        logger.error(
            f"命令执行失败: {command}, input_param=${input_params}\n"
            f"stdout:\n{e.stdout}\nstderr:\n{e.stderr}", exc=e
        )
        raise
    except FileNotFoundError as e:
        logger.error(f"错误: {e} 命令 '{command[0]}' 未找到。input_param=${input_params}。请确保它已安装并 PATH。", exc=e)
        raise
    except Exception as e:
        logger.error(f"未知错误: {e}， input_param=${input_params}", exc=e)
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
        else:
            run_command(["xdg-open", path], check_output=False)

def open_in_vscode(file_path: str, line: Optional[int] = None):
    target = file_path if line is None else f"{file_path}:{line}"
    try:
        run_command(["code", "-g", target], check_output=False)
    except Exception as e:
        logger.error(f"无法通过 VSCode 打开文件: {e}", e)
        raise
from typing import Optional

# ===== 通用工具函数 from adb.py =====
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