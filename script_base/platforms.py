#!/usr/bin/env python3
"""
Platform-specific abstractions for handling OS differences, such as process management.
This module uses a factory pattern to ensure the correct platform-specific
implementation is always returned.
"""

import os
import platform
import shutil
import subprocess
import signal
from typing import List, Optional

from script_base.utils import run_command

# --- Base and Platform-Specific Classes ---

class PlatformBase:
    """
    Base class for platform-specific helpers. The __new__ method acts as a factory,
    returning an instance of the appropriate subclass based on the current OS.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        # Singleton factory pattern: ensure only one instance of the correct platform class is created.
        if cls._instance is None:
            system_name = platform.system().lower()
            if system_name.startswith("win"):
                target_cls = WindowsPlatform
            elif system_name == "darwin":
                target_cls = MacOSPlatform
            else: # Default to Linux/POSIX behavior
                target_cls = LinuxPlatform
            
            # We instantiate the target class, not the base class.
            cls._instance = super().__new__(target_cls)
        return cls._instance

    def __init__(self, name: Optional[str] = None) -> None:
        # The __init__ will be called on the subclass instance.
        self.name = name or platform.system().lower()

    def get_adb_file_name(self) -> str:
        """Returns the adb executable filename. To be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement this method.")

    def start_new_process(self, command: List[str], cwd: Optional[str] = None) -> subprocess.Popen:
        """Starts a new process in a new process group. To be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement this method.")
    
    def terminate_process(self, process: subprocess.Popen) -> None:
        """Terminates the given process and its children."""
        raise NotImplementedError("Subclasses must implement this method.")
    
    def open_in_vscode(self, path: str) -> None:
        """Opens the specified path in Visual Studio Code."""
        raise NotImplementedError("Subclasses must implement this method.")


class WindowsPlatform(PlatformBase):
    """Windows-specific platform implementation."""
    def get_adb_file_name(self) -> str:
        return "adb.exe"

    def start_new_process(self, command: List[str], cwd: Optional[str] = None) -> subprocess.Popen:
        """Starts a new process using Windows-specific creation flags."""
        return subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=cwd,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
        )
        
    def terminate_process(self, process: subprocess.Popen) -> None:
        """Terminates the given process using Windows-specific methods."""
        process.send_signal(signal.CTRL_BREAK_EVENT)
        
    def open_in_vscode(self, path: str) -> None:
        """Opens the specified path in Visual Studio Code on Windows."""
        # check if code.exe is available in PATH
        code_path = shutil.which("code")
        if code_path:
            run_command([code_path, "-g", path], check_output=False, shell=True)
        else:
            logger.debug("VSCode command 'code' not found in PATH. Please ensure VSCode is installed and added to PATH.")
            
            # Find path of Code.exe in system environment variables
            # Iterate through PATH environment variable to find Code.exe
            for key, value in os.environ.items():
                if key.upper() == "PATH":
                    paths = value.split(os.pathsep)
                    for p in paths:
                        code_path = os.path.join(p, "Code.exe")
                        if os.path.isfile(code_path):
                            logger.debug(f"Found VSCode executable at: {code_path}")
                            try:
                                subprocess.run([code_path, "-g", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                return
                            except Exception as e:
                                from script_base.log import logger
                                logger.error(f"failed to open file in VSCode: {e}", e)
                                raise


class PosixPlatform(PlatformBase):
    """Base class for POSIX-compliant systems (Linux, macOS)."""
    def get_adb_file_name(self) -> str:
        return "adb"

    def start_new_process(self, command: List[str], cwd: Optional[str] = None) -> subprocess.Popen:
        """Starts a new process in a new session using os.setsid."""
        return subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=cwd,
            preexec_fn=os.setsid
        )
        
    def terminate_process(self, process: subprocess.Popen) -> None:
        """Terminates the given process and its children using os.killpg."""
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        
    def open_in_vscode(self, path: str) -> None:
        """Opens the specified path in Visual Studio Code on POSIX systems."""
        if not shutil.which("code"):
            from script_base.log import logger
            logger.error("VSCode command 'code' not found in PATH. Please ensure VSCode is installed and added to PATH.")
            return
        try:
            subprocess.Popen(["code", "-g", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            from script_base.log import logger
            logger.error(f"failed to open file in VSCode: {e}", e)
            raise

class LinuxPlatform(PosixPlatform):
    """Linux-specific platform implementation."""
    pass

class MacOSPlatform(PosixPlatform):
    """macOS-specific platform implementation."""
    pass


# --- Global Instance ---
# When any module imports 'current_platform', it will trigger the factory
# in PlatformBase.__new__ and receive the correct platform-specific instance.
current_platform = PlatformBase()