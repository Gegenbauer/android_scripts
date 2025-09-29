def set_debugger_app(adb_command: str, package_name: str) -> bool:
    """
    Set the specified application as the debugger application.

    Args:
        adb_command (str): The adb command to use.
        package_name (str): The package name of the application to set as the debugger application.
        device (str): The ID of the device (optional).

    Returns:
        bool: Whether the application was successfully set as the debugger application.
    """
    if not adb_command:
        return False

    try:
        import subprocess
        from script_base.utils import run_command
        from script_base.log import logger

        command = f"{adb_command} shell am set-debug-app -w {package_name}"
        run_command(command, shell=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(
            f"Error occurred while setting application {package_name} as the debugger application: {e}",
            e,
        )
        raise

    return False


def remove_debugger_app(adb_command: str) -> bool:
    """
    Remove the currently set debugger application.

    Args:
        adb_command (str): The adb command to use.

    Returns:
        bool: Whether the debugger application was successfully removed.
    """
    if not adb_command:
        return False

    try:
        import subprocess
        from script_base.utils import run_command
        from script_base.log import logger

        command = f"{adb_command} shell am clear-debug-app"
        run_command(command, ignore_command_error=True, shell=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error occurred while removing the debugger application: {e}", e)
        raise

    return False

def kill_process(adb_command: str, package_name: str) -> bool:
    """
    Kill the specified process on the device.

    Args:
        device (str): The ID of the device.
        package_name (str): The package name of the process to kill.

    Returns:
        bool: Whether the process was successfully killed.
    """
    if not adb_command:
        return False
    try:
        # TODO Confirm if persistent app needs to be distinguished
        from script_base.utils import run_command
        from script_base.log import logger
        command = f"{adb_command} shell am force-stop {package_name}"
        run_command(command, shell=True)
        return True
    except Exception as e:
        return False
