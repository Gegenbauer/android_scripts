#!/usr/bin/env python3
"""
This script provides a function to dump the live View hierarchy of a focused Android application using Frida.
It leverages the `view.js` script to inspect the application's memory and retrieve detailed view information.
"""
from typing import List, Dict, Optional

from android_util_impls.manager import android_util_manager
from script_base.frida_utils import FridaScriptExecutor
from script_base.utils import run_command, ensure_directory_exists
from script_base.log import logger
import os

FRIDA_SCRIPT_FILE = "view.js"

def dump_views_with_frida(package_name: str, device_id: Optional[str]=None) -> bool:
    """
    Attaches to the foreground application and dumps its live View hierarchy using a Frida script.

    This function identifies the foreground application, injects a Frida script (`view.js`)
    to traverse the UI tree, and returns detailed information for each View.

    Args:
        app_name (Optional[str]): The package name of the target application.
                                  If not provided, it will be automatically detected.
        device_id (Optional[str]): The ID of the target Android device.

    Returns:
        Optional[List[Dict]]: A list of dictionaries, where each dictionary represents a View,
                              or None if an error occurs.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    frida_script_path = os.path.join(script_dir, FRIDA_SCRIPT_FILE)

    try:
        executor = FridaScriptExecutor(frida_script_path, device_id=device_id)

        android_util = android_util_manager.select()
        pid = android_util.get_pid_of_app(package_name, executor.device)
        if pid is None or pid == -1:
            logger.warning(f"Process '{package_name}' not found.")
            return False

        # Define the RPC calls to be executed
        # Format: (function_name, (arg1, arg2, ...), wait_for_result)
        rpc_calls = [
            #("dumpviewsbytype", ("android.widget.TextView",), True)
            #("dumpviewhierarchy", (), True)
            ("callviewmethod", (0xc01c26e, "setText", ""), True)
        ]

        # Run the script and execute all defined calls
        executor.run_script(pid, rpc_calls)

        if executor.error_occurred:
            logger.error("Failed to dump views. Please check the Frida script and device logs.")
            return False
        else:
            logger.info("View hierarchy dumped successfully.")
            return True

    except Exception as e:
        logger.error(f"An unexpected error occurred during execution: {e}", exc_info=True)
        return False


if __name__ == "__main__":
    # Simple test case: Dump views from the foreground application.
    logger.info("Running test: Dumping views from the current foreground app...")
    dump_views_with_frida("com.android.settings")
