#!/usr/bin/env python3
import os
from script_base.log import logger
from script_base.frida_utils import FridaScriptExecutor
from android_util_impls.manager import android_util_manager

# Define the Frida script file name
FRIDA_SCRIPT_FILE = "set_language.js"

def set_android_language(language, country, package_name="system_server", device_id=None):
    """
    Sets the system language on an Android device using Frida.

    :param language: Language code (e.g., 'en', 'zh').
    :param country: Country/region code (e.g., 'US', 'CN').
    :param package_name: The package name of the target process.
    :param device_id: The ID of the specific device to connect to.
    """
    # Get the directory of the current script and construct the full path to the Frida script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    frida_script_path = os.path.join(script_dir, FRIDA_SCRIPT_FILE)

    try:
        executor = FridaScriptExecutor(frida_script_path, device_id=device_id)
        
        android_util = android_util_manager.select()
        pid = android_util.get_pid_of_app(package_name, executor.device)
        if pid is None or pid == -1:
            logger.warning(f"Process '{package_name}' not found. Trying fallback target 'system_server'...")
            pid = android_util.get_pid_of_app("system_server", executor.device)
            if pid is None or pid == -1:
                logger.error("Fallback process 'system_server' also not found. Please ensure the device is connected and the target process is running.")
                return False

        # Define the RPC calls to be executed
        # Format: (function_name, (arg1, arg2, ...), wait_for_result)
        rpc_calls = [
            ("setsystemlanguage", (language, country), True)
        ]

        # Run the script and execute all defined calls
        executor.run_script(pid, rpc_calls)
        
        if executor.error_occurred:
            logger.error("Failed to set language. Please check the Frida script and device logs.")
            return False
        else:
            logger.info("Language setting command sent successfully.")
            return True

    except Exception as e:
        logger.error(f"An unexpected error occurred during execution: {e}", exc_info=True)
        return False

# Optional: test/demo code
if __name__ == "__main__":
    # Example usage
    set_android_language("en", "US")