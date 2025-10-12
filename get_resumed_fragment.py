#!/usr/bin/env python3
from android_util_impls.manager import android_util_manager
from script_base.frida_utils import FridaScriptExecutor
from script_base.log import logger
import os
import json

def get_resumed_fragment(package_name, frida_script="get_resumed_fragment.js", device_id=None) -> str:
    """Get all currently resumed fragments in an Android application.
    
    Args:
        package: Android package name to inspect
        frida_script: Frida JavaScript file name (default: get_resumed_fragment.js)
        device_id: Optional Android device ID for multi-device scenarios
    
    Returns:
        JSON string containing resumed fragment information
    """
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        frida_script_path = os.path.join(script_dir, frida_script)
        executor = FridaScriptExecutor(frida_script_path, device_id=device_id)
        android_util = android_util_manager.select()
        pid = android_util.get_pid_of_app(package_name, executor.device)
        if pid is None or pid == -1:
            logger.error(f"Process '{package_name}' not found. Please ensure the device is connected and the target process is running.")
            return ""
        results = executor.run_script(pid, [("getresumedfragment", (), True)])
        if executor.error_occurred:
            logger.error("Frida script failed.")
            return ""
        if results is None or len(results) == 0:
            logger.warning("No results returned from Frida script.")
            return ""
        # result is list of strings, join them with ','
        return "\n"+ "\n".join(results)
        
    except Exception as e:
        error_msg = f"Failed to get resumed fragments for {package_name}: {e}"
        logger.error(error_msg)
        return json.dumps({"error": error_msg, "fragments": []})

    
# Optional: test/demo code
if __name__ == "__main__":
    # Example usage
    logger.info("Resumed fragments: " + get_resumed_fragment("com.android.settings"))