#!/usr/bin/env python3
FRIDA_SCRIPT_FILE = "export_bitmaps.js"
ANDROID_SAVE_DIR = "/sdcard/Download/exported_bitmaps/"

def export_bitmaps(package, output_dir=None, frida_script="export_bitmaps.js", device_id=None) -> str:
    """
    Export all in-memory Bitmaps from a running Android app process using Frida.

    :param package: Android package name to export bitmaps from.
    :param output_dir: Local output directory. If None, defaults to cache_files_dir/exported_bitmaps/<package>_<timestamp>/
    :param frida_script: Frida JS script filename (default: export_bitmaps.js)
    :param device_id: The ID of the specific device to connect to.
    :return: True if successful, False otherwise.
    """
    from datetime import datetime
    from android_util_impls.manager import android_util_manager
    from script_base.frida_utils import FridaScriptExecutor
    from script_base.utils import run_command, ensure_directory_exists
    from script_base.log import logger
    import os
    
    android_save_dir = ANDROID_SAVE_DIR

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    cache_root = os.environ.get("cache_files_dir", ".")
    out_dir = output_dir or os.path.join(cache_root, "exported_bitmaps", f"{package}_{timestamp}")
    ensure_directory_exists(out_dir)
    logger.info(f"Exporting bitmaps for package: {package}")
    logger.info(f"Output directory: {out_dir}")

    # 2. Call Frida script via frida_utils (method name must be lowercase)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    frida_script_path = os.path.join(script_dir, frida_script)
    try:
        executor = FridaScriptExecutor(frida_script_path, device_id=device_id)
        android_util = android_util_manager.select()
        pid = android_util.get_pid_of_app(package, executor.device)
        if pid is None or pid == -1:
            logger.warning(f"Process '{package}' not found. Trying fallback target 'system_server'...")
            pid = android_util.get_pid_of_app("system_server", executor.device)
            if pid is None or pid == -1:
                logger.error("Fallback process 'system_server' also not found. Please ensure the device is connected and the target process is running.")
                return False
        rpc_calls = [
            ("exportbitmaps", (android_save_dir,), True)  # Note the comma to make it a tuple
        ]
        is_running_as_root = android_util.is_adb_running_as_root(executor.device)
        if not is_running_as_root:
            logger.warning("ADB is not running as root. Try running as root")
            android_util.run_adb_as_root(device_id)
        target_dir_exists = android_util.check_file_or_directory_exists(android_save_dir, executor.device)
        if not target_dir_exists:
            logger.info(f"Creating directory {android_save_dir} on device...")
            android_util.create_directory(android_save_dir, executor.device)
        
        android_util.change_access_mode(android_save_dir, "777", executor.device)
            
        executor.run_script(int(pid), rpc_calls)
        if executor.error_occurred:
            logger.error("Frida script failed.")
            return ""
        logger.info("Frida script completed.")
    except Exception as e:
        logger.error(f"Frida script failed: {e}", exc_info=True)
        return ""

    # 3. Pull exported bitmaps from device
    try:
        run_command(["adb", "-s", executor.device, "pull", android_save_dir, out_dir], check_output=False)
        logger.info(f"Pulled exported bitmaps to {out_dir}")
    except Exception as e:
        logger.error(f"Failed to pull bitmaps: {e}", exc_info=True)
        return ""
    return out_dir

# Optional: test/demo code
if __name__ == "__main__":
    # Example usage
    export_bitmaps("com.mega.carsettings")