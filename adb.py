#!/usr/bin/env python3
"""
Comprehensive adb utility script, integrating set_time, show_focused_activity, and android_file_viewer features.
"""
import os
from script_base import log
from script_base.script_manager import ScriptManager, Command
from android_util_impls.manager import android_util_manager

from script_base.utils import (
    cache_root_arg_to_path,
    open_in_file_manager,
    open_in_vscode,
    run_command,
    ensure_directory_exists,
    sanitize_for_fs,
    timestamp,
)
from script_base.log import logger
from script_base.frida_utils import FridaScriptExecutor
from export_bitmaps import export_bitmaps
from set_language import set_android_language


# ===== ViewFolderCommand & ViewFileCommand =====
class ViewFolderCommand(Command):
    """Pull a specified directory from the device to a local cache directory and open it in the file manager."""

    def add_arguments(self, parser):
        parser.add_argument(
            "--device-path",
            "-p",
            type=str,
            required=True,
            help="Directory path on the Android device, e.g., /sdcard/Download/",
        )
        parser.add_argument(
            "--cache-root",
            type=str,
            help="Local cache root directory (defaults to environment variable cache_files_dir or current directory)",
        )
        parser.add_argument(
            "--tag",
            type=str,
            help="Optional. Custom directory tag name for distinguishing multiple pulls. Defaults to auto-generation based on device path and timestamp.",
        )
        parser.add_argument(
            "--no-open", action="store_true", help="Only pull to local, do not open file manager"
        )

    def execute(self, args):
        device_path = args.device_path
        if not device_path:
            logger.error("Error: --device-path must be provided.")
            return
        cache_root = cache_root_arg_to_path(args.cache_root)
        ensure_directory_exists(cache_root)
        tag = args.tag if args.tag else f"{sanitize_for_fs(device_path)}_{timestamp()}"
        local_base_dir = os.path.join(cache_root, "android_viewer", tag)
        ensure_directory_exists(local_base_dir)
        android_util = android_util_manager.select()
        connected_devices = android_util.get_connected_devices()
        if not connected_devices:
            logger.info("No connected devices found.")
            return
        is_remote_path_dir = android_util.is_remote_path_directory(
            remote_path=device_path
        )
        if not is_remote_path_dir:
            logger.error(f"Error: Device path {device_path} is not a directory.")
            return
        logger.info(f"Pulling directory: {device_path} -> {local_base_dir}")
        try:
            run_command(
                ["adb", "pull", device_path, local_base_dir], check_output=False
            )
        except PermissionError as e:
            logger.error(f"adb pull permission error: {e}", e)
            return
        except Exception as e:
            logger.error(f"adb pull failed: {e}", e)
            return
        basename = os.path.basename(device_path.rstrip("/")) or "root"
        open_dir = os.path.join(local_base_dir, basename)
        if not os.path.exists(open_dir):
            open_dir = local_base_dir
        logger.info(f"Local directory: {open_dir}")
        if not args.no_open:
            open_in_file_manager(open_dir)


class ViewFileCommand(Command):
    """Pull a specified file from the device to a local cache directory, with support for outputting to the terminal or opening in VSCode."""

    def add_arguments(self, parser):
        parser.add_argument(
            "--device-path",
            "-p",
            type=str,
            required=True,
            help="File path on the Android device, e.g., /sdcard/xxx.txt",
        )
        parser.add_argument(
            "--cache-root",
            type=str,
            help="Local cache root directory (defaults to environment variable cache_files_dir or current directory)",
        )
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "--cat", action="store_true", help="Directly output file content to the terminal after pulling"
        )
        group.add_argument(
            "--open-in-vscode", action="store_true", help="Open the file in VSCode after pulling"
        )
        group.add_argument(
            "--open-in-manager",
            action="store_true",
            help="Show the file in the file manager after pulling",
        )
        parser.add_argument(
            "--encoding",
            type=str,
            default="utf-8",
            help="File encoding to use with --cat, defaults to utf-8",
        )

    def execute(self, args):
        device_path = args.device_path
        if not device_path:
            logger.error("Error: --device-path must be provided.")
            return
        cache_root = cache_root_arg_to_path(args.cache_root)
        ensure_directory_exists(cache_root)
        tag = f"{sanitize_for_fs(device_path)}_{timestamp()}"
        local_dir = os.path.join(cache_root, "android_viewer", tag)
        ensure_directory_exists(local_dir)
        android_util = android_util_manager.select()
        is_remote_path_file = android_util.is_remote_path_file(device_path)
        if not is_remote_path_file:
            logger.error(f"Error: Device path {device_path} is not a file.")
            return
        logger.info(f"Pulling file: {device_path} -> {local_dir}")
        connected_devices = android_util.get_connected_devices()
        if not connected_devices:
            logger.info("No connected devices found.")
            return
        try:
            run_command(["adb", "pull", device_path, local_dir], check_output=False)
        except PermissionError as e:
            logger.info(f"{str(e)}")
            return
        except Exception as e:
            logger.error(f"adb pull failed: {e}", e)
            return
        local_file = os.path.join(local_dir, os.path.basename(device_path))
        if not os.path.exists(local_file):
            candidate = os.path.join(
                local_dir, os.path.basename(device_path.rstrip("/"))
            )
            local_file = candidate if os.path.exists(candidate) else local_file
        if not os.path.exists(local_file):
            logger.error(f"Local file not found: {local_file}")
            return
        logger.info(f"Local file: {local_file}")
        # if xml_content:
        #     with open(local_file, "w", encoding="utf-8") as f:
        #         f.write(xml_content)
        # xml_content = ""
        # is_binary = android_util.is_binary_xml(local_file)
        # if is_binary:
        #     logger.info("Binary XML file detected, attempting to parse...")
        #     xml_content = android_util.parse_binary_xml(local_file)
        # else:
        #     is_aapt_binary_xml = android_util.is_aapt_binary_xml(local_file)
        #     if is_aapt_binary_xml:
        #         logger.info("AAPT binary XML file detected, attempting to parse...")
        #         xml_content = android_util.parse_aapt_binary_xml(local_file)
        #         # Write the parsed xml back to the local file
        #     is_aapt2_binary_xml = android_util.is_aapt2_binary_xml(local_file)
        #     if is_aapt2_binary_xml:
        #         logger.info("AAPT2 binary XML file detected, attempting to parse...")
        #         xml_content = android_util.parse_aapt2_binary_xml(local_file)
        #         # Write the parsed xml back to the local file
        if args.cat:
            try:
                with open(
                    local_file, "r", encoding=args.encoding, errors="replace"
                ) as f:
                    print(f.read())
            except Exception as e:
                logger.error(f"Failed to read file: {e}", e)
        elif args.open_in_vscode:
            open_in_vscode(local_file)
        elif args.open_in_manager:
            open_in_file_manager(local_file)
        else:
            logger.info(
                "Use --cat to output content, --open-in-vscode to open the file, or --open-in-manager to show it in the file manager."
            )


class SetTimeCommand(Command):
    """
    Set the time on an Android device.
    """

    def add_arguments(self, parser):
        parser.add_argument(
            "time", help="Target time (YYYY-MM-DD-HH-MM-SS) or 'auto' to sync with network time"
        )

    def execute(self, args):
        if args.time == "auto":
            # Automatically sync network time
            run_command("adb shell settings put global auto_time 1", shell=True)
            run_command(
                "adb shell settings put global auto_time_zone 1", shell=True
            )  # Also enable auto timezone
            logger.debug("Auto time and timezone enabled")
            return
        android_util = android_util_manager.select()
        # Validate time format
        if not android_util.is_valid_time_format(args.time):
            logger.error("Invalid time format, should be YYYY-MM-DD-HH-MM-SS or 'auto'")
            return

        connected_devices = android_util.get_connected_devices()
        if not connected_devices:
            logger.info("No connected devices found.")
            return

        android_util = android_util_manager.select()
        # Get IANA timezone name from the device
        device_tz_name = android_util.get_device_timezone_name()
        if not device_tz_name:
            return
        # Let the device calculate the UTC timestamp itself
        milliseconds_utc = android_util.get_utc_milliseconds_from_device(args.time, device_tz_name)
        if milliseconds_utc is None:
            return

        run_command(
            "adb shell settings put global auto_time 0", shell=True
        )  # Disable auto time
        run_command(f"adb shell cmd alarm set-time {milliseconds_utc}", shell=True)
        logger.info(
            f"Time set on device to display as {args.time} (UTC milliseconds sent: {milliseconds_utc})."
        )
        logger.info(
            "Note: auto_time_zone has been disabled to maintain the manually set time."
        )


class ShowFocusedActivityCommand(Command):
    """
    Show the currently focused Activity.
    """

    def add_arguments(self, parser):
        pass

    def execute(self, args):
        android_util = android_util_manager.select()
        connnected_devices = android_util.get_connected_devices()
        if not connnected_devices:
            logger.error("No connected devices detected")
            return
        focused_package = android_util.get_focused_app_package()
        focused_activity = android_util.get_focused_activity()
        focused_window = android_util.get_focused_window()
        resumed_fragment = android_util.get_resumed_fragment()
        logger.info(f"Currently focused package: {focused_package}")
        logger.info(f"Currently focused Activity: {focused_activity}")
        logger.info(f"Currently focused Window: {focused_window}")
        logger.info(f"Current Resumed Fragment: {resumed_fragment}")


class DumpMemoryCommand(Command):
    """
    Dump the memory snapshot of an Android device and pull it to the local machine. Optionally convert to a MAT-supported format and show in Finder.
    """

    def add_arguments(self, parser):
        parser.add_argument(
            "-p", "--package", help="Target application package name. If not provided, --focused must be used."
        )
        parser.add_argument(
            "--focused",
            action="store_true",
            help="Use the currently focused application's package name as the target.",
        )
        parser.add_argument(
            "--convert-mat",
            action="store_true",
            help="Whether to convert to MAT-supported hprof format",
        )
        parser.add_argument(
            "--cache-dir",
            default=os.environ.get("cache_files_dir", "."),
            help="Local cache directory",
        )

    def execute(self, args):
        package_name = args.package
        if args.focused:
            logger.info("Getting the package name of the currently focused app...")
            android_util = android_util_manager.select()
            focused_package = android_util.get_focused_app_package()
            if focused_package:
                package_name = focused_package
                logger.info(f"Successfully got focused app package name: {package_name}")
            else:
                logger.error("Could not get the currently focused app package name. Please ensure the target app is in the foreground.")
                return

        if not package_name:
            logger.error(
                "Error: You must provide a package name with -p/--package, or use the --focused flag."
            )
            return

        ts = timestamp()
        local_dir = os.path.join(args.cache_dir, "mem_dump", package_name, ts)
        ensure_directory_exists(local_dir)
        remote_hprof = f"/data/local/tmp/{package_name}_{ts}.hprof"
        local_hprof = os.path.join(local_dir, f"{package_name}_{ts}.hprof")
        # Dump memory
        logger.info(f"Dumping memory snapshot: {remote_hprof}")
        run_command(["adb", "shell", "am", "dumpheap", package_name, remote_hprof])
        # Pull to local
        logger.info(f"Pulling to local: {local_hprof}")
        run_command(["adb", "pull", remote_hprof, local_hprof])
        # Optional conversion
        if args.convert_mat:
            mat_hprof = os.path.join(local_dir, f"{package_name}_{ts}_mat.hprof")
            logger.info(f"Converting to MAT format: {mat_hprof}")
            run_command(["adb", "shell", "rm", remote_hprof])  # Clean up on device
            # Hprof exported from Android needs to be converted with hprof-conv
            platform_tools_path = android_util.get_android_platform_tools_path()
            hprof_conv = (
                os.path.join(platform_tools_path, "hprof-conv")
                if platform_tools_path
                else "hprof-conv"
            )
            if not os.path.exists(hprof_conv):
                logger.warning("hprof-conv tool not found, skipping conversion")
            else:
                run_command([hprof_conv, local_hprof, mat_hprof])
                local_hprof = mat_hprof
        # Open Finder
        import platform

        if platform.system().lower() == "darwin":
            run_command(["open", "-R", local_hprof], check_output=False)
        elif platform.system().lower().startswith("win"):
            run_command(["explorer", "/select,", local_hprof], check_output=False)
        else:
            run_command(["xdg-open", local_dir], check_output=False)
        logger.info(f"Memory snapshot saved to: {local_hprof}")


class SetUiModeCommand(Command):
    """
    Switch the day/night mode of the Android device.
    """

    def add_arguments(self, parser):
        parser.add_argument(
            "mode",
            choices=["day", "night", "auto"],
            help="The UI mode to set: 'day', 'night', or 'auto'.",
        )

    def execute(self, args):
        # Check device connection
        android_util = android_util_manager.select()
        if not android_util.get_connected_devices():
            logger.error("No connected devices detected")
            return

        # Map user input to adb command arguments
        mode_map = {"day": "no", "night": "yes", "auto": "auto"}
        adb_mode_arg = mode_map[args.mode]

        try:
            logger.info(
                f"Setting UI mode to: {args.mode} (adb: 'cmd uimode night {adb_mode_arg}')"
            )
            run_command(["adb", "shell", "cmd", "uimode", "night", adb_mode_arg])
            logger.info("UI mode set successfully.")
        except Exception as e:
            logger.error(f"Failed to set UI mode", exc=e)


class KillCommand(Command):
    """
    Force stop an Android application.
    """

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-p", "--package", help="The package name of the target application to force stop.")
        group.add_argument(
            "--focused",
            action="store_true",
            help="Force stop the currently focused application.",
        )

    def execute(self, args):
        package_name = args.package
        if args.focused:
            logger.info("Getting the package name of the currently focused app...")
            android_util = android_util_manager.select()
            focused_package = android_util.get_focused_app_package()
            if focused_package:
                package_name = focused_package
                logger.info(f"Successfully got focused app package name: {package_name}")
            else:
                logger.error("Could not get the currently focused app package name. Please ensure the target app is in the foreground.")
                return

        try:
            logger.info(f"Force stopping application: {package_name}")
            android_util.kill_process(package_name)
            logger.info(f"Application {package_name} has been force stopped.")
        except Exception as e:
            logger.error(f"Failed to force stop application {package_name}", exc=e)


class ClearDataCommand(Command):
    """
    Clear some or all of an application's data, providing more fine-grained control than 'pm clear'.
    Requires root permission to operate on internal storage.
    """

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-p", "--package", help="Target application package name.")
        group.add_argument(
            "--focused", action="store_true", help="Use the currently focused application's package name."
        )

        parser.add_argument(
            "--type",
            nargs="+",  # Allow multiple values
            required=True,
            choices=["database", "shared_prefs", "files", "cache", "mmkv", "all"],
            help="Data types to clear (multiple choices allowed). 'all' clears all types.",
        )
        parser.add_argument(
            "--location",
            choices=["internal", "external"],
            default="internal",
            help="Data storage location: 'internal' (default) or 'external'.",
        )

    def execute(self, args):
        package_name = args.package
        if args.focused:
            logger.info("Getting the package name of the currently focused app...")
            android_util = android_util_manager.select()
            focused_package = android_util.get_focused_app_package()
            if focused_package:
                package_name = focused_package
                logger.info(f"Successfully got focused app package name: {package_name}")
            else:
                logger.error("Could not get the currently focused app package name. Please ensure the target app is in the foreground.")
                return

        # Check for root permission
        if args.location == "internal" and not android_util.is_adb_running_as_root():
            logger.error("Error: Clearing internal storage data requires root permission. Please run 'adb root' first.")
            return

        # Define path mappings
        path_map = {
            "internal": {
                "database": f"/data/data/{package_name}/databases",
                "shared_prefs": f"/data/data/{package_name}/shared_prefs",
                "files": f"/data/data/{package_name}/files",
                "cache": f"/data/data/{package_name}/cache",
                "mmkv": f"/data/data/{package_name}/files/mmkv",  # Default MMKV path
            },
            "external": {
                "files": f"/sdcard/Android/data/{package_name}/files",
                "cache": f"/sdcard/Android/data/{package_name}/cache",
            },
        }

        types_to_clear = set(args.type)
        if "all" in types_to_clear:
            types_to_clear = set(path_map[args.location].keys())

        logger.info(
            f"Preparing to clear the following data types for app '{package_name}' at '{args.location}' location: {', '.join(types_to_clear)}"
        )

        for data_type in types_to_clear:
            location_map = path_map.get(args.location)
            if not location_map or data_type not in location_map:
                logger.warning(
                    f"Warning: Clearing data type '{data_type}' is not supported at '{args.location}' location. Skipped."
                )
                continue

            target_path = location_map[data_type]
            try:
                logger.info(f"Clearing: {target_path}")
                # Use rm -rf to clear directory contents
                run_command(["adb", "shell", "rm", "-rf", f"{target_path}/*"])
                logger.info(f"Successfully cleared contents of {target_path}.")
            except Exception as e:
                logger.error(f"Failed while clearing {target_path}", exc=e)


class ExportBitmapsCommand(Command):
    """
    Export all in-memory Bitmaps from a running Android app process using Frida and pull them to the local machine.
    """
    def add_arguments(self, parser):
        parser.add_argument("--package", type=str, required=True, help="Android package name to export bitmaps from.")
        parser.add_argument("--output-dir", type=str, help="Local output directory. Defaults to cache_files_dir/exported_bitmaps/<package>_<timestamp>/")
        parser.add_argument("--frida-script", type=str, default="export_bitmaps.js", help="Frida JS script filename (default: export_bitmaps.js)")
        parser.add_argument("--device-id", type=str, help="The ID of the specific device to connect to.")

    def execute(self, args):
        output_dir = export_bitmaps(
            package=args.package,
            output_dir=args.output_dir,
            frida_script=args.frida_script,
            device_id=args.device_id
        )
        # show in file manager
        import script_base.utils as utils
        if output_dir and os.path.exists(output_dir):
            first_file_in_dir = None
            for root, dirs, files in os.walk(output_dir):
                if files:
                    first_file_in_dir = os.path.join(root, files[0])
                    break
            if first_file_in_dir and os.path.exists(first_file_in_dir):
                utils.open_in_file_manager(first_file_in_dir)
            else:
                utils.open_in_file_manager(output_dir)
        else:
            logger.error("No bitmaps were exported.")
        

class SetLanguageCommand(Command):
    """
    Set the system language on an Android device using Frida.
    """
    def add_arguments(self, parser):
        parser.add_argument("--language", type=str, required=True, help="Language code, e.g. 'en', 'zh'")
        parser.add_argument("--country", type=str, default="", help="Country/region code, e.g. 'US', 'CN'")
        parser.add_argument("--package", type=str, default="com.android.settings", help="Target process package name (default: com.android.settings)")
        parser.add_argument("--device-id", type=str, help="The ID of the specific device to connect to.")

    def execute(self, args):
        set_android_language(
            language=args.language,
            country=args.country,
            package_name=args.package,
            device_id=args.device_id
        )
        
        
class DebuggerCommand(Command):
    """
    Set or clear the application to be debugged.
    """

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(dest="action", required=True, help="Action to perform")

        # Sub-parser for 'set'
        parser_set = subparsers.add_parser("set", help="Set the debugger application.")
        group = parser_set.add_mutually_exclusive_group(required=True)
        group.add_argument("-p", "--package", help="The package name of the target application to set as debugger.")
        group.add_argument(
            "--focused",
            action="store_true",
            help="Set the currently focused application as the debugger.",
        )

        # Sub-parser for 'clear'
        subparsers.add_parser("clear", help="Clear the current debugger application.")

    def execute(self, args):
        android_util = android_util_manager.select()
        if not android_util.get_connected_devices():
            logger.error("No connected devices detected")
            return

        if args.action == "set":
            package_name = args.package
            if args.focused:
                logger.info("Getting the package name of the currently focused app...")
                focused_package = android_util.get_focused_app_package()
                if focused_package:
                    package_name = focused_package
                    logger.info(f"Successfully got focused app package name: {package_name}")
                else:
                    logger.error("Could not get the currently focused app package name. Please ensure the target app is in the foreground.")
                    return
            
            if not package_name:
                logger.error("Package name is required to set the debugger app.")
                return

            logger.info(f"Setting {package_name} as the debugger app...")
            if android_util.set_debugger_app(package_name):
                logger.info(f"Successfully set {package_name} as the debugger app.")
            else:
                logger.error(f"Failed to set {package_name} as the debugger app.")

        elif args.action == "clear":
            logger.info("Clearing the debugger app...")
            if android_util.remove_debugger_app():
                logger.info("Successfully cleared the debugger app.")
            else:
                logger.error("Failed to clear the debugger app.")


if __name__ == "__main__":
    # Test if android_sdk_path exists in environment variables
    manager = ScriptManager(
        description="Android ADB multi-tool script.\n\nIncludes subcommands like set-time, show-focused-activity, file-viewer, etc., supporting time setting, focused activity query, file/folder pulling and viewing.\n\nUsage examples:\n  python adb.py set-time 2025-08-23-12-00-00\n  python adb.py show-focused-activity\n  python adb.py view-folder /sdcard/Download\n  python adb.py view-file /sdcard/Download/test.txt --open-in-vscode\n  python adb.py set-ui-mode night\n  python adb.py dump-memory --focused\n"
    )

    manager.register_command(
        "set-time", SetTimeCommand(), help_text="Set the time on an Android device."
    )
    manager.register_command(
        "show-focused-activity",
        ShowFocusedActivityCommand(),
        help_text="Show the currently focused Activity.",
    )
    manager.register_command(
        "view-folder",
        ViewFolderCommand(),
        help_text="View a device directory: pull to local and open in file manager.",
    )
    manager.register_command(
        "view-file",
        ViewFileCommand(),
        help_text="View a device file: pull to local, can output or open in VSCode.",
    )
    manager.register_command(
        "dump-memory",
        DumpMemoryCommand(),
        help_text="Dump memory snapshot and pull to local, optionally convert to MAT format and show in Finder.",
    )
    manager.register_command(
        "set-ui-mode",
        SetUiModeCommand(),
        help_text="Switch the day/night mode of the Android device.",
    )
    manager.register_command(
        "kill",
        KillCommand(),
        help_text="Force stop an Android application (by package name or focused app).",
    )
    manager.register_command(
        "clear-data",
        ClearDataCommand(),
        help_text="Fine-grained clearing of application data (requires root permission)."
    )
    manager.register_command(
        "export-bitmaps",
        ExportBitmapsCommand(),
        help_text="Export all in-memory Bitmaps from a running Android app process using Frida."
    )
    manager.register_command(
        "set-language",
        SetLanguageCommand(),
        help_text="Set the system language on an Android device using Frida."
    )
    manager.register_command(
        "debugger",
        DebuggerCommand(),
        help_text="Set or clear the application to be debugged."
    )

    manager.run()
