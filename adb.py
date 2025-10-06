#!/usr/bin/env python3
"""
Comprehensive adb utility script, integrating set_time, show_focused_activity, and android_file_viewer features.
"""
import os
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
from export_bitmaps import export_bitmaps
from set_language import set_android_language


# ===== Base Command for ADB Operations =====
class AdbCommand(Command):
    """Base class for all ADB device operation commands.

    Automatically adds --serial and --suppress-warnings arguments.
    Subclasses should override add_custom_arguments() and execute_on_device().
    """

    def add_arguments(self, parser):
        """Add common ADB arguments. Override add_custom_arguments() for command-specific args."""
        parser.add_argument(
            "--serial",
            "-s",
            type=str,
            help="Device serial number. If not specified, uses the first connected device.",
        )
        parser.add_argument(
            "--suppress-warnings",
            action="store_true",
            help="Suppress warning messages when multiple devices are connected.",
        )
        self.add_custom_arguments(parser)

    def add_custom_arguments(self, parser):
        """Override this method to add command-specific arguments."""
        pass

    def execute(self, args):
        """Execute the command with device selection handling."""
        # Get android_util with device selection
        android_util = self.get_android_util(args)
        if android_util is None:
            return

        # Execute the command-specific logic
        self.execute_on_device(args, android_util)

    def get_android_util(self, args):
        """Get android_util instance with proper device selection and warning handling."""
        device_serial = getattr(args, 'serial', None)
        suppress_warnings = getattr(args, 'suppress_warnings', False)

        # Create android_util with device selection
        default_android_util = android_util_manager.select()

        # Check if device is connected
        devices = default_android_util.get_connected_devices()
        if not devices or len(devices) == 0:
            logger.error("No connected devices detected")
            return None
        logger.debug(f"Connected devices: {devices}")
        # Handle multiple device warning
        if len(devices) > 1 and not device_serial and not suppress_warnings:
            device_ids = [d.split()[0] for d in devices]
            logger.warning(
                f"Multiple devices connected: {device_ids}. "
                f"Device not specified, using the first device: {device_ids[0]}. "
                f"Use --serial to specify a device or --suppress-warnings to hide this message."
            )
        if not device_serial:
            device_serial = devices[0].split()[0]
        return android_util_manager.select(device=device_serial)

    def execute_on_device(self, args, android_util):
        """Override this method to implement command-specific logic.

        Args:
            args: Parsed command-line arguments
            android_util: AndroidUtilBase instance with device already selected
        """
        raise NotImplementedError("Subclasses must implement execute_on_device()")


# ===== ViewFolderCommand & ViewFileCommand =====
class ViewFolderCommand(AdbCommand):
    """Pull a specified directory from the device to a local cache directory and open it in the file manager."""

    def add_custom_arguments(self, parser):
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

    def execute_on_device(self, args, android_util):
        device_path = args.device_path
        if not device_path:
            logger.error("Error: --device-path must be provided.")
            return
        cache_root = cache_root_arg_to_path(args.cache_root)
        ensure_directory_exists(cache_root)
        tag = args.tag if args.tag else f"{sanitize_for_fs(device_path)}_{timestamp()}"
        local_base_dir = os.path.join(cache_root, "android_viewer", tag)
        ensure_directory_exists(local_base_dir)
        
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


class ViewFileCommand(AdbCommand):
    """Pull a specified file from the device to a local cache directory, with support for outputting to the terminal or opening in VSCode."""

    def add_custom_arguments(self, parser):
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

    def execute_on_device(self, args, android_util):
        device_path = args.device_path
        if not device_path:
            logger.error("Error: --device-path must be provided.")
            return
        cache_root = cache_root_arg_to_path(args.cache_root)
        ensure_directory_exists(cache_root)
        tag = f"{sanitize_for_fs(device_path)}_{timestamp()}"
        local_dir = os.path.join(cache_root, "android_viewer", tag)
        ensure_directory_exists(local_dir)
        
        is_remote_path_file = android_util.is_remote_path_file(device_path)
        if not is_remote_path_file:
            logger.error(f"Error: Device path {device_path} is not a file.")
            return
        logger.info(f"Pulling file: {device_path} -> {local_dir}")
        
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


class SetTimeCommand(AdbCommand):
    """
    Set the time on an Android device.
    """

    def add_custom_arguments(self, parser):
        parser.add_argument(
            "time", help="Target time (YYYY-MM-DD-HH-MM-SS) or 'auto' to sync with network time"
        )

    def execute_on_device(self, args, android_util):
        device_id = android_util.get_connected_device_id()
        if args.time == "auto":
            # Automatically sync network time
            run_command(f"adb -s {device_id} shell settings put global auto_time 1", shell=True)
            run_command(
                f"adb -s {device_id} shell settings put global auto_time_zone 1", shell=True
            )  # Also enable auto timezone
            logger.debug("Auto time and timezone enabled")
            return
        
        # Validate time format
        if not android_util.is_valid_time_format(args.time):
            logger.error("Invalid time format, should be YYYY-MM-DD-HH-MM-SS or 'auto'")
            return

        # Get IANA timezone name from the device
        device_tz_name = android_util.get_device_timezone_name()
        if not device_tz_name:
            return
        # Let the device calculate the UTC timestamp itself
        milliseconds_utc = android_util.get_utc_milliseconds_from_device(args.time, device_tz_name)
        if milliseconds_utc is None:
            return

        run_command(
            f"adb -s {device_id} shell settings put global auto_time 0", shell=True
        )  # Disable auto time
        run_command(f"adb -s {device_id} shell cmd alarm set-time {milliseconds_utc}", shell=True)
        logger.info(
            f"Time set on device to display as {args.time} (UTC milliseconds sent: {milliseconds_utc})."
        )
        logger.info(
            "Note: auto_time_zone has been disabled to maintain the manually set time."
        )


class ShowFocusedActivityCommand(AdbCommand):
    """
    Show the currently focused Activity.
    """

    def add_custom_arguments(self, parser):
        pass

    def execute_on_device(self, args, android_util):
        focused_package = android_util.get_focused_app_package()
        focused_activity = android_util.get_focused_activity()
        focused_window = android_util.get_focused_window()
        resumed_fragment = android_util.get_resumed_fragment()
        logger.info(f"Currently focused package: {focused_package}")
        logger.info(f"Currently focused Activity: {focused_activity}")
        logger.info(f"Currently focused Window: {focused_window}")
        logger.info(f"Current Resumed Fragment: {resumed_fragment}")


class DumpMemoryCommand(AdbCommand):
    """
    Dump the memory snapshot of an Android device and pull it to the local machine. Optionally convert to a MAT-supported format and show in Finder.
    """

    def add_custom_arguments(self, parser):
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

    def execute_on_device(self, args, android_util):
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
            logger.error(
                "Error: You must provide a package name with -p/--package, or use the --focused flag."
            )
            return

        ts = timestamp()
        local_dir = str(os.path.join(args.cache_dir, "mem_dump", package_name, ts))
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


class SetUiModeCommand(AdbCommand):
    """
    Switch the day/night mode of the Android device.
    """

    def add_custom_arguments(self, parser):
        parser.add_argument(
            "mode",
            choices=["day", "night", "auto"],
            help="The UI mode to set: 'day', 'night', or 'auto'.",
        )

    def execute_on_device(self, args, android_util):
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


class KillCommand(AdbCommand):
    """
    Force stop an Android application.
    """

    def add_custom_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-p", "--package", help="The package name of the target application to force stop.")
        group.add_argument(
            "--focused",
            action="store_true",
            help="Force stop the currently focused application.",
        )

    def execute_on_device(self, args, android_util):
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

        try:
            logger.info(f"Force stopping application: {package_name}")
            android_util.kill_process(package_name)
            logger.info(f"Application {package_name} has been force stopped.")
        except Exception as e:
            logger.error(f"Failed to force stop application {package_name}", exc=e)


class ClearDataCommand(AdbCommand):
    """
    Clear some or all of an application's data, providing more fine-grained control than 'pm clear'.
    Requires root permission to operate on internal storage.
    """

    def add_custom_arguments(self, parser):
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

    def execute_on_device(self, args, android_util):
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


class ExportBitmapsCommand(AdbCommand):
    """
    Export all in-memory Bitmaps from a running Android app process using Frida and pull them to the local machine.
    """
    def add_custom_arguments(self, parser):
        parser.add_argument("--package", type=str, required=True, help="Android package name to export bitmaps from.")
        parser.add_argument("--output-dir", type=str, help="Local output directory. Defaults to cache_files_dir/exported_bitmaps/<package>_<timestamp>/")
        parser.add_argument("--frida-script", type=str, default="export_bitmaps.js", help="Frida JS script filename (default: export_bitmaps.js)")
        parser.add_argument("--device-id", type=str, help="The ID of the specific device to connect to.")

    def execute_on_device(self, args, android_util):
        output_dir = export_bitmaps(
            package=args.package,
            output_dir=args.output_dir,
            frida_script=args.frida_script,
            device_id=android_util.get_connected_device_id()
        )
        # show in file manager
        import script_base.utils as utils
        if output_dir and os.path.exists(output_dir):
            first_file_in_dir = None
            for root, _, files in os.walk(output_dir):
                if files:
                    first_file_in_dir = os.path.join(root, files[0])
                    break
            if first_file_in_dir and os.path.exists(first_file_in_dir):
                utils.open_in_file_manager(first_file_in_dir)
            else:
                utils.open_in_file_manager(output_dir)
        else:
            logger.error("No bitmaps were exported.")
        

class SetLanguageCommand(AdbCommand):
    """
    Set the system language on an Android device using Frida.
    """
    def add_custom_arguments(self, parser):
        parser.add_argument("--language", type=str, required=True, help="Language code, e.g. 'en', 'zh'")
        parser.add_argument("--country", type=str, default="", help="Country/region code, e.g. 'US', 'CN'")
        parser.add_argument("--package", type=str, default="com.android.settings", help="Target process package name (default: com.android.settings)")
        parser.add_argument("--device-id", type=str, help="The ID of the specific device to connect to.")

    def execute_on_device(self, args, android_util):
        set_android_language(
            language=args.language,
            country=args.country,
            package_name=args.package,
            device_id=args.device_id
        )
        
        
class DebuggerCommand(AdbCommand):
    """
    Set or clear the application to be debugged.
    """

    def add_custom_arguments(self, parser):
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

    def execute_on_device(self, args, android_util):
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


class PackageManagerCommand(AdbCommand):
    """
    Package Manager Service operations for Android applications.
    
    Provides various package manager functionalities including:
    - View application flags (system flags, private flags, package flags)
    - Future: permissions, package info, etc.
    """

    def add_custom_arguments(self, parser):
        subparsers = parser.add_subparsers(dest="action", required=True, help="Package manager action to perform")

        # Sub-parser for 'flags'
        parser_flags = subparsers.add_parser("flags", help="Show application flags (system, private, package flags)")
        group = parser_flags.add_mutually_exclusive_group(required=True)
        group.add_argument("-p", "--package", help="The package name of the target application")
        group.add_argument(
            "--focused",
            action="store_true",
            help="Show flags for the currently focused application"
        )

    def execute_on_device(self, args, android_util):
        if args.action == "flags":
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
                logger.error("Package name is required to get application flags.")
                return

            try:
                logger.info(f"Getting flags for application: {package_name}")
                flags = android_util.get_package_flags(package_name)
                
                if not flags:
                    logger.warning(f"No flags found for application {package_name}. Application may not be installed.")
                    return

                logger.info(f"Flags for application {package_name}: {flags}")
            except Exception as e:
                logger.error(f"Failed to get flags for application {package_name}: {e}", exc=e)


class PullApkCommand(AdbCommand):
    """
    Pull APK file from Android device to local machine.
    """

    def add_custom_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-p", "--package", help="Package name of the application to pull APK for.")
        group.add_argument(
            "--focused",
            action="store_true",
            help="Pull APK for the currently focused application.",
        )
        
        parser.add_argument(
            "--output-dir",
            type=str,
            help="Local output directory. Defaults to cache_files_dir/pulled_apks/",
        )
        parser.add_argument(
            "--show-in-manager",
            action="store_true",
            help="Show the pulled APK in file manager after download.",
        )

    def execute_on_device(self, args, android_util):
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
            logger.error("Package name is required to pull APK.")
            return

        # Get APK path from device
        logger.info(f"Getting APK path for package: {package_name}")
        try:
            apk_path = android_util.get_apk_path(package_name)
            if not apk_path:
                logger.error(f"Could not find APK path for package: {package_name}")
                return
            logger.info(f"Found APK path: {apk_path}")
        except Exception as e:
            logger.error(f"Failed to get APK path for {package_name}: {e}", exc=e)
            return

        # Setup output directory
        if args.output_dir:
            output_dir = args.output_dir
        else:
            cache_root = cache_root_arg_to_path(None)
            output_dir = os.path.join(cache_root, "pulled_apks")
        
        ensure_directory_exists(output_dir)
        
        # Generate local APK filename
        ts = timestamp()
        apk_filename = f"{package_name}_{ts}.apk"
        local_apk_path = os.path.join(output_dir, apk_filename)

        # Pull APK from device
        logger.info(f"Pulling APK: {apk_path} -> {local_apk_path}")
        try:
            success = android_util.pull_file(android_util.get_connected_device_id(), apk_path, local_apk_path)
            if success:
                logger.info(f"Successfully pulled APK to: {local_apk_path}")
            else:
                logger.error("Failed to pull APK from device")
                return
        except Exception as e:
            logger.error(f"Failed to pull APK: {e}", exc=e)
            return

        # Verify file exists and show in manager if requested
        if os.path.exists(local_apk_path):
            logger.info(f"APK saved: {local_apk_path}")
            if args.show_in_manager:
                open_in_file_manager(local_apk_path)
        else:
            logger.error("APK file was not created successfully.")


class DecompileCommand(AdbCommand):
    """
    Decompile APK or JAR files using apktool, with support for pulling from device first.
    """

    def add_custom_arguments(self, parser):
        # Source selection - mutually exclusive
        source_group = parser.add_mutually_exclusive_group(required=True)
        source_group.add_argument(
            "--local-file",
            type=str,
            help="Path to local APK or JAR file to decompile.",
        )
        source_group.add_argument(
            "--package",
            "-p",
            type=str,
            help="Package name to pull APK from device and then decompile.",
        )
        source_group.add_argument(
            "--focused",
            action="store_true",
            help="Pull APK for currently focused app and decompile.",
        )
        
        parser.add_argument(
            "--output-dir",
            type=str,
            help="Output directory for decompiled files. Defaults to cache_files_dir/decompiled/",
        )
        parser.add_argument(
            "--apktool-jar",
            type=str,
            help="Path to apktool jar file. If not specified, will try to find apktool in PATH.",
        )
        parser.add_argument(
            "--no-open",
            action="store_true",
            help="Do not open the decompiled directory in VSCode after decompilation.",
        )

    def execute_on_device(self, args, android_util):
        # Determine source file
        source_file = None
        
        if args.local_file:
            source_file = args.local_file
            if not os.path.exists(source_file):
                logger.error(f"Local file does not exist: {source_file}")
                return
        else:
            # Need to pull APK from device first
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
                logger.error("Package name is required to pull APK from device.")
                return

            # Pull APK from device
            source_file = self._pull_apk_from_device(package_name, android_util)
            if not source_file:
                return

        # Determine file type
        file_type = self._detect_file_type(source_file)
        if not file_type:
            logger.error(f"Unsupported file type. Only APK and JAR files are supported.")
            return

        logger.info(f"Detected file type: {file_type}")

        # Setup output directory
        if args.output_dir:
            base_output_dir = args.output_dir
        else:
            cache_root = cache_root_arg_to_path(None)
            base_output_dir = os.path.join(cache_root, "decompiled")
        
        ensure_directory_exists(base_output_dir)

        # Create unique output directory
        base_name = os.path.splitext(os.path.basename(source_file))[0]
        ts = timestamp()
        output_dir = os.path.join(base_output_dir, f"{base_name}_{ts}")
        ensure_directory_exists(output_dir)

        # Copy source file to output directory (temporary)
        temp_source = os.path.join(output_dir, os.path.basename(source_file))
        import shutil
        shutil.copy2(source_file, temp_source)

        # Decompile using apktool
        decompiled_dir = os.path.join(output_dir, base_name)
        success = self._decompile_with_apktool(temp_source, decompiled_dir, args.apktool_jar)
        
        if success:
            # Remove temporary source file copy
            try:
                os.remove(temp_source)
            except Exception as e:
                logger.warning(f"Could not remove temporary file {temp_source}: {e}")
            
            logger.info(f"Decompilation completed: {decompiled_dir}")
            
            # Open in VSCode if requested
            if not args.no_open:
                logger.info("Opening decompiled directory in VSCode...")
                open_in_vscode(decompiled_dir)
        else:
            logger.error("Decompilation failed.")

    def _pull_apk_from_device(self, package_name, android_util):
        """Pull APK from device and return local path."""
        try:
            apk_path = android_util.get_apk_path(package_name)
            if not apk_path:
                logger.error(f"Could not find APK path for package: {package_name}")
                return None
            
            # Create temporary directory for pulled APK
            cache_root = cache_root_arg_to_path(None)
            temp_dir = os.path.join(cache_root, "temp_apks")
            ensure_directory_exists(temp_dir)
            
            ts = timestamp()
            local_apk = os.path.join(temp_dir, f"{package_name}_{ts}.apk")
            
            logger.info(f"Pulling APK: {apk_path} -> {local_apk}")
            device_id = android_util.get_connected_device_id()
            success = android_util.pull_file(device_id, apk_path, local_apk)
            
            if success and os.path.exists(local_apk):
                logger.info(f"Successfully pulled APK: {local_apk}")
                return local_apk
            else:
                logger.error("Failed to pull APK from device.")
                return None
                
        except Exception as e:
            logger.error(f"Error pulling APK from device: {e}", exc=e)
            return None

    def _detect_file_type(self, file_path):
        """Detect if file is APK or JAR based on extension."""
        if file_path.lower().endswith('.apk'):
            return 'apk'
        elif file_path.lower().endswith('.jar'):
            return 'jar'
        else:
            return None

    def _decompile_with_apktool(self, source_file, output_dir, apktool_jar_path=None):
        """Decompile APK/JAR using apktool."""
        try:
            # Determine apktool command
            if apktool_jar_path and os.path.exists(apktool_jar_path):
                apktool_cmd = ["java", "-jar", apktool_jar_path]
            else:
                # check if apktool is in PATH
                import shutil
                if shutil.which("apktool"):
                    apktool_cmd = ["apktool"]
                else:
                    logger.error("apktool not found. Please provide the path to apktool jar using --apktool-jar or ensure apktool is in your PATH.")
                    return False
            
            # Build decompile command
            cmd = apktool_cmd + ["d", "-o", output_dir, source_file]
            
            logger.info(f"Running decompile command: {' '.join(cmd)}")
            run_command(cmd, check_output=False)
            
            # Check if decompilation was successful
            if os.path.exists(output_dir) and os.listdir(output_dir):
                return True
            else:
                logger.error("Decompilation output directory is empty or does not exist.")
                return False
                
        except Exception as e:
            logger.error(f"Decompilation failed: {e}", exc=e)
            return False


if __name__ == "__main__":
    # Test if android_sdk_path exists in environment variables
    manager = ScriptManager(
        description="""Android ADB multi-tool script.

Includes comprehensive subcommands for Android device operations:
- Device management: set-time, show-focused-activity, set-ui-mode
- File operations: view-folder, view-file (pull and view device files)
- App management: kill, clear-data, dump-memory, debugger, package-manager
- APK operations: pull-apk (extract APK from device), decompile (decompile APK/JAR)
- Advanced features: export-bitmaps, set-language (using Frida)

All commands support device selection via --serial and --suppress-warnings options.

Usage examples:
  python adb.py set-time 2025-10-05-14-30-00
  python adb.py show-focused-activity
  python adb.py view-folder /sdcard/Download --no-open
  python adb.py view-file /sdcard/Download/test.txt --open-in-vscode
  python adb.py set-ui-mode night
  python adb.py dump-memory --focused --convert-mat
  python adb.py kill --focused
  python adb.py clear-data --focused --type cache shared_prefs
  python adb.py pull-apk --focused --show-in-manager
  python adb.py decompile --package com.example.app
  python adb.py decompile --local-file /path/to/app.apk --no-open
  python adb.py export-bitmaps --package com.example.app
  python adb.py set-language --language zh --country CN
  python adb.py debugger set --focused
  python adb.py package-manager flags --focused
"""
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
    manager.register_command(
        "package-manager",
        PackageManagerCommand(),
        help_text="Package Manager Service operations (flags, permissions, etc.)"
    )
    manager.register_command(
        "pull-apk",
        PullApkCommand(),
        help_text="Pull APK file from Android device to local machine."
    )
    manager.register_command(
        "decompile",
        DecompileCommand(),
        help_text="Decompile APK or JAR files using apktool, with support for pulling from device."
    )

    manager.run()
