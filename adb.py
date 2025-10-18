#!/usr/bin/env python3
"""
Comprehensive adb utility script, integrating set_time, show_focused_activity, and android_file_viewer features.
"""

from command.android.apk import PullApkCommand, DecompileCommand
from command.android.base import AdbCommand
from command.android.file import ViewFolderCommand, ViewFileCommand
from command.android.package_manager import PackageManagerCommand
from command.android.performance import ExportBitmapsCommand, DumpMemoryCommand, DumpThreadStackCommand
from command.android.setting import SetTimeCommand, SetUiModeCommand, SetLanguageCommand
from script_base.log import logger
from script_base.script_manager import ScriptManager
from script_base.utils import run_command

class ShowFocusedActivityCommand(AdbCommand):
    """
    Show the currently focused Activity.
    """

    def add_custom_arguments(self, parser):
        pass

    def execute_on_device(self, args, android_util):
        focused_package = android_util.get_focused_app_package()
        from get_resumed_fragment import get_resumed_fragment
        resumed_fragment = get_resumed_fragment(focused_package, device_id=android_util.get_connected_device_id())
        focused_activity = android_util.get_focused_activity()
        focused_window = android_util.get_focused_window()
        logger.info(f"Currently focused package: {focused_package}")
        logger.info(f"Currently focused Activity: {focused_activity}")
        logger.info(f"Currently focused Window: {focused_window}")
        logger.info(f"Current Resumed Fragment: {resumed_fragment}")


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


if __name__ == "__main__":
    # Test if android_sdk_path exists in environment variables
    manager = ScriptManager(
        description="""Android ADB multi-tool script.

Includes comprehensive subcommands for Android device operations:
- Device management: set-time, show-focused-activity, set-ui-mode
- File operations: view-folder, view-file (pull and view device files)
- App management: kill, clear-data, dump-memory, debugger, package-manager, dump-thread-stack
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
  python adb.py dump-thread-stack --focused --open-vscode
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
    manager.register_command(
        "dump-thread-stack",
        DumpThreadStackCommand(),
        help_text="Dump thread stack traces of a target Android app process."
    )

    manager.run()
