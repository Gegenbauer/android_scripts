from command.android.base import AdbCommand
from script_base.log import logger
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
                logger.error(
                    "Could not get the currently focused app package name. Please ensure the target app is in the foreground.")
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
                logger.error(
                    "Could not get the currently focused app package name. Please ensure the target app is in the foreground.")
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
                    logger.error(
                        "Could not get the currently focused app package name. Please ensure the target app is in the foreground.")
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
