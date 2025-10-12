from command.android.base import AdbCommand
from script_base.log import logger


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
                    logger.error(
                        "Could not get the currently focused app package name. Please ensure the target app is in the foreground.")
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
