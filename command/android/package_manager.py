from command.android.base import AdbCommand
from script_base.log import logger

GRANT_FLAG_DESCRIPTIONS = {
    "USER_SET": "explicitly set by the user",
    "USER_FIXED": "permanently fixed by the user (won't ask again)",
    "POLICY_FIXED": "fixed by a device policy",
    "SYSTEM_FIXED": "fixed by the system",
    "GRANTED_BY_DEFAULT": "granted by default",
    "USER_SENSITIVE_WHEN_GRANTED": "user-sensitive when granted",
    "USER_SENSITIVE_WHEN_DENIED": "user-sensitive when denied",
    "RESTRICTION_INSTALLER_EXEMPT": "exempt from restrictions by the installer",
    "RESTRICTION_SYSTEM_EXEMPT": "exempt from restrictions by the system",
    "RESTRICTION_UPGRADE_EXEMPT": "exempt from restrictions on app upgrade",
    "APPLIES_RESTRICTION": "applies a restriction",
    "ONE_TIME": "one-time grant (only this time)",
    "USER_FIXED_SENSITIVE": "permanently fixed by the user (sensitive)",
    "REVOKE_WHEN_REQUESTED": "revoked when requested again",
}


class PackageManagerCommand(AdbCommand):
    """
    Package Manager Service operations for Android applications.

    Provides various package manager functionalities including:
    - View application flags (system flags, private flags, package flags)
    - Check, grant, and revoke permissions for an application
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

        # Sub-parser for 'permission'
        parser_permission = subparsers.add_parser(
            "permission", help="Check, grant, or revoke permissions for an application"
        )
        permission_subparsers = parser_permission.add_subparsers(
            dest="permission_action",
            required=True,
            help="Permission action to perform",
        )
        self._add_permission_target_args(
            permission_subparsers.add_parser(
                "check",
                help="Check the status of a permission for an application "
                     "(definition, declarer, protection level, grant status, app flags)",
            )
        )
        self._add_permission_target_args(
            permission_subparsers.add_parser(
                "grant",
                help="Grant a permission to an application. Verifies installation, "
                     "permission definition, whether the app requests it, the protection "
                     "level, and root requirements before granting.",
            )
        )
        self._add_permission_target_args(
            permission_subparsers.add_parser(
                "revoke",
                help="Revoke a permission from an application. Verifies installation, "
                     "permission definition, the current grant status, and root "
                     "requirements before revoking.",
            )
        )

    def _add_permission_target_args(self, parser):
        """Add the common -p/--package, --focused, and --permission arguments."""
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-p", "--package", help="The package name of the target application")
        group.add_argument(
            "--focused",
            action="store_true",
            help="Use the currently focused application",
        )
        parser.add_argument(
            "--permission",
            required=True,
            help="The permission to operate on, e.g. 'android.permission.CAMERA'",
        )

    def execute_on_device(self, args, android_util):
        if args.action == "flags":
            package_name = self._resolve_package_name(args, android_util)
            if not package_name:
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
        elif args.action == "permission":
            if args.permission_action == "check":
                self._execute_permission_check(args, android_util)
            elif args.permission_action == "grant":
                self._execute_permission_grant(args, android_util)
            elif args.permission_action == "revoke":
                self._execute_permission_revoke(args, android_util)

    def _execute_permission_check(self, args, android_util):
        """Execute the 'permission check' action."""
        package_name, info = self._precheck_permission_operation(args, android_util)
        if not package_name:
            return
        self._log_permission_info(info, package_name)

    def _execute_permission_grant(self, args, android_util):
        """Execute the 'permission grant' action."""
        package_name, info = self._precheck_permission_operation(args, android_util)
        if not package_name:
            return

        permission = args.permission
        if not info.get("defined"):
            logger.error(
                f"Permission '{permission}' is NOT defined on this device, "
                f"so it cannot be granted."
            )
            return

        if not info.get("requested"):
            logger.error(
                f"Application {package_name} does NOT declare/request permission "
                f"'{permission}', so it cannot be granted."
            )
            return

        if info.get("granted"):
            logger.info(
                f"Permission '{permission}' is already granted to {package_name}. Nothing to do."
            )
            return

        if not self._is_runtime_permission(info.get("protection_level", "")):
            logger.warning(
                f"Permission '{permission}' has a non-runtime protection level "
                f"({info.get('protection_level') or 'unknown'}); it is normally granted "
                f"at install time."
            )
            if not android_util.is_adb_running_as_root():
                logger.error(
                    "Granting this permission requires root permission. "
                    "Please run 'adb root' and retry."
                )
                return
            logger.info("adb is running as root, attempting to grant the permission anyway...")

        logger.info(f"Granting permission '{permission}' to {package_name}...")
        if android_util.grant_permission(permission, package_name):
            logger.info(f"Successfully granted permission '{permission}' to {package_name}.")
            self._verify_grant_status(android_util, package_name, permission)
        else:
            logger.error(
                f"Failed to grant permission '{permission}' to {package_name}. "
                f"If the permission has a signature/privileged protection level, "
                f"run 'adb root' and retry."
            )

    def _execute_permission_revoke(self, args, android_util):
        """Execute the 'permission revoke' action."""
        package_name, info = self._precheck_permission_operation(args, android_util)
        if not package_name:
            return

        permission = args.permission
        if not info.get("defined"):
            logger.error(
                f"Permission '{permission}' is NOT defined on this device, "
                f"so it cannot be revoked."
            )
            return

        if not info.get("granted"):
            logger.warning(
                f"Permission '{permission}' is not granted to {package_name}. "
                f"Nothing to revoke."
            )
            return

        if not self._is_runtime_permission(info.get("protection_level", "")):
            logger.warning(
                f"Permission '{permission}' has a non-runtime protection level "
                f"({info.get('protection_level') or 'unknown'}); it is normally granted "
                f"at install time."
            )
            if not android_util.is_adb_running_as_root():
                logger.error(
                    "Revoking this permission requires root permission. "
                    "Please run 'adb root' and retry."
                )
                return
            logger.info("adb is running as root, attempting to revoke the permission anyway...")

        logger.info(f"Revoking permission '{permission}' from {package_name}...")
        if android_util.revoke_permission(permission, package_name):
            logger.info(f"Successfully revoked permission '{permission}' from {package_name}.")
            self._verify_grant_status(android_util, package_name, permission)
        else:
            logger.error(
                f"Failed to revoke permission '{permission}' from {package_name}. "
                f"If the permission has a signature/privileged protection level, "
                f"run 'adb root' and retry."
            )

    def _precheck_permission_operation(self, args, android_util):
        """
        Resolve the package name and run the checks shared by all permission actions.

        Returns:
            tuple: (package_name, permission info dict) on success, or (None, None)
                when the package could not be resolved, is not installed, or the
                permission info could not be obtained.
        """
        package_name = self._resolve_package_name(args, android_util)
        if not package_name:
            return None, None

        permission = args.permission
        logger.info(f"Verifying application {package_name} is installed...")
        try:
            apk_path = android_util.get_apk_path(package_name)
            if not apk_path:
                logger.error(f"Application {package_name} is not installed on the device.")
                return None, None

            info = android_util.check_permission(permission, package_name)
        except Exception as e:
            logger.error(
                f"Failed to inspect permission '{permission}' for application "
                f"{package_name}: {e}",
                exc=e,
            )
            return None, None

        if not info:
            logger.error("Failed to inspect permission: no device/adb available.")
            return None, None

        return package_name, info

    def _resolve_package_name(self, args, android_util):
        """
        Resolve the target package name from --package or --focused.

        Returns:
            str: The resolved package name, or None if it could not be resolved.
        """
        package_name = getattr(args, "package", None)
        if package_name:
            return package_name

        if getattr(args, "focused", False):
            logger.info("Getting the package name of the currently focused app...")
            focused_package = android_util.get_focused_app_package()
            if focused_package:
                logger.info(f"Successfully got focused app package name: {focused_package}")
                return focused_package
            logger.error(
                "Could not get the currently focused app package name. "
                "Please ensure the target app is in the foreground."
            )
            return None

        return None

    def _is_runtime_permission(self, protection_level):
        """
        Check whether the permission is a runtime permission changeable via 'pm grant/revoke'.

        Args:
            protection_level (str): The protection level of the permission.

        Returns:
            bool: True if the permission can be changed via 'pm grant/revoke'.
        """
        if not protection_level:
            return True
        return any(
            keyword in protection_level for keyword in ("dangerous", "appop")
        )

    def _verify_grant_status(self, android_util, package_name, permission):
        """Re-check and log the grant status after a grant/revoke operation."""
        try:
            updated = android_util.check_permission(permission, package_name)
        except Exception as e:
            logger.warning(f"Could not verify the grant status after the operation: {e}")
            return

        granted = updated.get("granted")
        if granted is None:
            logger.warning("Could not verify the grant status after the operation.")
        else:
            status = "GRANTED" if granted else "NOT GRANTED"
            logger.info(f"Grant status after operation: {status}")

    def _log_permission_info(self, info, package_name):
        """Log the collected permission and package information in a user-friendly way."""
        permission = info.get("permission", "")
        logger.info(f"===== Permission Check Result =====")
        logger.info(f"Package: {package_name}")

        if not info.get("defined"):
            logger.warning(
                f"Permission '{permission}' is NOT defined on this device, "
                f"so it cannot be granted."
            )
            return

        logger.info(f"Permission '{permission}' is defined on this device:")
        logger.info(
            f"  Declared by (sourcePackage): {info.get('source_package') or 'unknown'}"
        )
        logger.info(
            f"  Protection level: {info.get('protection_level') or 'unknown'}"
        )

        if not info.get("requested"):
            logger.warning(
                f"Package {package_name} does NOT request permission '{permission}'."
            )
        elif info.get("granted") is None:
            logger.warning(
                f"Permission '{permission}' is requested by {package_name} "
                f"but has no grant record yet."
            )
        elif info.get("granted"):
            logger.info(
                f"Grant status: GRANTED"
                f"{self._describe_grant_flags(info.get('grant_flags'))}"
            )
        else:
            logger.warning(
                f"Grant status: NOT GRANTED"
                f"{self._describe_grant_flags(info.get('grant_flags'))}"
            )

        self._log_app_flags(info, package_name)

    def _describe_grant_flags(self, grant_flags):
        """
        Build a user-friendly explanation of the raw grant flags.

        Args:
            grant_flags (list): Raw grant flag names from dumpsys.

        Returns:
            str: A parenthesized explanation (including the raw flags), or an
                empty string when there are no flags.
        """
        if not grant_flags:
            return ""
        raw_flags = []
        for flag in grant_flags:
            raw_flags.extend(flag.split("|"))
        descriptions = [GRANT_FLAG_DESCRIPTIONS.get(flag, flag) for flag in raw_flags]
        return f" ({', '.join(descriptions)}; flags: {'|'.join(raw_flags)})"

    def _log_app_flags(self, info, package_name):
        """Log the application flags and signature-related information."""
        flags = info.get("flags") or []
        private_flags = info.get("private_flags") or []
        pkg_flags = info.get("pkg_flags") or []

        if not flags and not private_flags and not pkg_flags:
            logger.warning(
                f"No flags found for application {package_name}. "
                f"The application may not be installed."
            )
            return

        logger.info(f"  App flags: {', '.join(flags) or 'none'}")
        logger.info(f"  Private flags: {', '.join(private_flags) or 'none'}")
        logger.info(f"  Package flags: {', '.join(pkg_flags) or 'none'}")
        logger.info(f"  System app: {info.get('is_system_app')}")
        logger.info(f"  Privileged app: {info.get('is_privileged')}")

        platform_signed = info.get("platform_signed")
        if platform_signed is None:
            if info.get("platform_check_requires_root"):
                logger.warning(
                    "  Platform signature (signed with platform key) could not be verified: "
                    "it requires root permission. Run 'adb root' and retry for complete info."
                )
            else:
                logger.warning("  Platform signature could not be verified.")
        else:
            logger.info(f"  Signed with platform key (system signature): {platform_signed}")
