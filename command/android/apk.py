import os

from command.android.base import AdbCommand
from script_base.utils import (
    cache_root_arg_to_path,
    open_in_file_manager,
    open_in_vscode,
    run_command,
    ensure_directory_exists,
    timestamp,
)
from script_base.log import logger


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
                logger.error(
                    "Could not get the currently focused app package name. Please ensure the target app is in the foreground.")
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
                    logger.error(
                        "Could not get the currently focused app package name. Please ensure the target app is in the foreground.")
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
                    logger.error(
                        "apktool not found. Please provide the path to apktool jar using --apktool-jar or ensure apktool is in your PATH.")
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
