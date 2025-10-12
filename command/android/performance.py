import os

from command.android.base import AdbCommand
from export_bitmaps import export_bitmaps
from script_base.log import logger
from script_base.utils import (
    run_command,
    ensure_directory_exists,
    timestamp)


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
                logger.error(
                    "Could not get the currently focused app package name. Please ensure the target app is in the foreground.")
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


class ExportBitmapsCommand(AdbCommand):
    """
    Export all in-memory Bitmaps from a running Android app process using Frida and pull them to the local machine.
    """
    def add_custom_arguments(self, parser):
        parser.add_argument("--package", type=str, required=True, help="Android package name to export bitmaps from.")
        parser.add_argument("--output-dir", type=str, help="Local output directory. Defaults to cache_files_dir/exported_bitmaps/<package>_<timestamp>/")
        parser.add_argument("--frida-script", type=str, default="export_bitmaps.js", help="Frida JS script filename (default: export_bitmaps.js)")

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