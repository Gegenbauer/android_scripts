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
            
            
class DumpThreadStackCommand(AdbCommand):
    """
    Dump thread stack traces of a target Android app process and pull to local machine.
    
    This command captures thread stack information by:
    1. Listing existing files in /data/anr/ directory
    2. Sending SIGQUIT signal to target process to generate stack dump
    3. Finding the newly created ANR file by comparing file lists
    4. Pulling the ANR file to local cache directory
    """

    def add_custom_arguments(self, parser):
        parser.add_argument(
            "-p", "--package", 
            help="Target application package name. If not provided, --focused must be used."
        )
        parser.add_argument(
            "--focused",
            action="store_true",
            help="Use the currently focused application's package name as the target.",
        )
        parser.add_argument(
            "--cache-dir",
            default=os.environ.get("cache_files_dir", "."),
            help="Local cache directory"
        )
        parser.add_argument(
            "--open-vscode",
            action="store_true",
            help="Open the dumped stack file in VSCode instead of file manager"
        )

    def execute_on_device(self, args, android_util):
        # Determine target package
        package_name = args.package
        if args.focused:
            logger.info("Getting the package name of the currently focused app...")
            focused_package = android_util.get_focused_app_package()
            if focused_package:
                package_name = focused_package
                logger.info(f"Successfully got focused app package name: {package_name}")
            else:
                logger.error(
                    "Could not get the currently focused app package name. Please ensure the target app is in the foreground."
                )
                return

        if not package_name:
            logger.error(
                "Error: You must provide a package name with -p/--package, or use the --focused flag."
            )
            return

        # Get process PID
        logger.info(f"Getting PID for package: {package_name}")
        pid = android_util.get_pid_of_app(package_name)
        if not pid or pid == -1:
            logger.error(f"Could not find running process for package: {package_name}")
            return

        logger.info(f"Found process PID: {pid}")

        try:
            # Step 1: List existing ANR files
            logger.info("Listing existing ANR files...")
            result_before = run_command(
                ["adb", "shell", "ls", "/data/anr/"], 
                check_output=True
            )
            files_before = set(result_before.strip().split('\n')) if result_before.strip() else set()
            logger.info(f"Found {len(files_before)} existing ANR files")

            # Step 2: Send SIGQUIT to trigger thread dump
            logger.info(f"Sending SIGQUIT signal to PID {pid} to generate stack dump...")
            run_command(["adb", "shell", "kill", "-3", str(pid)], check_output=False)
            
            # Wait a moment for the dump to be generated
            import time
            time.sleep(2)

            # Step 3: List ANR files again to find the new one
            logger.info("Checking for new ANR files...")
            result_after = run_command(
                ["adb", "shell", "ls", "/data/anr/"], 
                check_output=True
            )
            files_after = set(result_after.strip().split('\n')) if result_after.strip() else set()
            
            new_files = files_after - files_before
            if not new_files:
                logger.warning("No new ANR file was created. The process might not have generated a stack dump.")
                # Try to find the most recent ANR file as fallback
                logger.info("Attempting to find the most recent ANR file...")
                result_detailed = run_command(
                    ["adb", "shell", "ls", "-lt", "/data/anr/"], 
                    check_output=True
                )
                lines = result_detailed.strip().split('\n')
                if len(lines) > 1:  # Skip the "total" line
                    most_recent = lines[1].split()[-1]  # Get filename from ls -lt output
                    new_files = {most_recent}
                    logger.info(f"Using most recent ANR file: {most_recent}")
                else:
                    logger.error("No ANR files found in /data/anr/")
                    return

            anr_filename = list(new_files)[0]  # Take the first (should be only one)
            remote_anr_path = f"/data/anr/{anr_filename}"
            logger.info(f"Found new ANR file: {anr_filename}")

            # Step 4: Prepare local directory and pull the file
            ts = timestamp()
            sanitized_package = package_name.replace(".", "_")
            local_dir = os.path.join(args.cache_dir, "stack", f"{sanitized_package}_{ts}")
            ensure_directory_exists(local_dir)
            
            local_anr_path = os.path.join(local_dir, f"{sanitized_package}_stack_{ts}.txt")
            
            logger.info(f"Pulling ANR file to local: {local_anr_path}")
            run_command(["adb", "pull", remote_anr_path, local_anr_path], check_output=False)

            # Verify the file was pulled successfully
            if not os.path.exists(local_anr_path):
                logger.error(f"Failed to pull ANR file to: {local_anr_path}")
                return

            logger.info(f"Successfully pulled thread stack dump to: {local_anr_path}")

            # Step 5: Open the file
            if args.open_vscode:
                logger.info("Opening stack dump in VSCode...")
                try:
                    run_command(["code", local_anr_path], check_output=False)
                except Exception as e:
                    logger.warning(f"Failed to open in VSCode: {e}. Opening in file manager instead.")
                    import script_base.utils as utils
                    utils.open_in_file_manager(local_anr_path)
            else:
                logger.info("Opening stack dump in file manager...")
                import script_base.utils as utils
                utils.open_in_file_manager(local_anr_path)

        except Exception as e:
            logger.error(f"Failed to dump thread stack for {package_name}: {e}")
            return