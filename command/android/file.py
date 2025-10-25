import os

from command.android.base import AdbCommand
from script_base.utils import (
    open_in_file_manager,
    run_command,
    ensure_directory_exists,
    timestamp, sanitize_for_fs,
)
from script_base.platforms import current_platform
from script_base.log import logger


class ViewFolderCommand(AdbCommand):
    """Pull a specified directory from the device to a local cache directory and open it in the file manager."""

    def add_custom_arguments(self, parser):
        from script_base.env_setup import env, PathType
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
            default=env.get(PathType.CACHE),
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
        cache_root = args.cache_root
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
        from script_base.env_setup import env, PathType
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
            default=env.get(PathType.CACHE),
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
            "--open-in-file-manager",
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
        cache_root = args.cache_root
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
            current_platform.open_in_vscode(local_file)
        elif args.open_in_file_manager:
            open_in_file_manager(local_file)
        else:
            logger.info(
                "Use --cat to output content, --open-in-vscode to open the file, or --open-in-manager to show it in the file manager."
            )