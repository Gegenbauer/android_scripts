#!/usr/bin/env python3
"""
综合 adb 工具脚本，整合 set_time、show_focused_activity、android_file_viewer 功能。
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


# ===== ViewFolderCommand & ViewFileCommand =====
class ViewFolderCommand(Command):
    """从设备拉取指定目录到本地缓存目录，并在文件管理器中打开。"""

    def add_arguments(self, parser):
        parser.add_argument(
            "--device-path",
            "-p",
            type=str,
            required=True,
            help="Android 设备上的目录路径，例如 /sdcard/Download/",
        )
        parser.add_argument(
            "--cache-root",
            type=str,
            help="本地缓存根目录（默认取环境变量 cache_files_dir 或当前目录）",
        )
        parser.add_argument(
            "--tag",
            type=str,
            help="可选。自定义目录标签名，便于区分多次拉取。默认为基于设备路径与时间戳自动生成",
        )
        parser.add_argument(
            "--no-open", action="store_true", help="仅拉取到本地，不打开文件管理器"
        )

    def execute(self, args):
        device_path = args.device_path
        if not device_path:
            logger.error("错误: 必须提供 --device-path。")
            return
        cache_root = cache_root_arg_to_path(args.cache_root)
        ensure_directory_exists(cache_root)
        tag = args.tag if args.tag else f"{sanitize_for_fs(device_path)}_{timestamp()}"
        local_base_dir = os.path.join(cache_root, "android_viewer", tag)
        ensure_directory_exists(local_base_dir)
        android_util = android_util_manager.select()
        connected_devices = android_util.get_connected_devices()
        if not connected_devices:
            logger.info("未找到连接的设备。")
            return
        is_remote_path_dir = android_util.is_remote_path_directory(
            remote_path=device_path
        )
        if not is_remote_path_dir:
            logger.error(f"错误: 设备路径 {device_path} 不是一个目录。")
            return
        logger.info(f"拉取目录: {device_path} -> {local_base_dir}")
        try:
            run_command(
                ["adb", "pull", device_path, local_base_dir], check_output=False
            )
        except PermissionError as e:
            logger.error(f"adb pull 权限错误: {e}", e)
            return
        except Exception as e:
            logger.error(f"adb pull 失败: {e}", e)
            return
        basename = os.path.basename(device_path.rstrip("/")) or "root"
        open_dir = os.path.join(local_base_dir, basename)
        if not os.path.exists(open_dir):
            open_dir = local_base_dir
        logger.info(f"本地目录: {open_dir}")
        if not args.no_open:
            open_in_file_manager(open_dir)


class ViewFileCommand(Command):
    """从设备拉取指定文件到本地缓存目录，支持输出到终端或在 VSCode 中打开。"""

    def add_arguments(self, parser):
        parser.add_argument(
            "--device-path",
            "-p",
            type=str,
            required=True,
            help="Android 设备上的文件路径，例如 /sdcard/xxx.txt",
        )
        parser.add_argument(
            "--cache-root",
            type=str,
            help="本地缓存根目录（默认取环境变量 cache_files_dir 或当前目录）",
        )
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "--cat", action="store_true", help="拉取后直接在终端输出文件内容"
        )
        group.add_argument(
            "--open-in-vscode", action="store_true", help="拉取后用 VSCode 打开文件"
        )
        group.add_argument(
            "--open-in-manager",
            action="store_true",
            help="拉取后在文件管理器中显示文件",
        )
        parser.add_argument(
            "--encoding",
            type=str,
            default="utf-8",
            help="当使用 --cat 输出时采用的文件编码，默认 utf-8",
        )

    def execute(self, args):
        device_path = args.device_path
        if not device_path:
            logger.error("错误: 必须提供 --device-path。")
            return
        cache_root = cache_root_arg_to_path(args.cache_root)
        ensure_directory_exists(cache_root)
        tag = f"{sanitize_for_fs(device_path)}_{timestamp()}"
        local_dir = os.path.join(cache_root, "android_viewer", tag)
        ensure_directory_exists(local_dir)
        android_util = android_util_manager.select()
        is_remote_path_file = android_util.is_remote_path_file(device_path)
        if not is_remote_path_file:
            logger.error(f"错误: 设备路径 {device_path} 不是一个文件。")
            return
        logger.info(f"拉取文件: {device_path} -> {local_dir}")
        connected_devices = android_util.get_connected_devices()
        if not connected_devices:
            logger.info("未找到连接的设备。")
            return
        try:
            run_command(["adb", "pull", device_path, local_dir], check_output=False)
        except PermissionError as e:
            logger.info(f"{str(e)}")
            return
        except Exception as e:
            logger.error(f"adb pull 失败: {e}", e)
            return
        local_file = os.path.join(local_dir, os.path.basename(device_path))
        if not os.path.exists(local_file):
            candidate = os.path.join(
                local_dir, os.path.basename(device_path.rstrip("/"))
            )
            local_file = candidate if os.path.exists(candidate) else local_file
        if not os.path.exists(local_file):
            logger.error(f"未找到本地文件: {local_file}")
            return
        logger.info(f"本地文件: {local_file}")
        # if xml_content:
        #     with open(local_file, "w", encoding="utf-8") as f:
        #         f.write(xml_content)
        # xml_content = ""
        # is_binary = android_util.is_binary_xml(local_file)
        # if is_binary:
        #     logger.info("检测到二进制 XML 文件，尝试解析...")
        #     xml_content = android_util.parse_binary_xml(local_file)
        # else:
        #     is_aapt_binary_xml = android_util.is_aapt_binary_xml(local_file)
        #     if is_aapt_binary_xml:
        #         logger.info("检测到 AAPT 二进制 XML 文件，尝试解析...")
        #         xml_content = android_util.parse_aapt_binary_xml(local_file)
        #         # 将解析后的 xml 写入回本地文件
        #     is_aapt2_binary_xml = android_util.is_aapt2_binary_xml(local_file)
        #     if is_aapt2_binary_xml:
        #         logger.info("检测到 AAPT2 二进制 XML 文件，尝试解析...")
        #         xml_content = android_util.parse_aapt2_binary_xml(local_file)
        #         # 将解析后的 xml 写入回本地文件
        if args.cat:
            try:
                with open(
                    local_file, "r", encoding=args.encoding, errors="replace"
                ) as f:
                    print(f.read())
            except Exception as e:
                logger.error(f"读取文件失败: {e}", e)
        elif args.open_in_vscode:
            open_in_vscode(local_file)
        elif args.open_in_manager:
            open_in_file_manager(local_file)
        else:
            logger.info(
                "使用 --cat 输出内容，或使用 --open-in-vscode 打开文件，或 --open-in-manager 在文件管理器中显示文件。"
            )


class SetTimeCommand(Command):
    """
    设置 Android 设备时间
    """

    def add_arguments(self, parser):
        parser.add_argument(
            "time", help="目标时间(YYYY-MM-DD-HH-MM-SS)或'auto'自动同步网络时间"
        )

    def execute(self, args):
        if args.time == "auto":
            # 自动同步网络时间
            run_command("adb shell settings put global auto_time 1", shell=True)
            run_command(
                "adb shell settings put global auto_time_zone 1", shell=True
            )  # Also enable auto timezone
            log("自动时间和时区已启用")
            return
        android_util = android_util_manager.select()
        # 校验时间格式
        if not android_util.is_valid_time_format(args.time):
            logger.error(
                "时间格式错误，应为 YYYY-MM-DD-HH-MM-SS 或 'auto'", level="error"
            )
            return

        connected_devices = android_util.get_connected_devices()
        if not connected_devices:
            logger.info("未找到连接的设备。")
            return

        android_util = android_util_manager.select()
        # 从设备获取 IANA 时区名称
        device_tz_name = android_util.get_device_timezone_name()
        if not device_tz_name:
            return
        # 让设备自己计算 UTC 时间戳
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
    显示当前聚焦的 Activity
    """

    def add_arguments(self, parser):
        pass

    def execute(self, args):
        android_util = android_util_manager.select()
        connnected_devices = android_util.get_connected_devices()
        if not connnected_devices:
            logger.error("未检测到连接的设备")
            return
        focused_package = android_util.get_focused_app_package()
        focused_activity = android_util.get_focused_activity()
        focused_window = android_util.get_focused_window()
        logger.info(f"当前聚焦的包名: {focused_package}")
        logger.info(f"当前聚焦的 Activity: {focused_activity}")
        logger.info(f"当前聚焦的 Window: {focused_window}")


class DumpMemoryCommand(Command):
    """
    导出 Android 设备内存快照，并拉取到本地。可选转换为 MAT 支持的格式，并在 Finder 中展示。
    """

    def add_arguments(self, parser):
        parser.add_argument(
            "-p", "--package", help="目标应用包名。如果未提供，则必须使用 --focused。"
        )
        parser.add_argument(
            "--focused",
            action="store_true",
            help="使用当前聚焦的应用包名作为目标。",
        )
        parser.add_argument(
            "--convert-mat",
            action="store_true",
            help="是否转换为 MAT 支持的 hprof 格式",
        )
        parser.add_argument(
            "--cache-dir",
            default=os.environ.get("cache_files_dir", "."),
            help="本地缓存目录",
        )

    def execute(self, args):
        package_name = args.package
        if args.focused:
            logger.info("正在获取当前聚焦的应用包名...")
            android_util = android_util_manager.select()
            focused_package = android_util.get_focused_app_package()
            if focused_package:
                package_name = focused_package
                logger.info(f"成功获取到聚焦应用包名: {package_name}")
            else:
                logger.error("无法获取当前聚焦的应用包名，请确保目标应用在前台。")
                return

        if not package_name:
            logger.error(
                "错误: 必须通过 -p/--package 提供包名，或使用 --focused 标志。"
            )
            return

        ts = timestamp()
        local_dir = os.path.join(args.cache_dir, "mem_dump", package_name, ts)
        ensure_directory_exists(local_dir)
        remote_hprof = f"/data/local/tmp/{package_name}_{ts}.hprof"
        local_hprof = os.path.join(local_dir, f"{package_name}_{ts}.hprof")
        # 导出内存
        logger.info(f"导出内存快照: {remote_hprof}")
        run_command(["adb", "shell", "am", "dumpheap", package_name, remote_hprof])
        # 拉取到本地
        logger.info(f"拉取到本地: {local_hprof}")
        run_command(["adb", "pull", remote_hprof, local_hprof])
        # 可选转换
        if args.convert_mat:
            mat_hprof = os.path.join(local_dir, f"{package_name}_{ts}_mat.hprof")
            logger.info(f"转换为 MAT 格式: {mat_hprof}")
            run_command(["adb", "shell", "rm", remote_hprof])  # 清理设备端
            # Android 导出的 hprof 需用 hprof-conv 转换
            platform_tools_path = android_util.get_android_platform_tools_path()
            hprof_conv = (
                os.path.join(platform_tools_path, "hprof-conv")
                if platform_tools_path
                else "hprof-conv"
            )
            if not os.path.exists(hprof_conv):
                logger.warning("未找到 hprof-conv 工具，跳过转换")
            else:
                run_command([hprof_conv, local_hprof, mat_hprof])
                local_hprof = mat_hprof
        # 打开 Finder
        import platform

        if platform.system().lower() == "darwin":
            run_command(["open", "-R", local_hprof], check_output=False)
        elif platform.system().lower().startswith("win"):
            run_command(["explorer", "/select,", local_hprof], check_output=False)
        else:
            run_command(["xdg-open", local_dir], check_output=False)
        logger.info(f"内存快照已保存到: {local_hprof}")


class SetUiModeCommand(Command):
    """
    切换 Android 设备的白天/黑夜模式。
    """

    def add_arguments(self, parser):
        parser.add_argument(
            "mode",
            choices=["day", "night", "auto"],
            help="要设置的 UI 模式: 'day' (白天), 'night' (黑夜), 或 'auto' (自动)。",
        )

    def execute(self, args):
        # 检查设备连接
        android_util = android_util_manager.select()
        if not android_util.get_connected_devices():
            logger.error("未检测到连接的设备")
            return

        # 映射用户输入到 adb 命令参数
        mode_map = {"day": "no", "night": "yes", "auto": "auto"}
        adb_mode_arg = mode_map[args.mode]

        try:
            logger.info(
                f"正在将 UI 模式设置为: {args.mode} (adb: 'cmd uimode night {adb_mode_arg}')"
            )
            run_command(["adb", "shell", "cmd", "uimode", "night", adb_mode_arg])
            logger.info("UI 模式设置成功。")
        except Exception as e:
            logger.error(f"设置 UI 模式时失败", exc=e)


class KillCommand(Command):
    """
    强制停止一个 Android 应用。
    """

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-p", "--package", help="要强制停止的目标应用包名。")
        group.add_argument(
            "--focused",
            action="store_true",
            help="强制停止当前聚焦的应用。",
        )

    def execute(self, args):
        package_name = args.package
        if args.focused:
            logger.info("正在获取当前聚焦的应用包名...")
            android_util = android_util_manager.select()
            focused_package = android_util.get_focused_app_package()
            if focused_package:
                package_name = focused_package
                logger.info(f"成功获取到聚焦应用包名: {package_name}")
            else:
                logger.error("无法获取当前聚焦的应用包名，请确保目标应用在前台。")
                return

        try:
            logger.info(f"正在强制停止应用: {package_name}")
            android_util.kill_process(package_name)
            logger.info(f"应用 {package_name} 已被强制停止。")
        except Exception as e:
            logger.error(f"强制停止应用 {package_name} 失败", exc=e)


class ClearDataCommand(Command):
    """
    清除应用的部分或全部数据，提供比 'pm clear' 更精细的控制。
    需要 root 权限来操作内部存储。
    """

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-p", "--package", help="目标应用包名。")
        group.add_argument(
            "--focused", action="store_true", help="使用当前聚焦的应用包名。"
        )

        parser.add_argument(
            "--type",
            nargs="+",  # 允许多个值
            required=True,
            choices=["database", "shared_prefs", "files", "cache", "mmkv", "all"],
            help="要清除的数据类型（可多选）。'all' 会清除所有类型。",
        )
        parser.add_argument(
            "--location",
            choices=["internal", "external"],
            default="internal",
            help="数据存储位置：'internal' (默认) 或 'external'。",
        )

    def execute(self, args):
        package_name = args.package
        if args.focused:
            logger.info("正在获取当前聚焦的应用包名...")
            android_util = android_util_manager.select()
            focused_package = android_util.get_focused_app_package()
            if focused_package:
                package_name = focused_package
                logger.info(f"成功获取到聚焦应用包名: {package_name}")
            else:
                logger.error("无法获取当前聚焦的应用包名，请确保目标应用在前台。")
                return

        # 检查 root 权限
        if args.location == "internal" and not android_util.is_adb_running_as_root():
            logger.error("错误: 清除内部存储数据需要 root 权限。请先执行 'adb root'。")
            return

        # 定义路径映射
        path_map = {
            "internal": {
                "database": f"/data/data/{package_name}/databases",
                "shared_prefs": f"/data/data/{package_name}/shared_prefs",
                "files": f"/data/data/{package_name}/files",
                "cache": f"/data/data/{package_name}/cache",
                "mmkv": f"/data/data/{package_name}/files/mmkv",  # MMKV 默认路径
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
            f"准备在 '{args.location}' 位置为应用 '{package_name}' 清除以下类型的数据: {', '.join(types_to_clear)}"
        )

        for data_type in types_to_clear:
            location_map = path_map.get(args.location)
            if not location_map or data_type not in location_map:
                logger.warning(
                    f"警告: 在 '{args.location}' 位置不支持清除 '{data_type}' 类型的数据，已跳过。"
                )
                continue

            target_path = location_map[data_type]
            try:
                logger.info(f"正在清除: {target_path}")
                # 使用 rm -rf 清除目录内容
                run_command(["adb", "shell", "rm", "-rf", f"{target_path}/*"])
                logger.info(f"成功清除 {target_path} 的内容。")
            except Exception as e:
                logger.error(f"清除 {target_path} 时失败", exc=e)


if __name__ == "__main__":
    # 测试 环境变量中 android_sdk_path 是否存在
    manager = ScriptManager(
        description="Android ADB 多功能工具脚本。\n\n包含 set-time, show-focused-activity, file-viewer 等子命令，支持时间设置、聚焦 Activity 查询、文件/文件夹拉取与查看等功能。\n\n用法示例：\n  python adb.py set-time 2025-08-23-12-00-00\n  python adb.py show-focused-activity\n  python adb.py file-viewer view-folder /sdcard/Download\n  python adb.py file-viewer view-file /sdcard/Download/test.txt --open-in-vscode\n  python adb.py set-ui-mode night\n  python adb.py dump-memory --focused\n"
    )

    manager.register_command(
        "set-time", SetTimeCommand(), help_text="设置 Android 设备时间。"
    )
    manager.register_command(
        "show-focused-activity",
        ShowFocusedActivityCommand(),
        help_text="显示当前聚焦的 Activity。",
    )
    manager.register_command(
        "view-folder",
        ViewFolderCommand(),
        help_text="查看设备目录：拉取到本地并打开文件管理器。",
    )
    manager.register_command(
        "view-file",
        ViewFileCommand(),
        help_text="查看设备文件：拉取到本地，可输出或在 VSCode 打开。",
    )
    manager.register_command(
        "dump-memory",
        DumpMemoryCommand(),
        help_text="导出内存快照并拉取到本地，可选转换为 MAT 格式并在 Finder 展示。",
    )
    manager.register_command(
        "set-ui-mode",
        SetUiModeCommand(),
        help_text="切换 Android 设备的白天/黑夜模式。",
    )
    manager.register_command(
        "kill",
        KillCommand(),
        help_text="强制停止一个 Android 应用（通过包名或聚焦的应用）。",
    )
    manager.register_command(
        "clear-data",
        ClearDataCommand(),
        help_text="精细化清除应用数据（需要 root 权限）。"
    )

    manager.run()
