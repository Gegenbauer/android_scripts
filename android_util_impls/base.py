import subprocess
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")

from script_base.utils import run_command
from script_base.log import logger

class AndroidUtilBase:

    def get_android_sdk_path(self) -> str:
        """
        获取 Android SDK 的路径。

        Returns:
            str: Android SDK 的路径，如果未设置则返回空字符串。
        """
        sdk_path = os.environ.get("android_sdk_path", "")
        if not sdk_path:
            logger.error("请设置 ANDROID_SDK_ROOT 环境变量以指向 Android SDK 的安装目录。")
        if not os.path.exists(sdk_path):
            logger.error(
                f"指定的 Android SDK 路径 '{sdk_path}' 不存在，请检查路径是否正确。"
            )
            return ""
        return sdk_path


    def get_android_ndk_path(self) -> str:
        """
        获取 Android NDK 的路径。
        Returns:
            str: Android NDK 的路径，如果未设置则返回空字符串。
        """
        sdk_path = self.get_android_sdk_path()
        if not sdk_path:
            return ""
        # ndk 路径为 sdk_path + '/ndk'
        ndk_path = os.path.join(sdk_path, "ndk")
        if not os.path.exists(ndk_path):
            logger.error(
                "请确保 Android NDK 已安装，并且 ANDROID_SDK_ROOT 环境变量指向正确的目录。"
            )
            return ""
        return ndk_path


    def get_android_platform_tools_path(self) -> str:
        """
        获取 Android 平台工具的路径。
        Returns:
            str: Android 平台工具的路径，如果未设置则返回空字符串。
        """
        sdk_path = self.get_android_sdk_path()
        if not sdk_path:
            return ""
        # 平台工具路径为 sdk_path + '/platform-tools'
        platform_tools_path = os.path.join(sdk_path, "platform-tools")
        if not os.path.exists(platform_tools_path):
            logger.error(
                "请确保 Android SDK 已安装，并且 ANDROID_SDK_ROOT 环境变量指向正确的目录。"
            )
            return ""
        return platform_tools_path


    def get_android_build_tools_path(self, version) -> str:
        """
        获取 Android 构建工具的路径。
        Args:
            version (str): 构建工具的版本号，例如 '30'。
        Returns:
            str: Android 构建工具的路径，如果未设置则返回空字符串。
        """
        sdk_path = self.get_android_sdk_path()
        if not sdk_path:
            return ""
        build_tools_path = os.path.join(sdk_path, "build-tools")
        # 遍历 build-tools 目录，查找指定版本的构建工具，如果有 30.0.3，请求的是 30，认为匹配
        if not os.path.exists(build_tools_path):
            logger.error(
                "请确保 Android SDK 已安装，并且 ANDROID_SDK_ROOT 环境变量指向正确的目录。"
            )
            return ""
        for item in os.listdir(build_tools_path):
            if item.startswith(version):
                build_tools_path = os.path.join(build_tools_path, item)
                if os.path.exists(build_tools_path):
                    return build_tools_path
        logger.error(
            f"未找到 Android 构建工具版本 {version} 的路径，请检查是否已安装该版本。"
        )
        return ""


    def get_adb_path(self, warning: bool = False) -> str:
        """
        获取 adb 工具的路径。
        Returns:
            str: adb 工具的路径，如果未设置则返回空字符串。
        """
        adb_path = (
            os.path.join(self.get_android_platform_tools_path(), "adb")
            if self.get_android_platform_tools_path()
            else ""
        )
        if not adb_path or not os.path.exists(adb_path):
            if warning:
                logger.error(
                    "请确保 adb 工具已安装并在 ANDROID_PLATFORM_TOOLS_ROOT 环境变量指定的目录中。"
                )
        return adb_path


    def get_connected_devices(self, warningForAdb: bool = True) -> list:
        """
        获取连接的 Android 设备列表。

        Returns:
            list: 连接的设备列表，每个设备为一个字符串，格式为 'device_id device_name'。
        """
        adb_path = self.get_adb_path(warningForAdb)
        if not adb_path:
            return []

        try:
            command = f"{adb_path} devices"
            result = run_command(command, check_output=True, shell=True)
            devices = []

            for line in result.splitlines():
                if "\tdevice" in line:
                    parts = line.split("\t")
                    if len(parts) == 2:
                        devices.append(f"{parts[0]} {parts[1]}")

            return devices
        except Exception as e:
            logger.error(f"获取连接的设备时发生错误: {e}", e)
            raise


    # 获取可用的 adb 命令字符串
    def get_adb_command(
        self,
        device: str, print_adb_warning: bool = True, print_device_warning: bool = True
    ) -> str:
        """
        返回形如 '/path/to/adb -s device' 的命令前缀。
        - 如果 adb 路径无效，返回空字符串。
        - 如果 device 在已连接设备中，返回对应 device。
        - 如果 device 为空，返回第一个已连接设备。
        - 如果无设备，返回空字符串。
        - 如果 device 不在已连接设备中，返回第一个已连接设备，并可选打印警告。
        """
        adb_path = self.get_adb_path()
        if not adb_path:
            if print_adb_warning:
                logger.warning("未检测到 adb 工具，请检查环境变量和 SDK 配置。")
            return ""
        devices = self.get_connected_devices(warningForAdb=False)
        device_ids = [d.split()[0] for d in devices if d.strip()]
        if not device_ids:
            if print_device_warning:
                logger.warning("未检测到任何已连接的 Android 设备。")
            return ""
        if device and device in device_ids:
            return f"{adb_path} -s {device}"
        if device and device not in device_ids:
            if print_device_warning:
                logger.warning(
                    f"指定的设备 {device} 未连接，使用第一个已连接设备 {device_ids[0]} 代替。"
                )
            return f"{adb_path} -s {device_ids[0]}"
        # device 为空，返回第一个
        return f"{adb_path} -s {device_ids[0]}"


    def pull_file(self, device: str, remote_path: str, local_path: str) -> bool:
        """
        从 Android 设备拉取文件到本地。

        Args:
            device (str): 设备的 ID。
            remote_path (str): 设备上的文件路径。
            local_path (str): 本地保存路径。

        Returns:
            bool: 拉取是否成功。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} pull {remote_path} {local_path}"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(f"从设备 {device} 拉取文件失败: {e}", e)
            return False


    def push_file(self, device: str, local_path: str, remote_path: str) -> bool:
        """
        将本地文件推送到 Android 设备。

        Args:
            device (str): 设备的 ID。
            local_path (str): 本地文件路径。
            remote_path (str): 设备上的保存路径。

        Returns:
            bool: 推送是否成功。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} push {local_path} {remote_path}"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(f"向设备 {device} 推送文件失败: {e}", e)
            return False


    def is_rooted(self, device: str = "") -> bool:
        """
        检查设备是否已获得 root 权限。

        Args:
            device (str): 设备的 ID。

        Returns:
            bool: 是否已获得 root 权限。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} shell id"
            result = run_command(
                command, check_output=True, shell=True, ignore_command_error=True
            )
            return "uid=0(root)" in result
        except Exception as e:
            logger.error(f"检查设备 {device} 是否为 root 用户时发生错误: {e}", e)
            return False


    def run_adb_as_root(self, device: str = "") -> bool:
        """
        以 root 权限重新启动 adb 服务。

        Args:
            device (str): 设备的 ID。

        Returns:
            bool: 是否成功获取 root 权限。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} root"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(f"在设备 {device} 上获取 root 权限失败: {e}", e)
            return False


    def is_adb_running_as_root(self, device: str = "") -> bool:
        """
        检查 adb 是否以 root 身份运行。

        Args:
            device (str): 设备的 ID。

        Returns:
            bool: 是否已获得 root 权限。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} shell id"
            result = run_command(command, check_output=True, shell=True)
            return "uid=0(root)" in result
        except Exception as e:
            logger.error(f"检查设备 {device} 是否为 root 用户时发生错误: {e}", e)
            return False


    def remount(self, device: str) -> bool:
        """
        重新挂载系统分区为可读写。

        Args:
            device (str): 设备的 ID。

        Returns:
            bool: 是否成功重新挂载。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} remount"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(f"在设备 {device} 上重新挂载系统分区失败: {e}", e)
            return False


    def has_remount(self, device: str) -> bool:
        """
        检查设备是否支持重新挂载系统分区。

        Args:
            device (str): 设备的 ID。

        Returns:
            bool: 是否支持重新挂载。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f'{adb_cmd} shell "mount | grep /system"'
            result = run_command(command, check_output=True, shell=True)
            return "rw" in result
        except Exception as e:
            logger.error(f"检查设备 {device} 是否支持重新挂载时发生错误: {e}", e)
            return False


    def get_device_sdk_version(self, device="") -> str:
        """
        获取连接的 Android 设备的 SDK 版本。

        Args:
            device (str): 设备的 ID。

        Returns:
            str: 设备的 SDK 版本，如果未找到则返回空字符串。
        """
        adb_cmd = self.get_adb_command(device, print_adb_warning=True, print_device_warning=True)
        if not adb_cmd:
            return ""
        try:
            command = f"{adb_cmd} shell getprop ro.build.version.sdk"
            result = run_command(command, check_output=True, shell=True)
            return result.strip()
        except Exception as e:
            logger.error(f"获取设备 SDK 版本时发生错误: {e}", e)
            raise
        
        
    def get_device_brand(self, device="") -> str:
        """
        获取连接的 Android 设备的品牌信息。

        Args:
            device (str): 设备的 ID。

        Returns:
            str: 设备的品牌信息，如果未找到则返回空字符串。
        """
        adb_cmd = self.get_adb_command(device, print_adb_warning=True, print_device_warning=True)
        if not adb_cmd:
            return ""
        try:
            command = f"{adb_cmd} shell getprop ro.product.brand"
            result = run_command(command, check_output=True, shell=True)
            return result.strip()
        except Exception as e:
            logger.error(f"获取设备品牌信息时发生错误: {e}", e)
            raise


    def get_focused_app_package(self, device="") -> str:
        """
        获取当前聚焦的应用程序包名。

        Args:
        device (str): 设备的 ID。

        Returns:
            str: 当前聚焦的应用程序包名，如果未找到则返回空字符串。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return ""
        try:
            command = f'{adb_cmd} shell "dumpsys activity activities|grep mFocusedApp"'
            result = run_command(command, check_output=True, shell=True)
            focused_app = ""
            print(result)
            # 逐行检查输出，找到包含 mFocusedApp 且，= 后面不为 null 的行
            for line in result.splitlines():
                if "mFocusedApp" in line and "=null" not in line:
                    focused_app = line.strip()
                    break
            if focused_app:
                import re

                match = re.search(
                    r"mFocusedApp=ActivityRecord{[^ ]+ u0 ([^/]+)/", focused_app
                )
                if match:
                    return match.group(1)
            return ""
        except Exception as e:
            logger.error(f"获取当前聚焦应用程序包名时发生错误: {e}", e)
            raise
        return ""


    def get_focused_activity(self, device="") -> str:
        """
        获取当前聚焦的 Activity 名称。

        Args:
            device (str): 设备的 ID。

        Returns:
            str: 当前聚焦的 Activity 名称，如果未找到则返回空字符串。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return ""
        try:
            command = f'{adb_cmd} shell "dumpsys activity activities | grep mFocusedApp"'
            result = run_command(command, shell=True, check_output=True)
            # mFocusedApp=ActivityRecord{def7ea1 u0 com.android.launcher3/.Launcher t55}
            # 获得 com.android.launcher3/.Launcher
            for line in result.splitlines():
                if "mFocusedApp" in line and "=null" not in line:
                    import re

                    pattern = r"u0\s+([^ ]+)"

                    match = re.search(pattern, line)

                    if match:
                        # group(1) 获取第一个捕获组的内容
                        focused_activity = match.group(1)
                        return focused_activity
                    break
            return ""
        except Exception as e:
            logger.error(f"获取当前聚焦 Activity 名称时发生错误: {e}", e)
            raise


    def get_focused_window(self, device="") -> str:
        """
        获取当前聚焦的窗口名称。

        Args:
            device (str): 设备的 ID。

        Returns:
            str: 当前聚焦的窗口名称，如果未找到则返回空字符串。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return ""
        try:
            command = f'{adb_cmd} shell "dumpsys activity activities | grep mFocusedWindow"'
            result = run_command(command, shell=True, check_output=True)
            first_line = result.splitlines()[0] if result else ""
            if first_line:
                parts = first_line.split("=", 1)
                if len(parts) == 2:
                    window_info = parts[1].strip()
                    return window_info
            return ""
        except Exception as e:
            logger.error(f"获取当前聚焦窗口名称时发生错误: {e}", e)
            raise
        return ""


    def find_apk_path(self, keyword: str, device="") -> list:
        """
        查找包含指定关键字的 APK 文件路径。每一项包含包名和 APK 路径。

        Args:
            keyword (str): 要搜索的关键字。
            device (str): 设备的 ID（可选）。

        Returns:
            list: 包含指定关键字的 APK 文件路径列表。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return []
        try:
            command = f"{adb_cmd} shell pm list packages -f"
            result = run_command(command, shell=True, check_output=True)
            apk_paths = []
            for line in result.splitlines():
                if keyword in line:
                    parts = line.split("=")
                    if len(parts) == 2:
                        apk_path = parts[0].replace("package:", "")
                        package_name = parts[1]
                        apk_paths.append((package_name, apk_path))
            return apk_paths
        except Exception as e:
            logger.error(f"查找 APK 路径时发生错误: {e}", e)
            raise
        return []


    def get_app_version(self, package_name: str, device: str = "") -> str:
        """
        获取指定应用程序的版本名称。

        Args:
            package_name (str): 要查询的应用程序包名。
            device (str): 设备的 ID（可选）。

        Returns:
            str: 应用程序的版本名称，如果未找到则返回空字符串。
        """
        adb_command = self.get_adb_command(device)
        if not adb_command:
            return ""

        try:
            command = (
                f'{adb_command} shell "dumpsys package {package_name} | grep versionName"'
            )
            result = run_command(command, check_output=True, shell=True)
            # result 可能包含多行，取第一行
            first_line = result.splitlines()[0] if result else ""
            # first_line 格式为: versionName=1.2.3
            if first_line and "versionName=" in first_line:
                version_name = first_line.split("=")[1].strip()
                return version_name
            logger.info(f"未找到应用程序 {package_name} 的版本名称。")
        except Exception as e:
            logger.error(f"获取应用程序 {package_name} 版本名称时发生错误: {e}", e)
            raise

        return ""


    def clear_app_data(self, package_name: str, device="") -> bool:
        """
        清除指定应用程序的数据。

        Args:
            package_name (str): 要清除数据的应用程序包名。
            device (str): 设备的 ID。

        Returns:
            bool: 如果成功清除数据则返回 True，否则返回 False。
        """
        adb_command = self.get_adb_command(device)
        if not adb_command:
            return False

        try:
            command = f"{adb_command} shell pm clear {package_name}"
            run_command(command, shell=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"清除应用程序 {package_name} 数据时发生错误: {e}", e)
            raise


    def set_debugger_app(self, package_name: str, device: str = "") -> bool:
        """
        设置指定应用程序为调试应用程序。

        Args:
            package_name (str): 要设置为调试应用程序的包名。
            device (str): 设备的 ID（可选）。

        Returns:
            bool: 如果成功设置则返回 True，否则返回 False。
        """
        adb_command = self.get_adb_command(device)
        if not adb_command:
            return False

        try:
            command = f"{adb_command} shell am set-debug-app -w {package_name}"
            run_command(command, shell=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"设置应用程序 {package_name} 为调试应用程序时发生错误: {e}", e)
            raise

        return False


    def remove_debugger_app(self, device="") -> bool:
        """
        移除当前设置的调试应用程序。

        Args:
            device (str): 设备的 ID（可选）。

        Returns:
            bool: 如果成功移除则返回 True，否则返回 False。
        """
        adb_command = self.get_adb_command(device)
        if not adb_command:
            return False

        try:
            command = f"{adb_command} shell am clear-debug-app"
            run_command(command, ignore_command_error=True, shell=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"移除调试应用程序时发生错误: {e}", e)
            raise

        return False


    def get_pid_of_app(self, package_name: str, device="") -> str:
        """
        获取指定应用程序的进程 ID (PID)。

        Args:
            package_name (str): 要获取 PID 的应用程序包名。
            device (str): 设备的 ID（可选）。

        Returns:
            str: 应用程序的 PID，如果未找到则返回空字符串。
        """
        adb_command = self.get_adb_command(device)
        if not adb_command:
            return False

        try:
            command = f"{adb_command} shell pidof {package_name}"
            result = run_command(
                command, shell=True, check_output=True, ignore_command_error=True
            )
            pid = result.strip()
            if pid:
                return pid
            else:
                logger.info(f"未找到应用程序 {package_name} 的 PID。")
        except subprocess.CalledProcessError:
            logger.info(f"未找到应用程序 {package_name} 的 PID。")
            return ""
        except Exception as e:
            logger.error(f"获取应用程序 {package_name} 的 PID 时发生错误: {e}", e)
            raise

        return ""


    def get_app_version_code(self, package_name: str, device="") -> str:
        """
        获取指定应用程序的版本代码。

        Args:
            package_name (str): 要查询的应用程序包名。
            device (str): 设备的 ID（可选）。

        Returns:
            str: 应用程序的版本代码，如果未找到则返回空字符串。
        """
        adb_command = self.get_adb_command(device)
        if not adb_command:
            return False

        try:
            command = (
                f'{adb_command} shell "dumpsys package {package_name} | grep versionCode"'
            )
            result = run_command(command, shell=True, check_output=True)
            # result 可能包含多行，取第一行
            first_line = result.splitlines()[0] if result else ""
            # first_line 格式为: versionCode=123 minSdk=21 targetSdk=30
            if first_line and "versionCode=" in first_line:
                version_code = first_line.split("=")[1].split()[0].strip()
                return version_code
            logger.info(f"未找到应用程序 {package_name} 的版本代码。")
        except Exception as e:
            logger.error(f"获取应用程序 {package_name} 版本代码时发生错误: {e}", e)
            raise

        return ""


    def is_valid_time_format(self,time_str):
        import re

        pattern = r"^\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}$"
        return re.match(pattern, time_str)


    def get_device_timezone_name(self, device="") -> str:
        """从设备获取 IANA 时区名称，例如 'America/New_York'"""
        try:
            adb_command = self.get_adb_command(device)
            if not adb_command:
                return False
            result = run_command(
                f"{adb_command} shell getprop persist.sys.timezone",
                check_output=True,
                shell=True,
            )
            tz_name = result.strip()
            if not tz_name:
                logger.error("错误: 未能从设备获取时区名称。", e)
                return None
            return tz_name
        except Exception as e:
            logger.error(f"错误: 获取设备时区失败: {e}", e)
            raise


    def get_utc_milliseconds_from_device(self, local_time_str, tz_name, device="") -> int:
        """
        让设备使用其自身的时区数据库将本地时间转换为 UTC 毫秒。
        """
        try:
            adb_command = self.get_adb_command(device)
            if not adb_command:
                return False
            # 格式化时间以适配 'date -d' 命令
            # local_time_str 格式为 "YYYY-MM-DD-HH-MM-SS"
            # 转换为 "YYYY-MM-DD HH:MM:SS"
            date_part = local_time_str[:10]  # "YYYY-MM-DD"
            time_part = local_time_str[11:].replace("-", ":")  # "HH:MM:SS"
            date_input_str = f"{date_part} {time_part}"
            # 构造命令: TZ='<tz_name>' date -d '<time_str>' +%s
            # 这会强制 date 命令在指定时区下解析时间，并输出 UTC 秒数
            command = (
                f"{adb_command} shell \"TZ='{tz_name}' date -d '{date_input_str}' +%s\""
            )
            utc_seconds_str = run_command(command, check_output=True, shell=True)
            utc_seconds = int(utc_seconds_str.strip())
            return utc_seconds * 1000
        except ValueError as e:
            logger.error(
                f"错误: 无法将设备返回的 '{utc_seconds_str.strip()}' 解析为整数。", e
            )
            raise
        except Exception as e:
            logger.error(f"错误: 在设备上转换时间失败: {e}", e)
            logger.error("请检查设备上的 'date' 命令是否支持 '-d' 选项。")
            raise


    def get_device_cpu_cores_count(self, device="") -> int:
        """获取设备的 CPU 核心数"""
        # /sys/devices/system/cpu 目录下会有 cpuX 目录，X 为核心编号
        try:
            adb_command = self.get_adb_command(device)
            if not adb_command:
                return 0
            result = run_command(
                f"{adb_command} shell ls /sys/devices/system/cpu",
                check_output=True,
                shell=True,
            )
            # 检查哪个目录名称是 cpu[0-9]，后面必须跟数字
            import re

            cpu_dirs = [
                line
                for line in result.strip().splitlines()
                if re.match(r"^cpu[0-9]+$", line)
            ]
            cpu_cores = len(cpu_dirs)
            return cpu_cores
        except Exception as e:
            logger.error(f"错误: 获取设备 CPU 核心数失败: {e}", e)
            raise


    def get_biggest_cpu_core(self, device="") -> int:
        """
        获取设备的最大 CPU 核心编号

        return 大于 0 的整数
        """
        try:
            adb_command = self.get_adb_command(device)
            if not adb_command:
                return 0
            # /sys/devices/system/cpu/cpu{i}/cpufreq/cpuinfo_max_freq
            # 查看所有 cpuinfo_max_freq 文件内容，他是一个整数，表明该核心的最大频率
            max_freqs = []
            cpu_cores = self.get_device_cpu_cores_count(device)
            # 检查文件是否存在
            freq_file_check = run_command(
                f"{adb_command} shell ls /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq",
                check_output=True,
                shell=True,
                ignore_command_error=True,
            )
            if not freq_file_check.strip():
                return 0
            for i in range(cpu_cores):
                try:
                    # 读取文件内容
                    freq = run_command(
                        f"{adb_command} shell cat /sys/devices/system/cpu/cpu{i}/cpufreq/cpuinfo_max_freq",
                        check_output=True,
                        shell=True,
                    )
                    max_freqs.append(int(freq.strip()))
                except Exception as e:
                    logger.error(f"错误: 获取 CPU{i} 最大频率失败: {e}", e)
            biggest_core = max(max_freqs) if max_freqs else 0
            return biggest_core
        except Exception as e:
            logger.error(f"错误: 获取设备最大 CPU 核心失败: {e}", e)
            raise


    def get_device_architecture(self, device="") -> str:
        """获取设备的 CPU 架构信息"""
        try:
            adb_command = self.get_adb_command(device)
            if not adb_command:
                return ""
            result = run_command(
                f"{adb_command} shell getprop ro.product.cpu.abi",
                check_output=True,
                shell=True,
            )
            arch = result.strip()
            return arch
        except Exception as e:
            logger.error(f"错误: 获取设备 CPU 架构失败: {e}", e)
            raise


    def get_device_cpu_model(self, device="") -> str:
        """获取设备的 CPU 型号信息"""
        try:
            adb_command = self.get_adb_command(device)
            if not adb_command:
                return ""
            return "暂未实现"
        except Exception as e:
            logger.error(f"错误: 获取设备 CPU 型号失败: {e}", e)
            raise


    def get_device_gpu_model(self, device="") -> str:
        """获取设备的 GPU 型号信息"""
        try:
            adb_command = self.get_adb_command(device)
            if not adb_command:
                return ""
            return "暂未实现"
        except Exception as e:
            logger.error(f"错误: 获取设备 GPU 型号失败: {e}", e)
            raise


    def get_device_opengl_es_version(self, device="") -> str:
        """获取设备的 OpenGL ES 版本信息"""
        try:
            adb_command = self.get_adb_command(device)
            if not adb_command:
                return ""
            result = run_command(
                f"{adb_command} shell getprop ro.opengles.version",
                check_output=True,
                shell=True,
            )
            opengl_es_version = result.strip()
            return opengl_es_version
        except Exception as e:
            logger.error(f"错误: 获取设备 OpenGL ES 版本失败: {e}", e)
            raise


    def set_night_mode(self, mode: str, device="") -> bool:
        """设置设备的夜间模式"""
        try:
            adb_command = self.get_adb_command(device)
            if not adb_command:
                return False
            run_command(
                f"{adb_command} shell cmd uimode night {mode}",
                check_output=True,
                shell=True,
            )
            return True
        except Exception as e:
            logger.error(f"错误: 设置设备夜间模式失败: {e}", e)
            return False


    def grant_permission(self, permission: str, package_name: str, device="") -> bool:
        """
        授予设备指定的权限。

        Args:
            device (str): 设备的 ID。
            permission (str): 要授予的权限。

        Returns:
            bool: 是否成功授予权限。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} shell pm grant {package_name} {permission}"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(f"在设备 {device} 上授予权限 {permission} 失败: {e}", e)
            return False


    def check_permission(self, permission: str, package_name: str, device="") -> bool:
        """
        检查设备是否已授予指定的权限。

        Args:
            device (str): 设备的 ID。
            permission (str): 要检查的权限。
            package_name (str): 要检查的应用的包名。

        Returns:
            bool: 是否已授予权限。
        """
        # TODO


    def is_persistent_app(self, package_name: str, device="") -> bool:
        """
        检查设备上指定的应用是否为持久化应用。

        Args:
            device (str): 设备的 ID。
            package_name (str): 要检查的应用的包名。

        Returns:
            bool: 是否为持久化应用。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            # TODO 暂未实现
            return False
        except Exception as e:
            logger.error(
                f"在设备 {device} 上检查应用 {package_name} 是否为持久化应用失败: {e}", e
            )
            return False


    def kill_process(self, package_name: str, device="") -> bool:
        """
        杀死设备上指定的进程。

        Args:
            device (str): 设备的 ID。
            package_name (str): 要杀死的进程的包名。

        Returns:
            bool: 是否成功杀死进程。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            # TODO 确认是否需要区分 persistent app
            command = f"{adb_cmd} shell am force-stop {package_name}"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(f"在设备 {device} 上杀死进程 {package_name} 失败: {e}", e)
            return False


    def uninstall_app(self, package_name: str, device="") -> bool:
        """
        卸载设备上的应用。

        Args:
            device (str): 设备的 ID。
            package_name (str): 要卸载的应用的包名。

        Returns:
            bool: 是否成功卸载应用。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} uninstall {package_name}"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(f"在设备 {device} 上卸载应用 {package_name} 失败: {e}", e)
            return False


    def force_gc(self, package_name: str, device="") -> bool:
        """
        强制进行垃圾回收。

        Args:
            device (str): 设备的 ID。
            package_name (str): 要进行垃圾回收的应用的包名。

        Returns:
            bool: 是否成功进行垃圾回收。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} shell kill -10 {self.get_pid_of_app(package_name)}"
            run_command(command, shell=True)
            return True
        except PermissionError as e:
            logger.error(str(e))
            return False
        except Exception as e:
            logger.error(f"在设备 {device} 上强制进行垃圾回收失败: {e}", e)
            return False


    def is_remote_path_file(self, remote_path: str, device: str = "") -> bool:
        """
        检查设备上的远程路径是否为文件。

        Args:
            device (str): 设备的 ID。
            remote_path (str): 远程路径。

        Returns:
            bool: 如果是文件则返回 True，否则返回 False。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} shell [ -f {remote_path} ] && echo 'true' || echo 'false'"
            result = run_command(command, check_output=True, shell=True)
            return result.strip() == "true"
        except Exception as e:
            logger.error(
                f"检查设备 {device} 上的路径 {remote_path} 是否为文件时发生错误: {e}", e
            )
            return False


    def is_remote_path_directory(self, remote_path: str, device: str = "") -> bool:
        """
        检查设备上的远程路径是否为目录。

        Args:
            device (str): 设备的 ID。
            remote_path (str): 远程路径。

        Returns:
            bool: 如果是目录则返回 True，否则返回 False。
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} shell [ -d {remote_path} ] && echo 'true' || echo 'false'"
            result = run_command(command, check_output=True, shell=True)
            return result.strip() == "true"
        except Exception as e:
            logger.error(
                f"检查设备 {device} 上的路径 {remote_path} 是否为目录时发生错误: {e}", e
            )
            return False


    def parse_dumpsys_output(self, text: str) -> dict:
        """
        Parses adb dumpsys-like output with indentation into a nested dictionary.

        Args:
            text: The multi-line string content from dumpsys.

        Returns:
            A dictionary representing the hierarchical structure of the data.
        """
        lines = text.strip().split("\n")

        # Root node of the tree
        root = {"_root_": {}}

        # A stack to keep track of the current path in the tree
        # Each item in the stack is a tuple: (indent_level, dict_reference)
        stack = [(0, root["_root_"])]

        # Regular expression to extract the key and value from the line
        # It captures key-value pairs (e.g., "userId=1073") or simple keys (e.g., "Packages")
        import re

        line_pattern = re.compile(r"^\s*(.*?)(?::\s*|\s*=\s*)(.*)$")

        for line in lines:
            if not line.strip():
                continue

            # Get the current line's indentation level
            indent = len(line) - len(line.lstrip(" "))

            # Get the current parent from the stack
            current_indent, current_dict = stack[-1]

            # Adjust the stack based on indentation
            while indent <= current_indent and len(stack) > 1:
                stack.pop()
                current_indent, current_dict = stack[-1]

            # Clean the line by removing leading/trailing spaces
            clean_line = line.strip()

            # Extract key and value using regex
            match = line_pattern.match(clean_line)
            if match:
                key, value = match.groups()

                # If the value is empty, it's a new sub-tree (a header)
                if not value:
                    new_dict = {}
                    current_dict[key.strip()] = new_dict
                    stack.append((indent, new_dict))
                else:
                    # Store as a key-value pair
                    current_dict[key.strip()] = value.strip()
            else:
                # Handle lines that are just a simple key without a value,
                # which might also be a list item.
                # Example: "PackageSetting{...}"
                key = clean_line
                # If the key is already present, convert it into a list of items
                if key in current_dict:
                    if not isinstance(current_dict[key], list):
                        current_dict[key] = [current_dict[key]]
                    current_dict[key].append(key)
                else:
                    # Add a new key as a leaf node
                    current_dict[key] = key

        # Return the first key of the root, which contains the parsed data
        return root["_root_"]


    def get_all_permissions(self, device="") -> list:
        """
        获取设备上所有已安装应用的权限信息。

        Args:
            device (str): 设备的 ID（可选）。

        Returns:
            list: 包含所有应用权限信息的列表， item 类型为 PermissionInfo
        """
        adb_command = self.get_adb_command(device)
        if not adb_command:
            return {}

        try:
            command = f"{adb_command} shell dumpsys package permissions"
            result = run_command(command, check_output=True, shell=True)
            parsed_data = self.parse_dumpsys_output(result)
            # 找到最外层的两个节点，分别是 Permissions 和 AppOp Permissions
            permissions_node = parsed_data.get("Permissions", {})
            appop_permissions_node = parsed_data.get("AppOp Permissions", {})
            # 解析 Permissions 节点
            #"Permission [android.permission.ACCESS_DOWNLOAD_MANAGER_ADVANCED] (ddb6b8e)": {
            #    "sourcePackage": "com.android.providers.downloads",
            #    "uid": "10003 gids=null type=0 prot=signature|privileged",
            #    "perm": "Permission{f063faf android.permission.ACCESS_DOWNLOAD_MANAGER_ADVANCED}"
            #},
            package_permissions = []
            for key, value in permissions_node.items():
                # 使用正则表达式提取权限名称
                import re
                match = re.match(r"Permission \[(.+?)\]", key)
                if match:
                    permission_name = match.group(1)
                    source_package = value.get("sourcePackage", "")
                    prot = ""
                    uid_info = value.get("uid", "")
                    if "prot=" in uid_info:
                        prot = uid_info.split("prot=")[-1].strip()
                    package_permissions.append(
                        PermissionInfo(
                            name=permission_name,
                            sourcePackage=source_package,
                            prot=prot,
                        )
                    )
            # 解析 AppOp Permissions 节点
            #"AppOp Permissions": {
            #    "AppOp Permission android.permission.WRITE_SETTINGS": {
            #        "com.mega.calendar": "com.mega.calendar",
            #    }
            #}
            app_op_permissions = {}
            for key, value in appop_permissions_node.items():
                if key.startswith("AppOp Permission "):
                    permission_name = key.replace("AppOp Permission ", "").strip()
                    app_op_permissions[permission_name] = list(value.keys())
                    package_permissions.append(
                        PermissionInfo(
                            name=permission_name
                        )
                    )
            # 合并结果
            return package_permissions
        except Exception as e:
            logger.error(f"获取设备上所有应用权限信息时发生错误: {e}", e)
            raise
        
class PermissionInfo:
    def __init__(self, name="", sourcePackage="", prot=""):
        self.name = name
        self.sourcePackage = sourcePackage
        self.prot = prot
    
    def __repr__(self):
        return f"PermissionInfo(name={self.name}, sourcePackage={self.sourcePackage}, prot={self.prot})"
        

class PackagePermissionInfo:
    def __init__(self, packageName=""):
        self.packageName = packageName
        self.requestedPermissions = []  # List of permission names
        self.grantedPermissions = []    # List of permission names
        self.deniedPermissions = []     # List of permission names
        self.definedPermissions = []    # List of PermissionInfo objects
    
    def __repr__(self):
        return f"PackagePermissionInfo(packageName={self.packageName}, requestedPermissions={self.requestedPermissions}, grantedPermissions={self.grantedPermissions}, deniedPermissions={self.deniedPermissions}, definedPermissions={self.definedPermissions})"