import subprocess
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")

from script_base.utils import run_command
from script_base.log import logger
from android_util_impls.environment import (
    get_android_sdk_path,
    get_android_ndk_path,
    get_android_platform_tools_path,
    get_adb_path,
    get_android_build_tools_path,
)


class AndroidUtilBase:

    def __init__(self, device: str = None):
        self.device = device

    def get_android_sdk_path(self) -> str:
        return get_android_sdk_path()

    def get_android_ndk_path(self) -> str:
        return get_android_ndk_path()

    def get_android_platform_tools_path(self) -> str:
        return get_android_platform_tools_path()

    def get_android_build_tools_path(self, version) -> str:
        return get_android_build_tools_path(version)

    def get_adb_path(self, warning: bool = False) -> str:
        return get_adb_path(warning=warning)

    def get_connected_devices(self, warningForAdb: bool = True) -> list:
        """
        Get the list of connected Android devices.

        Returns:
            list: List of connected devices, each as a string in the format 'device_id device_name'.
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
            logger.error(f"Error occurred while getting connected devices: {e}", e)
            raise
        
    def get_connected_device_id(self, warningForAdb: bool = True) -> str:
        """
        Get the ID of the first connected Android device.

        Returns:
            str: The ID of the first connected device, or an empty string if no devices are connected.
        """
        if self.device != None and self.device != "":
            return self.device
        devices = self.get_connected_devices(warningForAdb)
        if devices:
            return devices[0].split()[0]
        return ""

    # Get the available adb command string
    def get_adb_command(
        self,
        device: str,
        print_adb_warning: bool = True,
        print_device_warning: bool = True,
    ) -> str:
        """
        Return a command prefix like '/path/to/adb -s device'.
        - If the adb path is invalid, return an empty string.
        - If the device is in the connected devices, return the corresponding device.
        - If device is empty, return the first connected device.
        - If no device, return an empty string.
        - If device is not in the connected devices, return the first connected device and optionally print a warning.
        """
        if device is None:
            device = self.device or ""
        adb_path = self.get_adb_path()
        if not adb_path:
            if print_adb_warning:
                logger.warning(
                    "adb tool not detected, please check environment variables and SDK configuration."
                )
            return ""
        devices = self.get_connected_devices(warningForAdb=False)
        device_ids = [d.split()[0] for d in devices if d.strip()]
        if not device_ids:
            if print_device_warning:
                logger.warning("No connected Android devices detected.")
            return ""
        if device and device in device_ids:
            return f"{adb_path} -s {device}"
        if device and device not in device_ids:
            if print_device_warning:
                logger.warning(
                    f"The specified device {device} is not connected, using the first connected device {device_ids[0]} instead."
                )
            return f"{adb_path} -s {device_ids[0]}"
        # If device is empty, return the first one
        return f"{adb_path} -s {device_ids[0]}"

    def pull_file(self, device: str, remote_path: str, local_path: str) -> bool:
        """
        Pull a file from an Android device to the local machine.

        Args:
            device (str): The ID of the device.
            remote_path (str): The file path on the device.
            local_path (str): The local save path.

        Returns:
            bool: Whether the pull was successful.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} pull {remote_path} {local_path}"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(f"Failed to pull file from device {device}: {e}", e)
            return False

    def push_file(self, device: str, local_path: str, remote_path: str) -> bool:
        """
        Push a local file to an Android device.

        Args:
            device (str): The ID of the device.
            local_path (str): The local file path.
            remote_path (str): The save path on the device.

        Returns:
            bool: Whether the push was successful.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} push {local_path} {remote_path}"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(f"Failed to push file to device {device}: {e}", e)
            return False

    def is_rooted(self, device: str = "") -> bool:
        """
        Check if the device has root access.

        Args:
            device (str): The ID of the device.

        Returns:
            bool: Whether the device has root access.
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
            logger.error(
                f"Error occurred while checking if device {device} is rooted: {e}", e
            )
            return False

    def run_adb_as_root(self, device: str = "") -> bool:
        """
        Restart the adb service with root privileges.

        Args:
            device (str): The ID of the device.

        Returns:
            bool: Whether root access was successfully obtained.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} root"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(f"Failed to obtain root access on device {device}: {e}", e)
            return False

    def is_adb_running_as_root(self, device: str = "") -> bool:
        """
        Check if adb is running as root.

        Args:
            device (str): The ID of the device.

        Returns:
            bool: Whether adb is running as root.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} shell id"
            result = run_command(command, check_output=True, shell=True)
            return "uid=0(root)" in result
        except Exception as e:
            logger.error(
                f"Error occurred while checking if adb is running as root on device {device}: {e}",
                e,
            )
            return False

    def remount(self, device: str) -> bool:
        """
        Remount the system partition as read-write.

        Args:
            device (str): The ID of the device.

        Returns:
            bool: Whether the remount was successful.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} remount"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(
                f"Failed to remount the system partition on device {device}: {e}", e
            )
            return False

    def has_remount(self, device: str) -> bool:
        """
        Check if the device supports remounting the system partition.

        Args:
            device (str): The ID of the device.

        Returns:
            bool: Whether remounting is supported.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f'{adb_cmd} shell "mount | grep /system"'
            result = run_command(command, check_output=True, shell=True)
            return "rw" in result
        except Exception as e:
            logger.error(
                f"Error occurred while checking if device {device} supports remounting: {e}",
                e,
            )
            return False

    def get_device_sdk_version(self, device="") -> str:
        """
        Get the SDK version of the connected Android device.

        Args:
            device (str): The ID of the device.

        Returns:
            str: The SDK version of the device, or an empty string if not found.
        """
        adb_cmd = self.get_adb_command(
            device, print_adb_warning=True, print_device_warning=True
        )
        if not adb_cmd:
            return ""
        try:
            command = f"{adb_cmd} shell getprop ro.build.version.sdk"
            result = run_command(command, check_output=True, shell=True)
            return result.strip()
        except Exception as e:
            logger.error(
                f"Error occurred while getting the SDK version of the device: {e}", e
            )
            raise

    def get_device_brand(self, device="") -> str:
        """
        Get the brand information of the connected Android device.

        Args:
            device (str): The ID of the device.

        Returns:
            str: The brand information of the device, or an empty string if not found.
        """
        adb_cmd = self.get_adb_command(
            device, print_adb_warning=True, print_device_warning=True
        )
        if not adb_cmd:
            return ""
        try:
            command = f"{adb_cmd} shell getprop ro.product.brand"
            result = run_command(command, check_output=True, shell=True)
            return result.strip()
        except Exception as e:
            logger.error(
                f"Error occurred while getting the brand information of the device: {e}",
                e,
            )
            raise

    def get_focused_app_package(self, device="") -> str:
        """
        Get the package name of the currently focused application.

        Args:
        device (str): The ID of the device.

        Returns:
            str: The package name of the currently focused application, or an empty string if not found.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return ""
        try:
            command = f'{adb_cmd} shell "dumpsys activity activities|grep mFocusedApp"'
            result = run_command(command, check_output=True, shell=True)
            focused_app = ""
            # Check the output line by line to find the line containing mFocusedApp and not null after =
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
            logger.error(
                f"Error occurred while getting the package name of the currently focused application: {e}",
                e,
            )
            raise
        return ""

    def get_focused_activity(self, device="") -> str:
        """
        Get the name of the currently focused Activity.

        Args:
            device (str): The ID of the device.

        Returns:
            str: The name of the currently focused Activity, or an empty string if not found.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return ""
        try:
            command = (
                f'{adb_cmd} shell "dumpsys activity activities | grep mFocusedApp"'
            )
            result = run_command(command, shell=True, check_output=True)
            # mFocusedApp=ActivityRecord{def7ea1 u0 com.android.launcher3/.Launcher t55}
            # Get com.android.launcher3/.Launcher
            for line in result.splitlines():
                if "mFocusedApp" in line and "=null" not in line:
                    import re

                    pattern = r"u0\s+([^ ]+)"

                    match = re.search(pattern, line)

                    if match:
                        # group(1) gets the content of the first capture group
                        focused_activity = match.group(1)
                        return focused_activity
                    break
            return ""
        except Exception as e:
            logger.error(
                f"Error occurred while getting the name of the currently focused Activity: {e}",
                e,
            )
            raise

    def get_focused_window(self, device="") -> str:
        """
        Get the name of the currently focused window.

        Args:
            device (str): The ID of the device.

        Returns:
            str: The name of the currently focused window, or an empty string if not found.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return ""
        try:
            command = (
                f'{adb_cmd} shell "dumpsys activity activities | grep mFocusedWindow"'
            )
            result = run_command(command, shell=True, check_output=True)
            first_line = result.splitlines()[0] if result else ""
            if first_line:
                parts = first_line.split("=", 1)
                if len(parts) == 2:
                    window_info = parts[1].strip()
                    return window_info
            return ""
        except Exception as e:
            logger.error(
                f"Error occurred while getting the name of the currently focused window: {e}",
                e,
            )
            raise
        return ""

    def get_resumed_fragment2(self, device="") -> str:
        """
        Get the name of the currently focused Fragment.

        Args:
            device (str): The ID of the device.

        Returns:
            str: The name of the currently focused Fragment, or an empty string if not found.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return ""
        try:
            focused_package = self.get_focused_app_package(device)
            if not focused_package:
                return ""
            command = (
                f'{adb_cmd} shell "dumpsys activity {focused_package} activities | grep mResumed=true"'
            )
            result = run_command(command, shell=True, check_output=True)
            # Find the part containing "Active Fragments" and extract SoundSettings
            # mCreated=true mResumed=true mStopped=false    Active Fragments:    SoundSettings{985054f} (287240d6-e623-4d37-859a-3fec6fc3d8f4) id=0x7f0a02b6}
            for line in result.splitlines():
                if "Active Fragments" in line:
                    import re

                    match = re.search(r"Active Fragments:\s+([^\s{]+)", line)
                    if match:
                        return match.group(1)
            return ""
        except Exception as e:
            logger.error(
                f"Error occurred while getting the name of the currently focused Fragment: {e}",
                e,
            )
            raise

    def get_resumed_fragment(self, device="") -> str:
        """
        Get the name of the currently resumed Fragment from a local dump file.

        This function find resumed fragments from command "adb shell dumpsys activity activities"
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return ""
        import re
        try:
            command = f"{adb_cmd} shell dumpsys activity activities"
            output = run_command(command, check_output=True, shell=True)
            # Find all activities with mResumed=true
            activity_blocks = re.split(r'TASK \d+:', output)[1:]
            for block in activity_blocks:
                # Find all fragments in this activity block
                for frag in re.finditer(r'([A-Za-z0-9_]+Fragment\{[^\}]+\})', block):
                    frag_block = frag.group(1)
                    frag_name_match = re.match(r'([A-Za-z0-9_]+Fragment)', frag_block)
                    frag_name = frag_name_match.group(1) if frag_name_match else None
                    state_match = re.search(r'mState=(\d+)', block)
                    state = int(state_match.group(1)) if state_match else None
                    if state and state >= 5:
                        return frag_name
            return ""
        except Exception as e:
            logger.error(f"Error occurred while getting resumed fragments: {e}", e)
            return ""

    def find_apk_path(self, keyword: str, device="") -> list:
        """
        Find the APK file paths containing the specified keyword. Each item contains the package name and APK path.

        Args:
            keyword (str): The keyword to search for.
            device (str): The ID of the device (optional).

        Returns:
            list: List of APK file paths containing the specified keyword.
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
            logger.error(f"Error occurred while finding APK paths: {e}", e)
            raise
        return []

    def get_app_version(self, package_name: str, device: str = "") -> str:
        """
        Get the version name of the specified application.

        Args:
            package_name (str): The package name of the application to query.
            device (str): The ID of the device (optional).

        Returns:
            str: The version name of the application, or an empty string if not found.
        """
        adb_command = self.get_adb_command(device)
        if not adb_command:
            return ""

        try:
            command = f'{adb_command} shell "dumpsys package {package_name} | grep versionName"'
            result = run_command(command, check_output=True, shell=True)
            # result may contain multiple lines, take the first line
            first_line = result.splitlines()[0] if result else ""
            # first_line format: versionName=1.2.3
            if first_line and "versionName=" in first_line:
                version_name = first_line.split("=")[1].strip()
                return version_name
            logger.info(f"Version name of application {package_name} not found.")
        except Exception as e:
            logger.error(
                f"Error occurred while getting the version name of application {package_name}: {e}",
                e,
            )
            raise

        return ""

    def clear_app_data(self, package_name: str, device="") -> bool:
        """
        Clear the data of the specified application.

        Args:
            package_name (str): The package name of the application to clear data for.
            device (str): The ID of the device.

        Returns:
            bool: Whether the data was successfully cleared.
        """
        adb_command = self.get_adb_command(device)
        if not adb_command:
            return False

        try:
            command = f"{adb_command} shell pm clear {package_name}"
            run_command(command, shell=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(
                f"Error occurred while clearing data for application {package_name}: {e}",
                e,
            )
            raise

    def set_debugger_app(self, package_name: str, device: str = "") -> bool:
        adb_command = self.get_adb_command(device)
        if not adb_command:
            return False
        from activity_manager_service import set_debugger_app

        return set_debugger_app(adb_command, package_name)

    def remove_debugger_app(self, device="") -> bool:
        adb_command = self.get_adb_command(device)
        if not adb_command:
            return False
        from activity_manager_service import remove_debugger_app

        return remove_debugger_app(adb_command)

    def get_pid_of_app(self, package_name: str, device="") -> int:
        """
        Get the process ID (PID) of the specified application.

        Args:
            package_name (str): The package name of the application to get the PID for.
            device (str): The ID of the device (optional).

        Returns:
            int: The PID of the application, or -1 if not found.
        """
        adb_command = self.get_adb_command(device)
        if not adb_command:
            return -1

        try:
            command = f"{adb_command} shell pidof {package_name}"
            result = run_command(
                command, shell=True, check_output=True, ignore_command_error=True
            )
            # check if result is a number

            if result.strip().isdigit():
                pid = int(result.strip())
                return pid
            else:
                logger.info(f"PID of application {package_name} not found.")
        except subprocess.CalledProcessError:
            logger.info(f"PID of application {package_name} not found.")
            return -1
        except Exception as e:
            logger.error(
                f"Error occurred while getting the PID of application {package_name}: {e}",
                e,
            )
            raise

        return -1

    def get_app_version_code(self, package_name: str, device="") -> str:
        """
        Get the version code of the specified application.

        Args:
            package_name (str): The package name of the application to query.
            device (str): The ID of the device (optional).

        Returns:
            str: The version code of the application, or an empty string if not found.
        """
        adb_command = self.get_adb_command(device)
        if not adb_command:
            return False

        try:
            command = f'{adb_command} shell "dumpsys package {package_name} | grep versionCode"'
            result = run_command(command, shell=True, check_output=True)
            # result may contain multiple lines, take the first line
            first_line = result.splitlines()[0] if result else ""
            # first_line format: versionCode=123 minSdk=21 targetSdk=30
            if first_line and "versionCode=" in first_line:
                version_code = first_line.split("=")[1].split()[0].strip()
                return version_code
            logger.info(f"Version code of application {package_name} not found.")
        except Exception as e:
            logger.error(
                f"Error occurred while getting the version code of application {package_name}: {e}",
                e,
            )
            raise

        return ""

    def is_valid_time_format(self, time_str):
        import re

        pattern = r"^\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}$"
        return re.match(pattern, time_str)

    def get_device_timezone_name(self, device="") -> str:
        """Get the IANA timezone name from the device, e.g. 'America/New_York'"""
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
                logger.error("Error: Failed to get timezone name from device.", e)
                return None
            return tz_name
        except Exception as e:
            logger.error(f"Error: Failed to get device timezone: {e}", e)
            raise

    def get_utc_milliseconds_from_device(
        self, local_time_str, tz_name, device=""
    ) -> int:
        """
        Let the device use its own timezone database to convert local time to UTC milliseconds.
        """
        try:
            adb_command = self.get_adb_command(device)
            if not adb_command:
                return False
            # Format the time to fit the 'date -d' command
            # local_time_str format is "YYYY-MM-DD-HH-MM-SS"
            # Convert to "YYYY-MM-DD HH:MM:SS"
            date_part = local_time_str[:10]  # "YYYY-MM-DD"
            time_part = local_time_str[11:].replace("-", ":")  # "HH:MM:SS"
            date_input_str = f"{date_part} {time_part}"
            # Construct the command: TZ='<tz_name>' date -d '<time_str>' +%s
            # This forces the date command to parse the time in the specified timezone and output UTC seconds
            command = (
                f"{adb_command} shell \"TZ='{tz_name}' date -d '{date_input_str}' +%s\""
            )
            utc_seconds_str = run_command(command, check_output=True, shell=True)
            utc_seconds = int(utc_seconds_str.strip())
            return utc_seconds * 1000
        except ValueError as e:
            logger.error(
                f"Error: Failed to parse '{utc_seconds_str.strip()}' returned by the device as an integer.",
                e,
            )
            raise
        except Exception as e:
            logger.error(f"Error: Failed to convert time on device: {e}", e)
            logger.error(
                "Please check if the 'date' command on the device supports the '-d' option."
            )
            raise

    def get_device_cpu_cores_count(self, device="") -> int:
        """Get the number of CPU cores on the device"""
        # The /sys/devices/system/cpu directory will have cpuX directories, where X is the core number
        try:
            adb_command = self.get_adb_command(device)
            if not adb_command:
                return 0
            result = run_command(
                f"{adb_command} shell ls /sys/devices/system/cpu",
                check_output=True,
                shell=True,
            )
            # Check which directory names are cpu[0-9], followed by a number
            import re

            cpu_dirs = [
                line
                for line in result.strip().splitlines()
                if re.match(r"^cpu[0-9]+$", line)
            ]
            cpu_cores = len(cpu_dirs)
            return cpu_cores
        except Exception as e:
            logger.error(
                f"Error: Failed to get the number of CPU cores on the device: {e}", e
            )
            raise

    def get_biggest_cpu_core(self, device="") -> int:
        """
        Get the highest CPU core number on the device

        return an integer greater than 0
        """
        try:
            adb_command = self.get_adb_command(device)
            if not adb_command:
                return 0
            # /sys/devices/system/cpu/cpu{i}/cpufreq/cpuinfo_max_freq
            # Check the contents of all cpuinfo_max_freq files, which is an integer indicating the maximum frequency of the core
            max_freqs = []
            cpu_cores = self.get_device_cpu_cores_count(device)
            # Check if the file exists
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
                    # Read the file contents
                    freq = run_command(
                        f"{adb_command} shell cat /sys/devices/system/cpu/cpu{i}/cpufreq/cpuinfo_max_freq",
                        check_output=True,
                        shell=True,
                    )
                    max_freqs.append(int(freq.strip()))
                except Exception as e:
                    logger.error(
                        f"Error: Failed to get the maximum frequency of CPU{i}: {e}", e
                    )
            biggest_core = max(max_freqs) if max_freqs else 0
            return biggest_core
        except Exception as e:
            logger.error(
                f"Error: Failed to get the highest CPU core on the device: {e}", e
            )
            raise

    def get_device_architecture(self, device="") -> str:
        """Get the CPU architecture information of the device"""
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
            logger.error(
                f"Error: Failed to get the CPU architecture of the device: {e}", e
            )
            raise

    def get_device_cpu_model(self, device="") -> str:
        """Get the CPU model information of the device"""
        try:
            adb_command = self.get_adb_command(device)
            if not adb_command:
                return ""
            return "Not implemented yet"
        except Exception as e:
            logger.error(f"Error: Failed to get the CPU model of the device: {e}", e)
            raise

    def get_device_gpu_model(self, device="") -> str:
        """Get the GPU model information of the device"""
        try:
            adb_command = self.get_adb_command(device)
            if not adb_command:
                return ""
            return "Not implemented yet"
        except Exception as e:
            logger.error(f"Error: Failed to get the GPU model of the device: {e}", e)
            raise

    def get_device_opengl_es_version(self, device="") -> str:
        """Get the OpenGL ES version information of the device"""
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
            logger.error(
                f"Error: Failed to get the OpenGL ES version of the device: {e}", e
            )
            raise

    def set_night_mode(self, mode: str, device="") -> bool:
        """Set the night mode of the device"""
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
            logger.error(f"Error: Failed to set the night mode of the device: {e}", e)
            return False

    def grant_permission(self, permission: str, package_name: str, device="") -> bool:
        """
        Grant the specified permission to the device.

        Args:
            device (str): The ID of the device.
            permission (str): The permission to grant.

        Returns:
            bool: Whether the permission was successfully granted.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} shell pm grant {package_name} {permission}"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(
                f"Failed to grant permission {permission} on device {device}: {e}", e
            )
            return False

    def check_permission(self, permission: str, package_name: str, device="") -> bool:
        """
        Check if the specified permission has been granted to the device.

        Args:
            device (str): The ID of the device.
            permission (str): The permission to check.
            package_name (str): The package name of the application to check.

        Returns:
            bool: Whether the permission has been granted.
        """
        # TODO

    def is_persistent_app(self, package_name: str, device="") -> bool:
        """
        Check if the specified application is a persistent app on the device.

        Args:
            device (str): The ID of the device.
            package_name (str): The package name of the application to check.

        Returns:
            bool: Whether the application is a persistent app.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            # TODO Not implemented yet
            return False
        except Exception as e:
            logger.error(
                f"Failed to check if application {package_name} is a persistent app on device {device}: {e}",
                e,
            )
            return False

    def kill_process(self, package_name: str, device="") -> bool:
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        from activity_manager_service import kill_process

        result = kill_process(adb_cmd, package_name)
        if not result:
            logger.error(
                f"Failed to kill process of application {package_name} on device {device}"
            )
        return result

    def uninstall_app(self, package_name: str, device="") -> bool:
        """
        Uninstall the application on the device.

        Args:
            device (str): The ID of the device.
            package_name (str): The package name of the application to uninstall.

        Returns:
            bool: Whether the application was successfully uninstalled.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} uninstall {package_name}"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(
                f"Failed to uninstall application {package_name} on device {device}: {e}",
                e,
            )
            return False

    def force_gc(self, package_name: str, device="") -> bool:
        """
        Force garbage collection.

        Args:
            device (str): The ID of the device.
            package_name (str): The package name of the application to perform garbage collection for.

        Returns:
            bool: Whether garbage collection was successfully performed.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            pid = self.get_pid_of_app(package_name, device)
            if pid == -1:
                logger.error(
                    f"Cannot perform garbage collection: Application {package_name} is not running on device {device}."
                )
                return False
            command = f"{adb_cmd} shell kill -10 {pid}"
            run_command(command, shell=True)
            return True
        except PermissionError as e:
            logger.error(str(e))
            return False
        except Exception as e:
            logger.error(
                f"Failed to force garbage collection on device {device}: {e}", e
            )
            return False

    def is_remote_path_file(self, remote_path: str, device: str = "") -> bool:
        """
        Check if the remote path on the device is a file.

        Args:
            device (str): The ID of the device.
            remote_path (str): The remote path.

        Returns:
            bool: Whether the remote path is a file.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = (
                f"{adb_cmd} shell [ -f {remote_path} ] && echo 'true' || echo 'false'"
            )
            result = run_command(command, check_output=True, shell=True)
            return result.strip() == "true"
        except Exception as e:
            logger.error(
                f"Error occurred while checking if the path {remote_path} on device {device} is a file: {e}",
                e,
            )
            return False

    def is_remote_path_directory(self, remote_path: str, device: str = "") -> bool:
        """
        Check if the remote path on the device is a directory.

        Args:
            device (str): The ID of the device.
            remote_path (str): The remote path.

        Returns:
            bool: Whether the remote path is a directory.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = (
                f"{adb_cmd} shell [ -d {remote_path} ] && echo 'true' || echo 'false'"
            )
            result = run_command(command, check_output=True, shell=True)
            return result.strip() == "true"
        except Exception as e:
            logger.error(
                f"Error occurred while checking if the path {remote_path} on device {device} is a directory: {e}",
                e,
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
        Get the permission information of all installed applications on the device.

        Args:
            device (str): The ID of the device (optional).

        Returns:
            list: List containing all application permission information, item type is PermissionInfo
        """
        adb_command = self.get_adb_command(device)
        if not adb_command:
            return {}

        try:
            command = f"{adb_command} shell dumpsys package permissions"
            result = run_command(command, check_output=True, shell=True)
            parsed_data = self.parse_dumpsys_output(result)
            # Find the two outermost nodes, Permissions and AppOp Permissions
            permissions_node = parsed_data.get("Permissions", {})
            appop_permissions_node = parsed_data.get("AppOp Permissions", {})
            # Parse the Permissions node
            # "Permission [android.permission.ACCESS_DOWNLOAD_MANAGER_ADVANCED] (ddb6b8e)": {
            #    "sourcePackage": "com.android.providers.downloads",
            #    "uid": "10003 gids=null type=0 prot=signature|privileged",
            #    "perm": "Permission{f063faf android.permission.ACCESS_DOWNLOAD_MANAGER_ADVANCED}"
            # },
            package_permissions = []
            for key, value in permissions_node.items():
                # Use regular expressions to extract the permission name
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
            # Parse the AppOp Permissions node
            # "AppOp Permissions": {
            #    "AppOp Permission android.permission.WRITE_SETTINGS": {
            #        "com.mega.calendar": "com.mega.calendar",
            #    }
            # }
            app_op_permissions = {}
            for key, value in appop_permissions_node.items():
                if key.startswith("AppOp Permission "):
                    permission_name = key.replace("AppOp Permission ", "").strip()
                    app_op_permissions[permission_name] = list(value.keys())
                    package_permissions.append(PermissionInfo(name=permission_name))
            # Merge results
            return package_permissions
        except Exception as e:
            logger.error(
                f"Error occurred while getting all application permission information on the device: {e}",
                e,
            )
            raise

    def check_file_or_directory_exists(self, remote_path: str, device="") -> bool:
        """
        Check if the specified file or directory exists on the device.

        Args:
            device (str): The ID of the device.
            remote_path (str): The remote path to check.
        Returns:
            bool: Whether the file or directory exists.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = (
                f"{adb_cmd} shell [ -e {remote_path} ] && echo 'true' || echo 'false'"
            )
            result = run_command(command, check_output=True, shell=True)
            return result.strip() == "true"
        except Exception as e:
            logger.error(
                f"Error occurred while checking if the path {remote_path} on device {device} exists: {e}",
                e,
            )
            return False

    def delete_file_or_directory(self, remote_path: str, device="") -> bool:
        """
        Delete the specified file or directory on the device.

        Args:
            device (str): The ID of the device.
            remote_path (str): The remote path to delete.
        Returns:
            bool: Whether the file or directory was successfully deleted.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} shell rm -rf {remote_path}"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(
                f"Error occurred while deleting the path {remote_path} on device {device}: {e}",
                e,
            )
            return False

    def create_directory(self, remote_path: str, accessMode: str, device="") -> bool:
        """
        Create a directory on the device.
        Args:
            device (str): The ID of the device.
            remote_path (str): The remote path of the directory to create.
            accessMode (str): The access mode of the directory, e.g. "755".
        Returns:
            bool: Whether the directory was successfully created.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            # Create the directory
            command = f"{adb_cmd} shell mkdir -p {remote_path}"
            run_command(command, shell=True)
            # Set the access mode
            command = f"{adb_cmd} shell chmod {accessMode} {remote_path}"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(
                f"Error occurred while creating directory {remote_path} on device {device}: {e}",
                e,
            )
            return False

    def change_access_mode(self, remote_path: str, accessMode: str, device="") -> bool:
        """
        Change the access mode of a file or directory on the device.
        Args:
            device (str): The ID of the device.
            remote_path (str): The remote path of the file or directory.
            accessMode (str): The access mode to set, e.g. "755".
        Returns:
            bool: Whether the access mode was successfully changed.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            command = f"{adb_cmd} shell chmod {accessMode} {remote_path}"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(
                f"Error occurred while changing access mode of {remote_path} on device {device}: {e}",
                e,
            )
            return False

    def set_binary_xml_enabled(self, enabled: bool, device="") -> bool:
        """
        Enable or disable binary XML parsing on the device.
        Args:
            device (str): The ID of the device.
            enabled (bool): Whether to enable or disable binary XML parsing.
        Returns:
            bool: Whether the operation was successful.
        """
        adb_cmd = self.get_adb_command(device)
        if not adb_cmd:
            return False
        try:
            value = "true" if enabled else "false"
            command = f"{adb_cmd} shell setprop persist.sys.binary_xml {value}"
            run_command(command, shell=True)
            return True
        except Exception as e:
            logger.error(
                f"Error occurred while setting binary XML parsing to {enabled} on device {device}: {e}",
                e,
            )
            return False

    def get_package_flags(self, package_name: str, device="") -> dict:
        """
        Get the flags of the specified application.

        Args:
            package_name (str): The package name of the application to query.
            device (str): The ID of the device (optional).

        Returns:
            dict: A dictionary containing the flags of the application, or an empty dictionary if not found.
        """
        adb_command = self.get_adb_command(device)
        if not adb_command:
            return {}

        try:
            from android_util_impls.package_manager_service import get_flags_for_package

            flags = get_flags_for_package(adb_command, package_name)
            return flags
        except Exception as e:
            logger.error(
                f"Error occurred while getting the flags of application {package_name}: {e}",
                e,
            )
            raise

        return {}

    def get_apk_path(self, package_name: str, device="") -> str:
        """
        Get the APK file path of the specified application on the device.

        Args:
            package_name (str): The package name of the application.
            device (str): The ID of the device (optional).

        Returns:
            str: The APK file path on the device, or an empty string if not found.
        """
        adb_command = self.get_adb_command(device)
        if not adb_command:
            return ""

        try:
            command = f'{adb_command} shell pm path {package_name}'
            result = run_command(command, check_output=True, shell=True)
            
            # Result format: package:/data/app/com.example.app/base.apk
            for line in result.splitlines():
                if line.startswith("package:"):
                    apk_path = line.replace("package:", "").strip()
                    return apk_path
                    
            logger.warning(f"APK path not found for package: {package_name}")
            return ""
        except Exception as e:
            logger.error(
                f"Error occurred while getting APK path for package {package_name}: {e}",
                e,
            )
            raise

        return ""


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
        self.grantedPermissions = []  # List of permission names
        self.deniedPermissions = []  # List of permission names
        self.definedPermissions = []  # List of PermissionInfo objects

    def __repr__(self):
        return f"PackagePermissionInfo(packageName={self.packageName}, requestedPermissions={self.requestedPermissions}, grantedPermissions={self.grantedPermissions}, deniedPermissions={self.deniedPermissions}, definedPermissions={self.definedPermissions})"
