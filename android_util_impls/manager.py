#!/usr/bin/env python3
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")

from android_util_impls.base import AndroidUtilBase
from script_base.log import logger


class AndroidUtilManager:
    """
    Manage all AndroidUtil implementations and select the most suitable one based on device information.
    """

    def __init__(self):
        # [(impl_class, android_version, brand)]
        self._impls = [(AndroidUtilBase, None, None)]

    def register(self, impl_class, android_version=None, brand=None):
        """
        Register an implementation class, optionally specifying the applicable android_version and brand name.
        """
        self._impls.append((impl_class, android_version, brand))
        logger.info(f"Registered implementation: {impl_class.__name__}, version={android_version}, brand={brand}")

    def select(self):
        """
        Select the most suitable implementation based on device_info.
        device_info: dict, must contain 'android_version', 'brand'
        """
        default_impl = self._impls[0][0]()
        version = default_impl.get_device_sdk_version()
        brand = default_impl.get_device_brand()
        for impl, v, b in self._impls:
            if (v is None or v == version) and (b is None or b.lower() == (brand or '').lower()):
                return impl()
        for impl, v, b in self._impls:
            if v is None or v == version:
                return impl()
        for impl, v, b in self._impls:
            if b is None or b.lower() == (brand or '').lower():
                return impl()
        if self._impls:
            return self._impls[0][0]()
        raise RuntimeError("No AndroidUtil implementation registered")


# Global manager instance
android_util_manager = AndroidUtilManager()

if __name__ == "__main__":
    try:
        android_util = android_util_manager.select()
        logger.info(f"Android SDK Path:{android_util.get_android_sdk_path()}")
        logger.info(f"Android NDK Path:{android_util.get_android_ndk_path()}")
        logger.info(f"Android Platform Tools Path:{android_util.get_android_platform_tools_path()}")
        get_device_sdk_version = android_util.get_device_sdk_version()
        logger.info(f"Device SDK Version:{get_device_sdk_version}")
        logger.info(f"Device Brand:{android_util.get_device_brand()}")
        logger.info(
            f"Android Build Tools Path:{android_util.get_android_build_tools_path(get_device_sdk_version)}"
        )
        logger.info(f"ADB Path:{android_util.get_adb_path()}")
        logger.info(f"Focused App Package:{android_util.get_focused_app_package()}")
        logger.info(f"APK Paths containing 'example':{android_util.find_apk_path('settings')}")
        logger.info(f"Focused Activity:{android_util.get_focused_activity()}")
        logger.info(f"Focused Window:{android_util.get_focused_window()}")
        logger.info(
            f"App Version for 'com.android.settings':{android_util.get_app_version('com.android.settings')}"
        )
        pid = android_util.get_pid_of_app("com.android.settings")
        if pid == -1:
            logger.info("PID of 'com.android.settings' not found. Is the app running?")
        else:
            logger.info(f"PID of 'com.android.settings': {pid}")
        logger.info(
            "Clearing app data for 'com.android.settings':"
            +str(android_util.clear_app_data("com.android.settings"))
        )
        logger.info(
            "Setting debugger app to 'com.android.settings':"
            +str(android_util.set_debugger_app("com.android.settings"))
        )
        logger.info("Removing debugger app:" + str(android_util.remove_debugger_app()))
        logger.info("Connected Devices:" + str(android_util.get_connected_devices()))
        logger.info("Device Timezone Name:" + str(android_util.get_device_timezone_name()))
        logger.info("Device CPU Cores Count:" + str(android_util.get_device_cpu_cores_count()))
        logger.info("Device Biggest CPU Core Frequency:" + str(android_util.get_biggest_cpu_core()))
        logger.info("Device Architecture:" + str(android_util.get_device_architecture()))
        logger.info("Device CPU Model:" + str(android_util.get_device_cpu_model()))
        logger.info("Device GPU Model:" + str(android_util.get_device_gpu_model()))
        logger.info("Device OpenGL ES Version:" + str(android_util.get_device_opengl_es_version()))
        logger.info("Setting Night Mode:" + str(android_util.set_night_mode(mode="yes")))
        logger.info("Setting Night Mode:" + str(android_util.set_night_mode(mode="no")))
        logger.info("Is device rooted? " + str(android_util.is_rooted()))
        # logger.info("Is 'com.android.launcher3' a persistent app? " + str(is_persistent_app(package_name='com.android.launcher3')))
        # logger.info("Granting permission 'android.permission.ACCESS_FINE_LOCATION': " + str(grant_permission(permission='android.permission.ACCESS_FINE_LOCATION', package_name='com.android.launcher3')))
        # logger.info("Checking permission 'android.permission.ACCESS_FINE_LOCATION': " + str(check_permission(permission='android.permission.ACCESS_FINE_LOCATION', package_name='com.android.launcher3')))
        logger.info(
            "Forcing GC for 'com.android.launcher3': "
            +str(android_util.force_gc(package_name="com.android.launcher3"))
        )
        # logger.info("Killing process 'com.android.launcher3': " + str(kill_process(package_name='com.android.launcher3')))
        # logger.info("Uninstalling 'com.android.launcher3': " + str(uninstall_app(package_name='com.android.launcher3')))
        # logger.info("All Permissions: " + str(android_util.get_all_permissions()))
        # permissions = android_util.get_all_permissions()
        # permissions_args = " ".join([perm.name for perm in permissions])
        # print(permissions_args)
        # logger.info("All Package Permissions: " + android_util.run_command("adb shell dumpsys package permission {permissions_args}", check_output=True, shell=True))
        logger.info("Package Flags: " + str(android_util.get_package_flags("com.android.settings")))
    except Exception as e:
        logger.error(f"Error occurred: {e}", e)
