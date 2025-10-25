import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")

from script_base.log import logger
from script_base.platforms import current_platform

def get_android_sdk_path() -> str:
    """
    Get the path of the Android SDK.

    Returns:
        str: The path of the Android SDK, or an empty string if not set.
    """
    sdk_path = os.environ.get("android_sdk_path", "")
    if not sdk_path:
        logger.error(
            "Please set the android_sdk_path environment variable to point to the Android SDK installation directory.",
            Exception("android_sdk_path not set")
        )
    if not os.path.exists(sdk_path):
        logger.error(
            f"The specified Android SDK path '{sdk_path}' does not exist. Please check if the path is correct.",
            Exception("android_sdk_path does not exist")
        )
        return ""
    return sdk_path

def get_android_ndk_path() -> str:
    """
    Get the path of the Android NDK.
    Returns:
        str: The path of the Android NDK, or an empty string if not set.
    """
    sdk_path = get_android_sdk_path()
    if not sdk_path:
        return ""
    # NDK path is sdk_path + '/ndk'
    ndk_path = os.path.join(sdk_path, "ndk")
    if not os.path.exists(ndk_path):
        logger.error(
            "Please make sure the Android NDK is installed and android_sdk_path points to the correct directory.",
            Exception("NDK not found")
        )
        return ""
    return ndk_path

def get_android_platform_tools_path() -> str:
    """
    Get the path of the Android platform tools.
    Returns:
        str: The path of the Android platform tools, or an empty string if not set.
    """
    sdk_path = get_android_sdk_path()
    if not sdk_path:
        return ""
    # Platform tools path is sdk_path + '/platform-tools'
    platform_tools_path = os.path.join(sdk_path, "platform-tools")
    if not os.path.exists(platform_tools_path):
        logger.error(
            "Please make sure the Android SDK is installed and android_sdk_path points to the correct directory.",
            Exception("Platform tools not found")
        )
        return ""
    return platform_tools_path

def get_android_build_tools_path(version) -> str:
    """
    Get the path of the Android build tools.
    Args:
        version (str): The version number of the build tools, e.g. '30'.
    Returns:
        str: The path of the Android build tools, or an empty string if not set.
    """
    sdk_path = get_android_sdk_path()
    if not sdk_path:
        return ""
    build_tools_path = os.path.join(sdk_path, "build-tools")
    # Traverse the build-tools directory to find the specified version. If there is 30.0.3 and the request is 30, consider it a match.
    if not os.path.exists(build_tools_path):
        logger.error(
            "Please make sure the Android SDK is installed and android_sdk_path points to the correct directory."
        )
        return ""
    for item in os.listdir(build_tools_path):
        if item.startswith(version):
            build_tools_path = os.path.join(build_tools_path, item)
            if os.path.exists(build_tools_path):
                return build_tools_path
    logger.error(
        f"Could not find the path for Android build tools version {version}. Please check if this version is installed.",
        Exception("Build tools not found")
    )
    return ""

def get_adb_path(warning: bool=False) -> str:
    """
    Get the path of the adb tool.
    Returns:
        str: The path of the adb tool, or an empty string if not set.
    """
    adb_file_name = current_platform.get_adb_file_name()
    adb_path = (
        os.path.join(get_android_platform_tools_path(), adb_file_name)
        if get_android_platform_tools_path()
        else ""
    )
    if not adb_path or not os.path.exists(adb_path):
        if warning:
            logger.error(
                "Cannot find adb tool. " +
                "Please make sure the Android SDK is installed and android_sdk_path points to the correct directory.",
                Exception("adb not found")
            )
    return adb_path