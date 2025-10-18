def get_flags_for_package(adb_command: str, package_name: str) -> dict:
    """
    Get the flags of the specified package.
    flags, privateFlags and pkgFlags

    Args:
        adb_command (str): The adb command to use.
        package_name (str): The package name of the application.

    Returns:
        dict: A dictionary containing the flags of the package.
        format: {flags: [PackageFlag...], privateFlags: [PackageFlag...], pkgFlags: [PackageFlag...]}
    """
    if not adb_command:
        return {}

    import subprocess
    from script_base.utils import run_command
    from script_base.log import logger
    try:

        command = f"{adb_command} shell dumpsys package {package_name}"
        output = run_command(command, shell=True)
        flags = {}
        # Example output lines:
        #     flags=[ SYSTEM DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
        #   privateFlags=[ PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE_VIA_SDK_VERSION ALLOW_AUDIO_PLAYBACK_CAPTURE PRIVILEGED PRIVATE_FLAG_ALLOW_NATIVE_HEAP_POINTER_TAGGING ]
        #   pkgFlags=[ SYSTEM DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
        #   User 0: ceDataInode=131076 installed=true hidden=false suspended=false distractionFlags=0 stopped=false notLaunched=false enabled=0 instant=false virtual=false
        #   android.permission.POST_NOTIFICATIONS: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("flags="):
                flag_str = line[len("flags=") :].strip().strip("[]")
                flags["flags"] = flag_str.split() if flag_str else []
            elif line.startswith("privateFlags="):
                flag_str = line[len("privateFlags=") :].strip().strip("[]")
                flags["privateFlags"] = flag_str.split() if flag_str else []
            elif line.startswith("pkgFlags="):
                flag_str = line[len("pkgFlags=") :].strip().strip("[]")
                flags["pkgFlags"] = flag_str.split() if flag_str else []
        # cause sometimes PRIVATE_FLAG_SIGNED_WITH_PLATFORM_KEY is not dumped in privateFlags
        # we need to check manually
        is_platform = is_platform_app(adb_command, package_name)
        # add PRIVATE_FLAG_SIGNED_WITH_PLATFORM_KEY to privateFlags if is_platform is True
        if is_platform:
            flags["privateFlags"].append("PRIVATE_FLAG_SIGNED_WITH_PLATFORM_KEY")
        return flags
    except subprocess.CalledProcessError as e:
        logger.error(
            f"Error occurred while getting flags for package {package_name}: {e}", e
        )
        raise


def is_platform_app(adb_command: str, package_name: str) -> bool:
    """
    Check if the specified package is a platform app.

    Args:
        adb_command (str): The adb command to use.
        package_name (str): The package name of the application.

    Returns:
        bool: True if the package is a platform app, False otherwise.
    """
    from script_base.log import logger
    from script_base.utils import run_command
    import re
    binary_xml_enabled = (
        run_command(
            f"{adb_command} shell getprop persist.sys.binary_xml",
            check_output=True,
            shell=True,
        )
        .strip()
        .lower()
        != "false"
    )
    if binary_xml_enabled:
        logger.error(
            "Note: The device has binary XML parsing enabled (persist.sys.binary_xml=true). packages.xml may be in binary XML format."
        )
        return False
    output = run_command(
        f"{adb_command} shell \"cat /data/system/packages.xml|grep {package_name}\"", check_output=True, shell=True
    )
    # <package name="com.example.demogroup" publicFlags="541638470" privateFlags="-1945104384" 
    # find privateFlags
    private_flags = re.search(r'privateFlags="([^"]+)"', output)
    # public static final int PRIVATE_FLAG_SIGNED_WITH_PLATFORM_KEY = 1 << 20;
    if private_flags and int(private_flags.group(1)) & (1 << 20):
        return True
    return False


class PackageFlag:
    FLAG_SYSTEM = "SYSTEM"
    FLAG_UPDATED_SYSTEM_APP = "UPDATED_SYSTEM_APP"
    FLAG_EXTERNAL_STORAGE = "EXTERNAL_STORAGE"
    FLAG_STOPPED = "STOPPED"
    FLAG_DEBUGGABLE = "DEBUGGABLE"
    FLAG_PERSISTENT = "PERSISTENT"
    FLAG_FORWARD_LOCK = "FORWARD_LOCK"
    FLAG_PRIVILEGED = "PRIVILEGED"
    FLAG_INSTANT = "INSTANT"
    FLAG_ISOLATED_SPLIT_LOADING = "ISOLATED_SPLIT_LOADING"
    FLAG_VIRTUAL_PRELOAD = "VIRTUAL_PRELOAD"
    FLAG_WELL_KNOWN = "WELL_KNOWN"
    FLAG_EPHEMERAL = "EPHEMERAL"
    FLAG_LAUNCHER = "LAUNCHER"
    FLAG_ALLOW_BACKUP = "ALLOW_BACKUP"
    FLAG_RESIZEABLE_ACTIVITIES = "RESIZEABLE_ACTIVITIES"
    FLAG_SUPPORTS_PICTURE_IN_PICTURE = "SUPPORTS_PICTURE_IN_PICTURE"
    FLAG_VM_SAFE_MODE = "VM_SAFE_MODE"
    FLAG_CANT_SAVE_STATE = "CANT_SAVE_STATE"
    FLAG_ALLOW_CLEAR_USER_DATA = "ALLOW_CLEAR_USER_DATA"
    FLAG_INSTALLED = "INSTALLED"
    FLAG_HIDDEN = "HIDDEN"
    FLAG_SUSPENDED = "SUSPENDED"
    FLAG_STOPPED_USERALLY = "STOPPED_USERALLY"
    FLAG_PRIVACY_GUARD_ENABLED = "PRIVACY_GUARD_ENABLED"
    FLAG_PRIVACY_GUARD_FIXED = "PRIVACY_GUARD_FIXED"
    FLAG_RESTORE_ANY_VERSION = "RESTORE_ANY_VERSION"
    FLAG_FULL_BACKUP_ONLY = "FULL_BACKUP_ONLY"
    FLAG_KEYSET_ALIAS = "KEYSET_ALIAS"
    FLAG_IS_GAME = "IS_GAME"
    FLAG_HAS_CODE = "HAS_CODE"
