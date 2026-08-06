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
    try:
        output = run_command(
            f"{adb_command} shell \"cat /data/system/packages.xml|grep {package_name}\"",
            check_output=True,
            shell=True,
        )
    except PermissionError:
        logger.debug(
            f"Could not read /data/system/packages.xml (root required) to verify "
            f"the platform signature of {package_name}."
        )
        return False
    # <package name="com.example.demogroup" publicFlags="541638470" privateFlags="-1945104384" 
    # find privateFlags
    private_flags = re.search(r'privateFlags="([^"]+)"', output)
    # public static final int PRIVATE_FLAG_SIGNED_WITH_PLATFORM_KEY = 1 << 20;
    if private_flags and int(private_flags.group(1)) & (1 << 20):
        return True
    return False


def get_permission_definition(adb_command: str, permission: str) -> dict:
    """
    Check whether the given permission is defined on the device and return its definition info.

    The definition is read from 'dumpsys package permissions'.

    Args:
        adb_command (str): The adb command to use.
        permission (str): The permission name to check, e.g. 'android.permission.CAMERA'.

    Returns:
        dict: {'defined': bool, 'source_package': str, 'protection_level': str}
            source_package is the package that declares the permission and
            protection_level is the permission protection level (e.g. 'signature').
    """
    result = {"defined": False, "source_package": "", "protection_level": ""}
    if not adb_command:
        return result

    from script_base.utils import run_command
    from script_base.log import logger
    import re

    try:
        output = run_command(
            f"{adb_command} shell dumpsys package permissions",
            check_output=True,
            shell=True,
        )
    except Exception as e:
        logger.error(f"Error occurred while dumping package permissions: {e}", exc=e)
        raise

    # 'dumpsys package permissions' contains entries like:
    #   Permission [android.permission.CAMERA] (3efb9f7):
    #     sourcePackage=android
    #     uid=1000 gids=null type=0 prot=signature|privileged
    # AppOp permissions appear as:
    #   AppOp Permission android.permission.WRITE_SETTINGS:
    appop_permission_pattern = re.compile(r"AppOp Permission (.+)")
    current_permission = None
    for line in output.splitlines():
        stripped = line.strip()
        permission_match = re.match(r"Permission \[(.+?)\]", stripped)
        if permission_match:
            current_permission = permission_match.group(1)
            if current_permission == permission:
                result["defined"] = True
            continue
        appop_match = appop_permission_pattern.match(stripped)
        if appop_match:
            current_permission = appop_match.group(1).rstrip(":")
            if current_permission == permission:
                result["defined"] = True
            continue
        if current_permission != permission:
            continue
        if stripped.startswith("sourcePackage="):
            result["source_package"] = stripped.split("sourcePackage=", 1)[1].strip()
        elif "prot=" in stripped:
            result["protection_level"] = stripped.split("prot=", 1)[1].strip()
    return result


def get_permission_grant_status(
    adb_command: str, package_name: str, permission: str
) -> dict:
    """
    Check how the given permission is requested and granted for the given package.

    The status is read from 'dumpsys package <package_name>'.

    Args:
        adb_command (str): The adb command to use.
        package_name (str): The package name of the application.
        permission (str): The permission name to check, e.g. 'android.permission.CAMERA'.

    Returns:
        dict: {'requested': bool, 'granted': bool or None, 'grant_flags': list}
            granted is None when the package has no grant record for the permission.
    """
    result = {"requested": False, "granted": None, "grant_flags": []}
    if not adb_command:
        return result

    from script_base.utils import run_command
    from script_base.log import logger

    try:
        output = run_command(
            f"{adb_command} shell dumpsys package {package_name}",
            check_output=True,
            shell=True,
        )
    except Exception as e:
        logger.error(
            f"Error occurred while dumping package {package_name}: {e}", exc=e
        )
        raise

    # 'dumpsys package <pkg>' contains sections like:
    #   requested permissions:
    #     android.permission.CAMERA
    #   install permissions:
    #     android.permission.CAMERA: granted=true, flags=[ USER_SET ]
    #   User 0: ... runtime permissions:
    #     android.permission.CAMERA: granted=true, flags=[
    #       USER_SET
    #     ]
    in_requested_section = False
    lines = output.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "requested permissions:":
            in_requested_section = True
            continue
        if in_requested_section:
            if stripped == permission:
                result["requested"] = True
            elif ":" in stripped:
                in_requested_section = False
        if stripped.startswith(permission + ":"):
            rest = stripped[len(permission) + 1:].strip()
            if "granted=" in rest:
                granted_value = rest.split("granted=", 1)[1].split(",", 1)[0].strip()
                result["granted"] = granted_value == "true"
            if "flags=" in rest:
                result["grant_flags"] = _parse_grant_flags(
                    lines, i, rest.split("flags=", 1)[1]
                )
    return result


def _parse_grant_flags(lines: list, start_index: int, flags_text: str) -> list:
    """
    Parse the flags= list of a permission grant record, which may span multiple lines.

    Args:
        lines (list): All output lines of the dumpsys command.
        start_index (int): Index of the grant record line in 'lines'.
        flags_text (str): The text right after 'flags=' on the grant record line.

    Returns:
        list: The parsed flag names.
    """
    flags = []
    content = flags_text.strip()
    if content == "[]":
        return flags
    content = content.lstrip("[")
    parts = [content]
    if not content.endswith("]"):
        for j in range(start_index + 1, len(lines)):
            parts.append(lines[j].strip())
            if parts[-1].endswith("]"):
                break
    joined = " ".join(parts).rstrip("]")
    import re

    for token in re.split(r"[,;\s|]+", joined):
        if token:
            flags.append(token)
    return flags


def check_permission(
    adb_command: str, package_name: str, permission: str, is_root: bool = False
) -> dict:
    """
    Check the overall status of a permission for a package.

    Combines the permission definition, the grant status for the package, the
    package flags, and the platform-signature status.

    Args:
        adb_command (str): The adb command to use.
        package_name (str): The package name of the application.
        permission (str): The permission name to check, e.g. 'android.permission.CAMERA'.
        is_root (bool): Whether adb is running as root. Verifying the platform
            signature requires root access.

    Returns:
        dict: All available permission and package information. The 'platform_signed'
            field is None when it could not be verified (root unavailable).
    """
    result = {
        "package_name": package_name,
        "permission": permission,
        "platform_check_requires_root": False,
    }

    result.update(get_permission_definition(adb_command, permission))
    result.update(get_permission_grant_status(adb_command, package_name, permission))

    flags = get_flags_for_package(adb_command, package_name)
    result["flags"] = flags.get("flags", [])
    result["private_flags"] = flags.get("privateFlags", [])
    result["pkg_flags"] = flags.get("pkgFlags", [])
    result["is_system_app"] = "SYSTEM" in result["pkg_flags"]
    result["is_privileged"] = "PRIVILEGED" in result["private_flags"]

    platform_signed = None
    if "PRIVATE_FLAG_SIGNED_WITH_PLATFORM_KEY" in result["private_flags"]:
        platform_signed = True
    elif is_root:
        try:
            platform_signed = is_platform_app(adb_command, package_name)
        except PermissionError:
            platform_signed = None
    else:
        result["platform_check_requires_root"] = True
    result["platform_signed"] = platform_signed
    return result


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
