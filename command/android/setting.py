from command.android.base import AdbCommand
from script_base.log import logger
from script_base.utils import (
    run_command,
)
from set_language import set_android_language


class SetTimeCommand(AdbCommand):
    """
    Set the time on an Android device.
    """

    def add_custom_arguments(self, parser):
        parser.add_argument(
            "time", help="Target time (YYYY-MM-DD-HH-MM-SS) or 'auto' to sync with network time"
        )

    def execute_on_device(self, args, android_util):
        device_id = android_util.get_connected_device_id()
        if args.time == "auto":
            # Automatically sync network time
            run_command(f"adb -s {device_id} shell settings put global auto_time 1", shell=True)
            run_command(
                f"adb -s {device_id} shell settings put global auto_time_zone 1", shell=True
            )  # Also enable auto timezone
            logger.debug("Auto time and timezone enabled")
            return

        # Validate time format
        if not android_util.is_valid_time_format(args.time):
            logger.error("Invalid time format, should be YYYY-MM-DD-HH-MM-SS or 'auto'")
            return

        # Get IANA timezone name from the device
        device_tz_name = android_util.get_device_timezone_name()
        if not device_tz_name:
            return
        # Let the device calculate the UTC timestamp itself
        milliseconds_utc = android_util.get_utc_milliseconds_from_device(args.time, device_tz_name)
        if milliseconds_utc is None:
            return

        run_command(
            f"adb -s {device_id} shell settings put global auto_time 0", shell=True
        )  # Disable auto time
        run_command(f"adb -s {device_id} shell cmd alarm set-time {milliseconds_utc}", shell=True)
        logger.info(
            f"Time set on device to display as {args.time} (UTC milliseconds sent: {milliseconds_utc})."
        )
        logger.info(
            "Note: auto_time_zone has been disabled to maintain the manually set time."
        )


class SetUiModeCommand(AdbCommand):
    """
    Switch the day/night mode of the Android device.
    """

    def add_custom_arguments(self, parser):
        parser.add_argument(
            "mode",
            choices=["day", "night", "auto"],
            help="The UI mode to set: 'day', 'night', or 'auto'.",
        )

    def execute_on_device(self, args, android_util):
        # Map user input to adb command arguments
        mode_map = {"day": "no", "night": "yes", "auto": "auto"}
        adb_mode_arg = mode_map[args.mode]

        try:
            logger.info(
                f"Setting UI mode to: {args.mode} (adb: 'cmd uimode night {adb_mode_arg}')"
            )
            run_command(["adb", "shell", "cmd", "uimode", "night", adb_mode_arg])
            logger.info("UI mode set successfully.")
        except Exception as e:
            logger.error(f"Failed to set UI mode", exc=e)


class SetLanguageCommand(AdbCommand):
    """
    Set the system language on an Android device using Frida.
    """
    def add_custom_arguments(self, parser):
        parser.add_argument("--language", type=str, required=True, help="Language code, e.g. 'en', 'zh'")
        parser.add_argument("--country", type=str, default="", help="Country/region code, e.g. 'US', 'CN'")
        parser.add_argument("--package", type=str, default="com.android.settings", help="Target process package name (default: com.android.settings)")

    def execute_on_device(self, args, android_util):
        set_android_language(
            language=args.language,
            country=args.country,
            package_name=args.package,
            device_id=android_util.get_connected_device_id()
        )