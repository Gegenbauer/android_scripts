# ===== Base Command for ADB Operations =====
from android_util_impls.manager import android_util_manager
from script_base.log import logger
from script_base.script_manager import Command


class AdbCommand(Command):
    """Base class for all ADB device operation commands.

    Automatically adds --serial and --suppress-warnings arguments.
    Subclasses should override add_custom_arguments() and execute_on_device().
    """

    def add_arguments(self, parser):
        """Add common ADB arguments. Override add_custom_arguments() for command-specific args."""
        parser.add_argument(
            "--serial",
            "-s",
            type=str,
            help="Device serial number. If not specified, uses the first connected device.",
        )
        parser.add_argument(
            "--suppress-warnings",
            action="store_true",
            help="Suppress warning messages when multiple devices are connected.",
        )
        self.add_custom_arguments(parser)

    def add_custom_arguments(self, parser):
        """Override this method to add command-specific arguments."""
        pass

    def execute(self, args):
        """Execute the command with device selection handling."""
        # Get android_util with device selection
        android_util = self.get_android_util(args)
        if android_util is None:
            return

        # Execute the command-specific logic
        self.execute_on_device(args, android_util)

    def get_android_util(self, args):
        """Get android_util instance with proper device selection and warning handling."""
        device_serial = getattr(args, 'serial', None)
        suppress_warnings = getattr(args, 'suppress_warnings', False)

        # Create android_util with device selection
        default_android_util = android_util_manager.select()

        # Check if device is connected
        devices = default_android_util.get_connected_devices()
        if not devices or len(devices) == 0:
            logger.error("No connected devices detected")
            return None
        logger.debug(f"Connected devices: {devices}")
        # Handle multiple device warning
        if len(devices) > 1 and not device_serial and not suppress_warnings:
            device_ids = [d.split()[0] for d in devices]
            logger.warning(
                f"Multiple devices connected: {device_ids}. "
                f"Device not specified, using the first device: {device_ids[0]}. "
                f"Use --serial to specify a device or --suppress-warnings to hide this message."
            )
        if not device_serial:
            device_serial = devices[0].split()[0]
        return android_util_manager.select(device=device_serial)

    def execute_on_device(self, args, android_util):
        """Override this method to implement command-specific logic.

        Args:
            args: Parsed command-line arguments
            android_util: AndroidUtilBase instance with device already selected
        """
        raise NotImplementedError("Subclasses must implement execute_on_device()")
