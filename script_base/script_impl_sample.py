import argparse

from script_manager import ScriptManager, Command
from utils import get_current_timestamp, ensure_directory_exists
from log import logger


# --- Example Command 1: GreetCommand ---
class GreetCommand(Command):
    """
    Greet a specified person.
    """
    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument("--name", type=str, default="World", help="Name of the person to greet.")
        parser.add_argument("-u", "--uppercase", action="store_true", help="Convert the greeting to uppercase.")

    def execute(self, args: argparse.Namespace):
        greeting = f"Hello, {args.name}!"
        if args.uppercase:
            greeting = greeting.upper()
        logger.info(greeting)
        print(f"Current timestamp: {get_current_timestamp()}")

# --- Example Command 2: FileOpCommand ---
class FileOpCommand(Command):
    """
    Perform file system operations, such as creating directories.
    """
    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument("--path", type=str, required=True, help="Path to operate on.")
        parser.add_argument("--create-dir", action="store_true", help="Create the specified directory if it does not exist.")

    def execute(self, args: argparse.Namespace):
        if args.create_dir:
            ensure_directory_exists(args.path)
            logger.info(f"Attempting to create directory: {args.path}")
        else:
            logger.info(f"Performing other file operations on path '{args.path}'.")
            # You can add more file operation logic here, such as reading/writing files, etc.
            print(f"File operation completed on {args.path}.")

if __name__ == "__main__":
    manager = ScriptManager(description="A simple command-line script manager.")

    # Register your commands
    manager.register_command("greet", GreetCommand(), help_text="Greet someone.")
    manager.register_command("fileop", FileOpCommand(), help_text="Perform file system operations.")

    manager.run()