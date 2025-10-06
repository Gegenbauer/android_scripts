#!/usr/bin/env python

import argparse
import sys
from script_base.log import simple_logger as logger

class ScriptManager:
    def __init__(self, description="A multifunctional script management tool."):
        self.parser = argparse.ArgumentParser(
            description=description,
            formatter_class=argparse.RawTextHelpFormatter # Key: use RawTextHelpFormatter to preserve newlines and formatting in docstrings
        )
        self.subparsers = self.parser.add_subparsers(
            dest="command",
            help="Available commands"
        )
        self.commands = {} # Store command instances

    def register_command(self, command_name: str, command_instance: 'Command', help_text: str = None):
        """
        Register a new command.

        Args:
            command_name (str): The command name entered by the user on the command line.
            command_instance (Command): The command instance, must inherit from the Command abstract base class.
            help_text (str, optional): Brief help text for the command. If not provided, the first line of the command class's __doc__ will be used.
        """
        if not isinstance(command_instance, Command):
            raise TypeError("Command instance must inherit from the 'Command' abstract base class.")

        # Use the command's __doc__ as the full description, take the first line as short help
        full_doc = command_instance.__doc__ if command_instance.__doc__ else ""
        short_help = help_text if help_text else full_doc.strip().split('\n')[0]

        parser_command = self.subparsers.add_parser(
            command_name,
            help=short_help, # Short help for command line overview
            description=full_doc # Full description for specific command help
        )
        parser_command.add_argument("--debug", action="store_true", help="Enable debug logging for all commands.")
        command_instance.add_arguments(parser_command)
        self.commands[command_name] = command_instance

    def run(self):
        """
        Parse command-line arguments and execute the corresponding command.
        """
        args = self.parser.parse_args()

        if getattr(args, "debug", False):
            import logging
            from script_base.log import logger as default_logger
            logger.set_level(logging.DEBUG)
            default_logger.set_level(logging.DEBUG)

        if args.command in self.commands:
            command_instance = self.commands[args.command]
            try:
                command_instance.execute(args)
            except Exception as e:
                logger.error(f"Error occurred while executing command '{args.command}", e)
                sys.exit(1)
        else:
            if args.command: # If the user entered an unknown command
                logger.error(f"Unknown command: '{args.command}'\n")
            # By default, ArgumentParser.print_help() outputs a brief overview of all subcommands
            # For more detailed summaries, you can manually iterate and print
            logger.info("Available commands and their detailed descriptions:")
            for name, cmd_instance in self.commands.items():
                logger.info(f"\n  {name}:")
                # Print the full docstring of the command
                doc = cmd_instance.__doc__
                if doc:
                    # For formatting, you can indent the docstring
                    indented_doc = "\n".join(["    " + line for line in doc.strip().split('\n')])
                    logger.info(indented_doc)
                else:
                    logger.info("    (No detailed description)")
            logger.info("\nFor more information on a specific command, use: ./your_script.py <command> --help")
            sys.exit(1)
            
from abc import ABC, abstractmethod

class Command(ABC):
    """
    Abstract base class for all commands.
    Each specific command must inherit from this base class.
    """
    @abstractmethod
    def add_arguments(self, parser: argparse.ArgumentParser):
        """
        Add command-line arguments to the command's subparser.

        Args:
            parser (argparse.ArgumentParser): The subparser for the command, used to define command-specific arguments.
        """
        pass

    @abstractmethod
    def execute(self, args: argparse.Namespace):
        """
        Execute the specific logic of the command.

        Args:
            args (argparse.Namespace): The parsed command-line arguments object, containing all user inputs.
        """
        pass