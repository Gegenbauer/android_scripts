#!/usr/bin/env python

import argparse
import sys

class ScriptManager:
    def __init__(self, description="一个多功能的脚本管理工具。"):
        self.parser = argparse.ArgumentParser(
            description=description,
            formatter_class=argparse.RawTextHelpFormatter # 关键：使用 RawTextHelpFormatter 以保留文档字符串中的换行和格式
        )
        self.subparsers = self.parser.add_subparsers(
            dest="command",
            help="可用命令"
        )
        self.commands = {} # 存储命令实例

    def register_command(self, command_name: str, command_instance: 'Command', help_text: str = None):
        """
        注册一个新命令。

        Args:
            command_name (str): 用户在命令行中输入的命令名称。
            command_instance (Command): 命令的实例，必须继承自 Command 抽象基类。
            help_text (str, optional): 命令的简要帮助信息。如果未提供，将使用命令类的 __doc__ 的第一行。
        """
        if not isinstance(command_instance, Command):
            raise TypeError("命令实例必须继承自 'Command' 抽象基类。")

        # 使用命令的 __doc__ 作为完整描述，截取第一行作为简短帮助
        full_doc = command_instance.__doc__ if command_instance.__doc__ else ""
        short_help = help_text if help_text else full_doc.strip().split('\n')[0]

        parser_command = self.subparsers.add_parser(
            command_name,
            help=short_help, # 用于命令行概览的简短帮助
            description=full_doc # 用于特定命令帮助的完整描述
        )
        command_instance.add_arguments(parser_command)
        self.commands[command_name] = command_instance

    def run(self):
        """
        解析命令行参数并执行相应的命令。
        """
        args = self.parser.parse_args()

        if args.command in self.commands:
            command_instance = self.commands[args.command]
            try:
                command_instance.execute(args)
            except Exception as e:
                print(f"执行命令 '{args.command}' 时发生错误: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            if args.command: # 如果用户输入了未知命令
                print(f"未知命令: '{args.command}'\n", file=sys.stderr)
            # 默认情况下，ArgumentParser.print_help() 会输出所有子命令的简要信息
            # 如果需要更详细的汇总，可以手动遍历并打印
            print("可用命令及其详细描述：")
            for name, cmd_instance in self.commands.items():
                print(f"\n  {name}:")
                # 打印命令的完整文档字符串
                doc = cmd_instance.__doc__
                if doc:
                    # 为了排版，可以对文档字符串进行缩进处理
                    indented_doc = "\n".join(["    " + line for line in doc.strip().split('\n')])
                    print(indented_doc)
                else:
                    print("    (无详细描述)")
            print("\n有关特定命令的更多信息，请使用: ./your_script.py <command> --help")
            sys.exit(1)
            
from abc import ABC, abstractmethod

class Command(ABC):
    """
    所有命令的抽象基类。
    每个具体的命令都必须继承此基类。
    """
    @abstractmethod
    def add_arguments(self, parser: argparse.ArgumentParser):
        """
        向命令的子解析器添加命令行参数。

        Args:
            parser (argparse.ArgumentParser): 该命令的子解析器，用于定义命令特有的参数。
        """
        pass

    @abstractmethod
    def execute(self, args: argparse.Namespace):
        """
        执行命令的具体逻辑。

        Args:
            args (argparse.Namespace): 解析后的命令行参数对象，包含所有命令行输入。
        """
        pass
