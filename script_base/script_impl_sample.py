import argparse

from script_manager import ScriptManager, Command
from utils import get_current_timestamp, ensure_directory_exists
from log import logger


# --- 示例命令 1: GreetCommand ---
class GreetCommand(Command):
    """
    向指定的人打招呼。
    """
    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument("--name", type=str, default="World", help="要打招呼的人名。")
        parser.add_argument("-u", "--uppercase", action="store_true", help="将问候语转换为大写。")

    def execute(self, args: argparse.Namespace):
        greeting = f"Hello, {args.name}!"
        if args.uppercase:
            greeting = greeting.upper()
        logger.info(greeting)
        print(f"当前时间戳: {get_current_timestamp()}")

# --- 示例命令 2: FileOpCommand ---
class FileOpCommand(Command):
    """
    执行文件系统操作，例如创建目录。
    """
    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument("--path", type=str, required=True, help="要操作的路径。")
        parser.add_argument("--create-dir", action="store_true", help="如果不存在则创建指定的目录。")

    def execute(self, args: argparse.Namespace):
        if args.create_dir:
            ensure_directory_exists(args.path)
            logger.info(f"尝试创建目录: {args.path}")
        else:
            logger.info(f"对路径 '{args.path}' 执行其他文件操作。")
            # 在这里可以添加更多的文件操作逻辑，例如读写文件等
            print(f"文件操作在 {args.path} 上完成。")

if __name__ == "__main__":
    manager = ScriptManager(description="一个简单的命令行脚本管理器。")

    # 注册您的命令
    manager.register_command("greet", GreetCommand(), help_text="向某人打招呼。")
    manager.register_command("fileop", FileOpCommand(), help_text="执行文件系统操作。")

    manager.run()