# 指导 GitHub Copilot 的提示词（为本仓库量身定制）

目标：当我在 `python_scripts/` 下编写新脚本时，请严格遵循以下约定，统一复用 `script_base` 的基类与工具函数，整体风格参考 `git.py`。

---

你是 GitHub Copilot。请按照下述要求生成脚本：

- 脚本定位
  - 所有新脚本均放在 `python_scripts/` 目录下。
  - 入口均为 `if __name__ == "__main__":`，使用 `ScriptManager` 注册并运行命令。

- 基类与工具（必须复用）
  - 从 `script_base` 导入：
    - `from script_base.script_manager import ScriptManager, Command`
    - `from script_base.utils import run_command, ensure_directory_exists, log_message`
  - 不自行实现命令分发、日志与目录创建，统一复用上面工具。

- 命令风格
  - 每个子命令派生自 `Command`，实现：
    - `add_arguments(self, parser: argparse.ArgumentParser)` 定义 CLI 参数
    - `execute(self, args: argparse.Namespace)` 实现业务逻辑
  - 使用清晰的中文 docstring 说明命令的用途、参数与行为；`ScriptManager` 会用它作为帮助信息。
  - 注册命令示例：
    - `manager.register_command("your-command", YourCommand(), help_text="一句话简介")`

- CLI 设计规范
  - 长参数使用 `--kebab-case`，可添加短参数别名（如 `-p`）。
  - 互斥选项使用 `parser.add_mutually_exclusive_group()`。
  - 默认值明确，帮助文本完整，必要参数 `required=True`。

- 统一工具调用
  - Shell/外部命令：优先使用 `run_command(["cmd", "arg"], check_output=...)`。
    - 需要仅执行并忽略输出用 `check_output=False`。
    - 出错时交由工具函数抛出并打印 stderr。
  - 目录：使用 `ensure_directory_exists(path)` 保证存在。
  - 日志：使用 `log_message("消息", level="INFO"|"ERROR"|...)`。

- Android 设备相关操作（示例约定）
  - ADB 拉取：`run_command(["adb", "pull", remote, local], check_output=False)`。
  - 打开文件管理器：
    - macOS: `open path`；Windows: `explorer path`；Linux: `xdg-open path`（用 `run_command` 调用）。
  - 打开 VSCode：`run_command(["code", "-g", f"{file}:{line}"])`，行号可选。

- 缓存/输出目录约定
  - 本地缓存根目录默认优先读取环境变量 `cache_files_dir`，否则为当前目录 `.`。
  - 建议统一组织为：`<cache_root>/<feature_name>/<sanitized_key>_<timestamp>/...`。
  - `timestamp` 使用 `datetime.now().strftime("%Y%m%d_%H%M%S")`。

- 异常与健壮性
  - 对关键外部命令加 try/except；报错打印到 `stderr` 并尽量给出下一步提示。
  - 文件编码读取时优先 `encoding="utf-8"`，并设置 `errors="replace"`，避免因非法字符崩溃。

- 骨架模板（生成新脚本时参考）
  - 顶部添加 shebang：`#!/usr/bin/env python3`。
  - 典型结构：

```
#!/usr/bin/env python3
import argparse
import os
import sys
from datetime import datetime
from script_base.script_manager import ScriptManager, Command
from script_base.utils import run_command, ensure_directory_exists, log_message

class YourCommand(Command):
    """命令用途的一句话说明。

    更详细的多行说明：
    - 参数解释
    - 行为说明
    """
    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument("--path", "-p", type=str, required=True, help="示例参数")
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--flag-a", action="store_true", help="选项A")
        group.add_argument("--flag-b", action="store_true", help="选项B")

    def execute(self, args: argparse.Namespace):
        ensure_directory_exists("/tmp")
        log_message(f"处理路径: {args.path}")
        try:
            run_command(["echo", args.path], check_output=False)
        except Exception as e:
            print(f"命令执行失败: {e}", file=sys.stderr)
            return
        print("完成")

if __name__ == "__main__":
    manager = ScriptManager(description="脚本集合：统一基于 script_base 的命令工具。")
    manager.register_command("your-command", YourCommand(), help_text="一句话简介")
    manager.run()
```

- 参考文件（务必先阅读，再按风格实现）
  - `python_scripts/script_base/script_manager.py`
  - `python_scripts/script_base/utils.py`
  - `python_scripts/script_base/script_impl_sample.py`
  - `python_scripts/git.py`（风格、结构、错误处理）

- 提交前自检清单
  - [ ] 使用了 ScriptManager/Command 体系
  - [ ] 复用了 utils 的 `run_command/ensure_directory_exists/log_message`
  - [ ] 参数命名、帮助文案、互斥组符合规范
  - [ ] 关键外部命令已做异常处理
  - [ ] 输出对用户友好（中文提示），且尽量简洁
