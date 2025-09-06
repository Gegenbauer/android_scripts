#!/usr/bin/env python3
import os
import subprocess
import argparse
import sys
from script_base.script_manager import ScriptManager, Command
from script_base.utils import run_command, ensure_directory_exists

# 提供 git/repo 相关命令的封装

# 1. 获取当前目录所属的 git 仓库的根目录路径
# 2. 获取当前目录所属的 git 仓库的远程地址，fetch 和 push 的地址
# 3. 获取当前目录所属的 git 仓库配置的用户名和邮箱
# 4. 暂存当前目录下的所有修改，拉取远程仓库的最新代码，并 rebase
# 5. 获取当前目录所属 repo 的 manifest 文件的路径
# 6. 获取当前目录所属 repo 的 根目录路径
# 7. 获取当前目录所属 repo 的 manifest 文件的远程地址
# 8. 遍历当前目录所属 repo 的所有子模块，切换到指定分支，并对每个子模块执行 # 4
# 9. 生成 ssh 公钥和私钥，并将公钥内容输出到标准输出
# 10. 设置 git 用户名和邮箱。
# 11. 设置 git 远程仓库 push 和 fetch 地址。


def find_git_root(path: str = None) -> str:
    """
    获取当前目录或指定目录所属的 Git 仓库的根目录路径。
    """
    path = path if path else os.getcwd()
    try:
        return run_command(["git", "rev-parse", "--show-toplevel"], cwd=path)
    except Exception:
        raise Exception(f"'{path}' 不在 Git 仓库中。")


def find_repo_root(path: str = None) -> str:
    """
    获取当前目录或指定目录所属的 Repo 仓库的根目录路径。
    Repo 仓库的根目录通常包含一个 .repo 目录。
    """
    current_path = os.path.abspath(path if path else os.getcwd())
    while True:
        if os.path.isdir(os.path.join(current_path, ".repo")):
            return current_path
        parent_path = os.path.dirname(current_path)
        if parent_path == current_path:  # 达到文件系统根目录
            raise Exception(f"'{path if path else os.getcwd()}' 不在 Repo 仓库中。")
        current_path = parent_path


# --- 命令实现 ---


class GitRootCommand(Command):
    """获取当前目录所属 Git 仓库的根目录路径。"""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="指定要查找的起始路径，默认为当前目录。",
        )

    def execute(self, args: argparse.Namespace):
        try:
            root_path = find_git_root(args.path)
            print(f"{root_path}")
        except Exception as e:
            print(f"错误: {e}", file=sys.stderr)


class GitRemoteCommand(Command):
    """
    获取当前目录所属 Git 仓库的远程地址（fetch 和 push）。
    此命令会解析 `git remote -v` 的输出，以获取更可靠的远程 URL。
    默认尝试获取 'origin' 远程的地址；如果没有 'origin'，则使用第一个找到的远程。
    """

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="指定 Git 仓库路径，默认为当前目录。",
        )
        parser.add_argument(
            "--remote-name",
            type=str,
            default="origin",
            help="指定要获取地址的远程仓库名称，默认为 'origin'。",
        )

    def execute(self, args: argparse.Namespace):
        try:
            git_root = find_git_root(args.path)
            print(f"尝试在 Git 仓库 '{git_root}' 获取远程地址...")

            # 运行 git remote -v
            remote_output = run_command(["git", "remote", "-v"], cwd=git_root)

            fetch_url = None
            push_url = None
            found_remote_name = None

            # 解析输出
            for line in remote_output.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3:
                    remote_name = parts[0]
                    url = parts[1]
                    op_type = parts[2].strip("()")

                    # 如果找到了指定的远程名称，或者这是我们找到的第一个远程（当没有指定特定名称时）
                    if (args.remote_name and remote_name == args.remote_name) or (
                        not found_remote_name
                    ):
                        if op_type == "fetch":
                            fetch_url = url
                        elif op_type == "push":
                            push_url = url
                        found_remote_name = remote_name  # 记录当前处理的远程名称

                        # 如果我们已经找到了fetch和push的URL，并且这是我们正在查找的远程，就可以停止了
                        if (
                            fetch_url
                            and push_url
                            and found_remote_name == args.remote_name
                        ):
                            break
                    # 如果找到了 fetch 但没找到 push (或反之)，并且这是我们正在查找的远程，则继续查找同名远程的另一个操作
                    elif found_remote_name == remote_name and (
                        not fetch_url or not push_url
                    ):
                        if op_type == "fetch":
                            fetch_url = url
                        elif op_type == "push":
                            push_url = url

            if fetch_url:
                print(f"Git fetch 地址 ({found_remote_name}): {fetch_url}")
            else:
                print(
                    f"未找到远程 '{args.remote_name}' 的 fetch 地址。", file=sys.stderr
                )

            if push_url:
                print(f"Git push 地址 ({found_remote_name}): {push_url}")
            else:
                print(
                    f"Git push 地址 ({found_remote_name}): {fetch_url if fetch_url else '未找到' } (通常与 fetch 相同)",
                    file=sys.stderr,
                )

        except Exception as e:
            print(f"错误: {e}", file=sys.stderr)


class GitConfigCommand(Command):
    """获取当前目录所属 Git 仓库配置的用户名和邮箱。"""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="指定 Git 仓库路径，默认为当前目录。",
        )

    def execute(self, args: argparse.Namespace):
        try:
            git_root = find_git_root(args.path)
            user_name = run_command(
                ["git", "config", "--get", "user.name"], cwd=git_root
            )
            user_email = run_command(
                ["git", "config", "--get", "user.email"], cwd=git_root
            )
            print(f"Git 用户名: {user_name}")
            print(f"Git 邮箱: {user_email}")
        except Exception as e:
            print(f"错误: {e}", file=sys.stderr)


class GitSyncCommand(Command):
    """暂存所有修改，拉取远程最新代码并 rebase。"""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="指定 Git 仓库路径，默认为当前目录。",
        )

    def execute(self, args: argparse.Namespace):
        try:
            git_root = find_git_root(args.path)
            print(f"在 '{git_root}' 执行 Git 同步操作...")
            run_command(
                ["git", "stash", "save", "Auto-stashed by script"],
                cwd=git_root,
                check_output=False,
            )
            print("已暂存当前修改。")
            run_command(["git", "pull", "--rebase"], cwd=git_root, check_output=False)
            print("已拉取最新代码并 rebase。")
            try:
                run_command(["git", "stash", "pop"], cwd=git_root, check_output=False)
                print("已恢复暂存的修改。")
            except subprocess.CalledProcessError as e:
                if "No stash entries found" in e.stderr:
                    print("没有可恢复的暂存修改。")
                else:
                    raise
            print("Git 同步完成。")
        except Exception as e:
            print(f"错误: {e}", file=sys.stderr)


class RepoManifestCommand(Command):
    """获取当前目录所属 Repo 仓库的 manifest 文件的路径。"""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="指定 Repo 仓库路径，默认为当前目录。",
        )

    def execute(self, args: argparse.Namespace):
        try:
            repo_root = find_repo_root(args.path)
            manifest_path = os.path.join(repo_root, ".repo", "manifest.xml")
            if os.path.exists(manifest_path):
                print(f"Repo manifest 文件路径: {manifest_path}")
            else:
                print(f"在 '{repo_root}' 找不到 manifest.xml。", file=sys.stderr)
        except Exception as e:
            print(f"错误: {e}", file=sys.stderr)


class RepoRootCommand(Command):
    """获取当前目录所属 Repo 仓库的根目录路径。"""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="指定 Repo 仓库路径，默认为当前目录。",
        )

    def execute(self, args: argparse.Namespace):
        try:
            root_path = find_repo_root(args.path)
            print(f"{root_path}")
        except Exception as e:
            print(f"错误: {e}", file=sys.stderr)


class RepoManifestRemoteCommand(Command):
    """获取当前目录所属 Repo 仓库的 manifest 文件的远程地址。"""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="指定 Repo 仓库路径，默认为当前目录。",
        )

    def execute(self, args: argparse.Namespace):
        try:
            repo_root = find_repo_root(args.path)
            # Repo manifest 的远程地址通常在 .repo/manifests/.git/config 中
            manifest_git_config = os.path.join(
                repo_root, ".repo", "manifests", ".git", "config"
            )
            if os.path.exists(manifest_git_config):
                # 读取 .git/config 文件来获取远程URL
                # 这是一个简化的方法，更健壮的方式是使用 git 命令
                manifest_remote_url = run_command(
                    [
                        "git",
                        "config",
                        "--file",
                        manifest_git_config,
                        "--get",
                        "remote.origin.url",
                    ]
                )
                print(f"Repo manifest 远程地址: {manifest_remote_url}")
            else:
                print(
                    f"在 '{repo_root}' 找不到 manifest 的 Git 配置。", file=sys.stderr
                )
        except Exception as e:
            print(f"错误: {e}", file=sys.stderr)


class RepoSyncAllCommand(Command):
    """
    遍历当前目录所属 Repo 的所有子模块。
    如果指定了分支，将尝试切换到该分支（检查本地和远程）。
    随后对每个子模块执行 `git pull --rebase --autostash`。
    不会在本地自动创建新分支。
    """

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="指定 Repo 仓库路径，默认为当前目录。",
        )
        parser.add_argument(
            "--branch",
            type=str,
            help="可选。要切换到的目标分支名称。如果未指定，将使用每个子模块的当前分支。",
        )
        parser.add_argument(
            "--remote",
            type=str,
            default="origin",
            help="可选。指定远程仓库名称，默认为 'origin'。",
        )

    def execute(self, args: argparse.Namespace):
        try:
            repo_root = find_repo_root(args.path)
            
            target_branch_msg = f"到分支 '{args.branch}'" if args.branch else "在当前分支"
            print(f"在 Repo 仓库 '{repo_root}' 中执行全量同步操作 {target_branch_msg}...")

            # 获取所有子模块的路径
            project_paths_str = run_command(
                ["repo", "forall", "-c", "pwd"], cwd=repo_root
            )
            project_paths = project_paths_str.splitlines()

            for project_path in project_paths:
                print(f"\n--- 处理子模块: {project_path} ---")
                try:
                    # 如果指定了目标分支
                    if args.branch:
                        print(f"尝试切换子模块 '{os.path.basename(project_path)}' 到分支 '{args.branch}'...")
                        
                        local_branches = run_command(["git", "branch", "--list", args.branch], cwd=project_path)
                        local_branch_exists = bool(local_branches.strip())

                        if local_branch_exists:
                            print(f"本地分支 '{args.branch}' 存在，直接切换。")
                            run_command(["git", "checkout", args.branch], cwd=project_path, check_output=False)
                        else:
                            print(f"本地没有分支 '{args.branch}'，检查远程 '{args.remote}' 是否存在...")
                            run_command(["git", "remote", "update", args.remote], cwd=project_path, check_output=False)
                            
                            remote_branch_exists = False
                            try:
                                # 检查远程分支是否存在，例如通过 ls-remote
                                run_command(["git", "ls-remote", "--heads", args.remote, args.branch], cwd=project_path)
                                remote_branch_exists = True
                            except subprocess.CalledProcessError:
                                remote_branch_exists = False
                            
                            if remote_branch_exists:
                                print(f"远程分支 '{args.remote}/{args.branch}' 存在，创建本地跟踪分支并切换。")
                                run_command(["git", "checkout", "--track", f"{args.remote}/{args.branch}"], cwd=project_path, check_output=False)
                            else:
                                raise Exception(f"本地和远程均不存在分支 '{args.branch}'。请手动创建或检查分支名。")
                    else:
                        current_branch = run_command(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=project_path)
                        print(f"未指定分支，使用当前分支 '{current_branch}' 进行操作。")

                    # --- 优化后的 Git 同步操作 ---
                    print(f"执行 Git 同步操作 (git pull --rebase --autostash) 从远程 '{args.remote}'...")
                    run_command(["git", "pull", "--rebase", "--autostash", args.remote], cwd=project_path, check_output=False)
                    print("子模块同步完成。")
                    # --- 优化结束 ---

                except Exception as e:
                    print(
                        f"处理子模块 '{os.path.basename(project_path)}' 时发生错误: {e}", file=sys.stderr
                    )
                    # 即使某个子模块失败，也尝试继续处理其他子模块
            print("\nRepo 全量同步操作完成。")
        except Exception as e:
            print(f"错误: {e}", file=sys.stderr)
            sys.exit(1)


class GenerateSSHKeyCommand(Command):
    """生成 SSH 公钥和私钥，并将公钥内容输出到标准输出。"""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.path.expanduser("~/.ssh"),
            help="指定 SSH 密钥的生成目录，默认为 ~/.ssh。",
        )
        parser.add_argument(
            "--filename",
            type=str,
            default="id_rsa",
            help="指定私钥文件名（公钥为 .pub ）。默认为 id_rsa。",
        )
        parser.add_argument(
            "--force", action="store_true", help="如果密钥已存在，强制覆盖。"
        )

    def execute(self, args: argparse.Namespace):
        ssh_dir = os.path.abspath(args.path)
        private_key_path = os.path.join(ssh_dir, args.filename)
        public_key_path = private_key_path + ".pub"

        ensure_directory_exists(ssh_dir)  # 确保 ~/.ssh 目录存在

        if os.path.exists(private_key_path) and not args.force:
            print(
                f"错误: 私钥 '{private_key_path}' 已存在。使用 --force 覆盖。",
                file=sys.stderr,
            )
            return

        print(f"正在生成 SSH 密钥对到: {private_key_path}")
        try:
            # -f 指定文件名，-t 指定类型 (rsa)，-N "" 无密码，-q 静默模式
            run_command(
                ["ssh-keygen", "-t", "rsa", "-f", private_key_path, "-N", "", "-q"],
                check_output=False,
            )
            print("SSH 密钥对已成功生成。")

            with open(public_key_path, "r") as f:
                public_key_content = f.read().strip()
            print("\n--- SSH 公钥内容 (请将其添加到您的 Git 服务) ---")
            print(public_key_content)
            print("-----------------------------------------------------")

        except Exception as e:
            print(f"生成 SSH 密钥失败: {e}", file=sys.stderr)


class GitSetUserCommand(Command):
    """设置 Git 用户名和邮箱。"""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--name", type=str, required=True, help="要设置的 Git 用户名。"
        )
        parser.add_argument(
            "--email", type=str, required=True, help="要设置的 Git 用户邮箱。"
        )
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="指定 Git 仓库路径，默认为当前目录。",
        )

    def execute(self, args: argparse.Namespace):
        try:
            git_root = find_git_root(args.path)
            print(f"在 '{git_root}' 设置 Git 用户名和邮箱...")
            run_command(
                ["git", "config", "--local", "user.name", args.name], cwd=git_root
            )
            run_command(
                ["git", "config", "--local", "user.email", args.email], cwd=git_root
            )
            print(f"Git 用户名已设置为: {args.name}")
            print(f"Git 邮箱已设置为: {args.email}")
        except Exception as e:
            print(f"错误: {e}", file=sys.stderr)


class GitSetRemoteCommand(Command):
    """设置 Git 远程仓库的 fetch 和 push 地址。"""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--remote-name",
            type=str,
            default="origin",
            help="要设置的远程仓库名称，默认为 'origin'。",
        )
        parser.add_argument(
            "--fetch-url", type=str, required=True, help="要设置的 fetch 地址。"
        )
        parser.add_argument(
            "--push-url", type=str, required=True, help="要设置的 push 地址。"
        )
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="指定 Git 仓库路径，默认为当前目录。",
        )

    def execute(self, args: argparse.Namespace):
        try:
            git_root = find_git_root(args.path)
            print(f"在 '{git_root}' 设置 Git 远程仓库地址...")
            run_command(
                ["git", "remote", "set-url", args.remote_name, args.fetch_url],
                cwd=git_root,
            )
            run_command(
                ["git", "remote", "set-url", "--push", args.remote_name, args.push_url],
                cwd=git_root,
            )
            print(
                f"Git 远程仓库 '{args.remote_name}' 的 fetch 地址已设置为: {args.fetch_url}"
            )
            print(
                f"Git 远程仓库 '{args.remote_name}' 的 push 地址已设置为: {args.push_url}"
            )
        except Exception as e:
            print(f"错误: {e}", file=sys.stderr)


# --- 主入口点 ---
if __name__ == "__main__":
    manager = ScriptManager(description="一个用于管理 Git 和 Repo 仓库的实用脚本。")

    # 注册所有 Git 和 Repo 相关的命令
    manager.register_command(
        "git-root", GitRootCommand(), help_text="获取当前 Git 仓库的根目录路径。"
    )
    manager.register_command(
        "git-remote",
        GitRemoteCommand(),
        help_text="获取当前 Git 仓库的远程地址 (fetch/push)。",
    )
    manager.register_command(
        "git-config",
        GitConfigCommand(),
        help_text="获取当前 Git 仓库的用户配置 (名称/邮箱)。",
    )
    manager.register_command(
        "git-sync", GitSyncCommand(), help_text="暂存修改，拉取并 rebase 远程最新代码。"
    )
    manager.register_command(
        "repo-manifest",
        RepoManifestCommand(),
        help_text="获取当前 Repo 仓库 manifest 文件的路径。",
    )
    manager.register_command(
        "repo-root", RepoRootCommand(), help_text="获取当前 Repo 仓库的根目录路径。"
    )
    manager.register_command(
        "repo-manifest-remote",
        RepoManifestRemoteCommand(),
        help_text="获取当前 Repo 仓库 manifest 文件的远程地址。",
    )
    manager.register_command(
        "repo-sync-all",
        RepoSyncAllCommand(),
        help_text="遍历 Repo 所有子模块，切换分支并同步。",
    )
    manager.register_command(
        "gen-ssh-key",
        GenerateSSHKeyCommand(),
        help_text="生成 SSH 密钥对并将公钥输出。",
    )
    manager.register_command(
        "git-set-user", GitSetUserCommand(), help_text="设置 Git 用户名和邮箱。"
    )
    manager.register_command(
        "git-set-remote",
        GitSetRemoteCommand(),
        help_text="设置 Git 远程仓库的 fetch 和 push 地址。",
    )

    manager.run()
