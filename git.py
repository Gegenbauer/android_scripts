#!/usr/bin/env python3
import os
import subprocess
import argparse
import sys
from script_base.script_manager import ScriptManager, Command
from script_base.utils import run_command, ensure_directory_exists

# Provides wrappers for git/repo related commands.

# 1. Get the root directory path of the git repository for the current directory.
# 2. Get the remote URLs (fetch and push) of the git repository for the current directory.
# 3. Get the configured username and email for the git repository of the current directory.
# 4. Stash all changes in the current directory, pull the latest code from the remote repository, and rebase.
# 5. Get the path of the manifest file for the repo of the current directory.
# 6. Get the root directory path of the repo for the current directory.
# 7. Get the remote URL of the manifest file for the repo of the current directory.
# 8. Iterate through all submodules of the repo for the current directory, switch to a specified branch, and execute #4 for each submodule.
# 9. Generate an SSH public and private key pair, and output the public key content to standard output.
# 10. Set the git username and email.
# 11. Set the git remote repository push and fetch URLs.


def find_git_root(path: str = None) -> str:
    """
    Gets the root directory path of the Git repository for the current or a specified directory.
    """
    path = path if path else os.getcwd()
    try:
        return run_command(["git", "rev-parse", "--show-toplevel"], cwd=path)
    except Exception:
        raise Exception(f"'{path}' is not in a Git repository.")


def find_repo_root(path: str = None) -> str:
    """
    Gets the root directory path of the Repo repository for the current or a specified directory.
    A Repo repository root typically contains a .repo directory.
    """
    current_path = os.path.abspath(path if path else os.getcwd())
    while True:
        if os.path.isdir(os.path.join(current_path, ".repo")):
            return current_path
        parent_path = os.path.dirname(current_path)
        if parent_path == current_path:  # Reached the filesystem root
            raise Exception(f"'{path if path else os.getcwd()}' is not in a Repo repository.")
        current_path = parent_path


# --- Command Implementations ---


class GitRootCommand(Command):
    """Gets the root directory path of the current Git repository."""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="Specifies the starting path for the search, defaults to the current directory.",
        )

    def execute(self, args: argparse.Namespace):
        try:
            root_path = find_git_root(args.path)
            print(f"{root_path}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)


class GitRemoteCommand(Command):
    """
    Gets the remote URLs (fetch and push) for the current Git repository.
    This command parses the output of `git remote -v` for more reliable remote URLs.
    It defaults to trying to get the URL for the 'origin' remote; if 'origin' is not found, it uses the first remote it finds.
    """

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="Specifies the Git repository path, defaults to the current directory.",
        )
        parser.add_argument(
            "--remote-name",
            type=str,
            default="origin",
            help="Specifies the name of the remote to get the URL for, defaults to 'origin'.",
        )

    def execute(self, args: argparse.Namespace):
        try:
            git_root = find_git_root(args.path)
            print(f"Attempting to get remote URLs in Git repository '{git_root}'...")

            # Run git remote -v
            remote_output = run_command(["git", "remote", "-v"], cwd=git_root)

            fetch_url = None
            push_url = None
            found_remote_name = None

            # Parse the output
            for line in remote_output.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3:
                    remote_name = parts[0]
                    url = parts[1]
                    op_type = parts[2].strip("()")

                    # If we found the specified remote name, or this is the first remote we've found (when no specific name is given)
                    if (args.remote_name and remote_name == args.remote_name) or (
                        not found_remote_name
                    ):
                        if op_type == "fetch":
                            fetch_url = url
                        elif op_type == "push":
                            push_url = url
                        found_remote_name = remote_name  # Record the remote name being processed

                        # If we have already found both fetch and push URLs, and this is the remote we are looking for, we can stop
                        if (
                            fetch_url
                            and push_url
                            and found_remote_name == args.remote_name
                        ):
                            break
                    # If we found fetch but not push (or vice versa), and this is the remote we are looking for, continue looking for the other operation for the same remote name
                    elif found_remote_name == remote_name and (
                        not fetch_url or not push_url
                    ):
                        if op_type == "fetch":
                            fetch_url = url
                        elif op_type == "push":
                            push_url = url

            if fetch_url:
                print(f"Git fetch URL ({found_remote_name}): {fetch_url}")
            else:
                print(
                    f"Could not find fetch URL for remote '{args.remote_name}'.", file=sys.stderr
                )

            if push_url:
                print(f"Git push URL ({found_remote_name}): {push_url}")
            else:
                print(
                    f"Git push URL ({found_remote_name}): {fetch_url if fetch_url else 'Not found' } (usually the same as fetch)",
                    file=sys.stderr,
                )

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)


class GitConfigCommand(Command):
    """Gets the configured username and email for the current Git repository."""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="Specifies the Git repository path, defaults to the current directory.",
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
            print(f"Git Username: {user_name}")
            print(f"Git Email: {user_email}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)


class GitSyncCommand(Command):
    """Stashes all changes, pulls the latest remote code, and rebases."""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="Specifies the Git repository path, defaults to the current directory.",
        )

    def execute(self, args: argparse.Namespace):
        try:
            git_root = find_git_root(args.path)
            print(f"Performing Git sync operation in '{git_root}'...")
            run_command(
                ["git", "stash", "save", "Auto-stashed by script"],
                cwd=git_root,
                check_output=False,
            )
            print("Stashed current changes.")
            run_command(["git", "pull", "--rebase"], cwd=git_root, check_output=False)
            print("Pulled latest code and rebased.")
            try:
                run_command(["git", "stash", "pop"], cwd=git_root, check_output=False)
                print("Restored stashed changes.")
            except subprocess.CalledProcessError as e:
                if "No stash entries found" in e.stderr:
                    print("No stashed changes to restore.")
                else:
                    raise
            print("Git sync complete.")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)


class RepoManifestCommand(Command):
    """Gets the path of the manifest file for the current Repo repository."""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="Specifies the Repo repository path, defaults to the current directory.",
        )

    def execute(self, args: argparse.Namespace):
        try:
            repo_root = find_repo_root(args.path)
            manifest_path = os.path.join(repo_root, ".repo", "manifest.xml")
            if os.path.exists(manifest_path):
                print(f"Repo manifest file path: {manifest_path}")
            else:
                print(f"Could not find manifest.xml in '{repo_root}'.", file=sys.stderr)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)


class RepoRootCommand(Command):
    """Gets the root directory path of the current Repo repository."""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="Specifies the Repo repository path, defaults to the current directory.",
        )

    def execute(self, args: argparse.Namespace):
        try:
            root_path = find_repo_root(args.path)
            print(f"{root_path}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)


class RepoManifestRemoteCommand(Command):
    """Gets the remote URL of the manifest file for the current Repo repository."""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="Specifies the Repo repository path, defaults to the current directory.",
        )

    def execute(self, args: argparse.Namespace):
        try:
            repo_root = find_repo_root(args.path)
            # The remote URL for the repo manifest is usually in .repo/manifests/.git/config
            manifest_git_config = os.path.join(
                repo_root, ".repo", "manifests", ".git", "config"
            )
            if os.path.exists(manifest_git_config):
                # Read the .git/config file to get the remote URL
                # This is a simplified method; a more robust way is to use git commands
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
                print(f"Repo manifest remote URL: {manifest_remote_url}")
            else:
                print(
                    f"Could not find manifest's Git config in '{repo_root}'.", file=sys.stderr
                )
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)


class RepoSyncAllCommand(Command):
    """
    Iterates through all submodules of the current Repo.
    If a branch is specified, it will attempt to switch to that branch (checking local and remote).
    Then, it executes `git pull --rebase --autostash` for each submodule.
    It will not automatically create new branches locally.
    """

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="Specifies the Repo repository path, defaults to the current directory.",
        )
        parser.add_argument(
            "--branch",
            type=str,
            help="Optional. The target branch name to switch to. If not specified, the current branch of each submodule will be used.",
        )
        parser.add_argument(
            "--remote",
            type=str,
            default="origin",
            help="Optional. Specifies the remote repository name, defaults to 'origin'.",
        )

    def execute(self, args: argparse.Namespace):
        try:
            repo_root = find_repo_root(args.path)
            
            target_branch_msg = f"to branch '{args.branch}'" if args.branch else "on the current branch"
            print(f"Performing full sync operation in Repo repository '{repo_root}' {target_branch_msg}...")

            # Get the paths of all submodules
            project_paths_str = run_command(
                ["repo", "forall", "-c", "pwd"], cwd=repo_root
            )
            project_paths = project_paths_str.splitlines()

            for project_path in project_paths:
                print(f"\n--- Processing submodule: {project_path} ---")
                try:
                    # If a target branch is specified
                    if args.branch:
                        print(f"Attempting to switch submodule '{os.path.basename(project_path)}' to branch '{args.branch}'...")
                        
                        local_branches = run_command(["git", "branch", "--list", args.branch], cwd=project_path)
                        local_branch_exists = bool(local_branches.strip())

                        if local_branch_exists:
                            print(f"Local branch '{args.branch}' exists, checking it out directly.")
                            run_command(["git", "checkout", args.branch], cwd=project_path, check_output=False)
                        else:
                            print(f"Local branch '{args.branch}' not found, checking if remote '{args.remote}' has it...")
                            run_command(["git", "remote", "update", args.remote], cwd=project_path, check_output=False)
                            
                            remote_branch_exists = False
                            try:
                                # Check if the remote branch exists, e.g., via ls-remote
                                run_command(["git", "ls-remote", "--heads", args.remote, args.branch], cwd=project_path)
                                remote_branch_exists = True
                            except subprocess.CalledProcessError:
                                remote_branch_exists = False
                            
                            if remote_branch_exists:
                                print(f"Remote branch '{args.remote}/{args.branch}' exists, creating a local tracking branch and checking it out.")
                                run_command(["git", "checkout", "--track", f"{args.remote}/{args.branch}"], cwd=project_path, check_output=False)
                            else:
                                raise Exception(f"Branch '{args.branch}' does not exist locally or on the remote. Please create it manually or check the branch name.")
                    else:
                        current_branch = run_command(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=project_path)
                        print(f"No branch specified, operating on the current branch '{current_branch}'.")

                    # --- Optimized Git Sync Operation ---
                    print(f"Performing Git sync (git pull --rebase --autostash) from remote '{args.remote}'...")
                    run_command(["git", "pull", "--rebase", "--autostash", args.remote], cwd=project_path, check_output=False)
                    print("Submodule sync complete.")
                    # --- End of Optimization ---

                except Exception as e:
                    print(
                        f"An error occurred while processing submodule '{os.path.basename(project_path)}': {e}", file=sys.stderr
                    )
                    # Continue processing other submodules even if one fails
            print("\nRepo full sync operation complete.")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)


class GenerateSSHKeyCommand(Command):
    """Generates an SSH public and private key pair and outputs the public key content to standard output."""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--path",
            type=str,
            default=os.path.expanduser("~/.ssh"),
            help="Specifies the directory to generate the SSH keys in, defaults to ~/.ssh.",
        )
        parser.add_argument(
            "--filename",
            type=str,
            default="id_rsa",
            help="Specifies the private key filename (public key will have .pub). Defaults to id_rsa.",
        )
        parser.add_argument(
            "--force", action="store_true", help="Force overwrite if the key already exists."
        )

    def execute(self, args: argparse.Namespace):
        ssh_dir = os.path.abspath(args.path)
        private_key_path = os.path.join(ssh_dir, args.filename)
        public_key_path = private_key_path + ".pub"

        ensure_directory_exists(ssh_dir)  # Ensure the ~/.ssh directory exists

        if os.path.exists(private_key_path) and not args.force:
            print(
                f"Error: Private key '{private_key_path}' already exists. Use --force to overwrite.",
                file=sys.stderr,
            )
            return

        print(f"Generating SSH key pair at: {private_key_path}")
        try:
            # -f specifies filename, -t specifies type (rsa), -N "" for no passphrase, -q for quiet mode
            run_command(
                ["ssh-keygen", "-t", "rsa", "-f", private_key_path, "-N", "", "-q"],
                check_output=False,
            )
            print("SSH key pair generated successfully.")

            with open(public_key_path, "r") as f:
                public_key_content = f.read().strip()
            print("\n--- SSH Public Key Content (please add this to your Git service) ---")
            print(public_key_content)
            print("-----------------------------------------------------")

        except Exception as e:
            print(f"Failed to generate SSH key: {e}", file=sys.stderr)


class GitSetUserCommand(Command):
    """Sets the Git username and email."""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--name", type=str, required=True, help="The Git username to set."
        )
        parser.add_argument(
            "--email", type=str, required=True, help="The Git user email to set."
        )
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="Specifies the Git repository path, defaults to the current directory.",
        )

    def execute(self, args: argparse.Namespace):
        try:
            git_root = find_git_root(args.path)
            print(f"Setting Git username and email in '{git_root}'...")
            run_command(
                ["git", "config", "--local", "user.name", args.name], cwd=git_root
            )
            run_command(
                ["git", "config", "--local", "user.email", args.email], cwd=git_root
            )
            print(f"Git username has been set to: {args.name}")
            print(f"Git email has been set to: {args.email}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)


class GitSetRemoteCommand(Command):
    """Sets the fetch and push URLs for a Git remote."""

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--remote-name",
            type=str,
            default="origin",
            help="The name of the remote to set, defaults to 'origin'.",
        )
        parser.add_argument(
            "--fetch-url", type=str, required=True, help="The fetch URL to set."
        )
        parser.add_argument(
            "--push-url", type=str, required=True, help="The push URL to set."
        )
        parser.add_argument(
            "--path",
            type=str,
            default=os.getcwd(),
            help="Specifies the Git repository path, defaults to the current directory.",
        )

    def execute(self, args: argparse.Namespace):
        try:
            git_root = find_git_root(args.path)
            print(f"Setting Git remote URLs in '{git_root}'...")
            run_command(
                ["git", "remote", "set-url", args.remote_name, args.fetch_url],
                cwd=git_root,
            )
            run_command(
                ["git", "remote", "set-url", "--push", args.remote_name, args.push_url],
                cwd=git_root,
            )
            print(
                f"Fetch URL for remote '{args.remote_name}' has been set to: {args.fetch_url}"
            )
            print(
                f"Push URL for remote '{args.remote_name}' has been set to: {args.push_url}"
            )
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)


# --- Main Entry Point ---
if __name__ == "__main__":
    manager = ScriptManager(description="A utility script for managing Git and Repo repositories.")

    # Register all Git and Repo related commands
    manager.register_command(
        "git-root", GitRootCommand(), help_text="Get the root directory path of the current Git repository."
    )
    manager.register_command(
        "git-remote",
        GitRemoteCommand(),
        help_text="Get the remote URLs (fetch/push) for the current Git repository.",
    )
    manager.register_command(
        "git-config",
        GitConfigCommand(),
        help_text="Get the user configuration (name/email) for the current Git repository.",
    )
    manager.register_command(
        "git-sync", GitSyncCommand(), help_text="Stash changes, pull and rebase the latest remote code."
    )
    manager.register_command(
        "repo-manifest",
        RepoManifestCommand(),
        help_text="Get the path of the manifest file for the current Repo repository.",
    )
    manager.register_command(
        "repo-root", RepoRootCommand(), help_text="Get the root directory path of the current Repo repository."
    )
    manager.register_command(
        "repo-manifest-remote",
        RepoManifestRemoteCommand(),
        help_text="Get the remote URL of the manifest file for the current Repo repository.",
    )
    manager.register_command(
        "repo-sync-all",
        RepoSyncAllCommand(),
        help_text="Iterate through all Repo submodules, switch branches, and sync.",
    )
    manager.register_command(
        "gen-ssh-key",
        GenerateSSHKeyCommand(),
        help_text="Generate an SSH key pair and output the public key.",
    )
    manager.register_command(
        "git-set-user", GitSetUserCommand(), help_text="Set the Git username and email."
    )
    manager.register_command(
        "git-set-remote",
        GitSetRemoteCommand(),
        help_text="Set the fetch and push URLs for a Git remote.",
    )

    manager.run()
