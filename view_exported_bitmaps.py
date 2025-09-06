#! /usr/bin/env python3

# 从 /sdcard/Download/exported_bitmaps/ 目录中查看导出的位图文件
# 拉取到本地 ${cache_files_dir}/exported_bitmaps/ 目录
import os
import subprocess
import sys
from datetime import datetime

ANDROID_DIR = "/sdcard/Download/exported_bitmaps/"
PC_BASE_DIR = os.path.join(os.environ.get("cache_files_dir", "."), "exported_bitmaps")

def main():
    # 拉取文件到本地
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    local_path = os.path.join(PC_BASE_DIR, timestamp)
    os.makedirs(local_path, exist_ok=True)
    print(f"[*] Pulling files from '{ANDROID_DIR}' to '{local_path}'...")
    adb_command = ["adb", "pull", ANDROID_DIR, local_path]
    try:
        subprocess.run(adb_command, check=True)
        print("[+] Files pulled successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Adb pull failed: {e}")
        sys.exit(1)

    # 清除 Android 侧的文件
    print("[*] Clearing files on Android side...")
    clear_command = ["adb", "shell", "rm", "-rf", ANDROID_DIR]
    try:
        subprocess.run(clear_command, check=True)
        print("[+] Android side files cleared.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to clear Android side files: {e}")
        # 继续执行，不影响本地查看
        print("[*] Continuing to view local files...")

    # 列出本地目录下的文件
    files = os.listdir(local_path)
    if not files:
        print("[!] No bitmap files found.")
        sys.exit(0)

    print(f"[*] Bitmap files in '{local_path}':")
    for f in files:
        print(f"    {f}")

    # 打开本地目录
    reveal_path = os.path.join(local_path, os.listdir(local_path)[0]) if os.listdir(local_path) else local_path
    print(f"[*] Opening local directory: {reveal_path}")
    if sys.platform == "win32":
        os.startfile(reveal_path)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", reveal_path])
    else:
        subprocess.Popen(["xdg-open", reveal_path])

if __name__ == "__main__":
    main()