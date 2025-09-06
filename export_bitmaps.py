#!/usr/bin/env python
import frida
import sys
import argparse
import os
import subprocess
import time
from datetime import datetime

# 定义你的 Frida 脚本文件名
FRIDA_SCRIPT_FILE = "export_bitmaps.js"
# Android 设备上的目标目录，不再按包名区分
ANDROID_SAVE_DIR = "/sdcard/Download/exported_bitmaps/"
# 电脑上的本地保存目录模板
PC_BASE_DIR = os.path.join(os.environ.get("cache_files_dir"), "exported_bitmaps")

class FridaScriptRunner:
    def __init__(self, package_name, android_save_path):
        self.package_name = package_name
        self.android_save_path = android_save_path
        self.session = None
        self.script = None
        self.is_done = False

    def get_pid_from_adb(self):
        """
        通过 adb shell ps -A 命令获取进程 PID
        """
        print("[*] Getting process list from adb...")
        try:
            # 使用 adb shell ps -A 命令获取所有进程信息
            result = subprocess.run(
                ["adb", "shell", "ps", "-A"],
                capture_output=True,
                text=True,
                check=True
            )
            lines = result.stdout.splitlines()

            # 解析输出，查找匹配的包名
            for line in lines:
                if self.package_name in line:
                    # 分割行以提取 PID，PID 通常是第二列
                    parts = line.split()
                    pid = parts[1]
                    print(f"[+] Found process '{self.package_name}' with PID: {pid}")
                    return int(pid)
        except Exception as e:
            print(f"[!] Error getting PID via adb: {e}")
        
        return None

    def on_message(self, message, data):
        """Frida 脚本发送消息的回调函数"""
        if message['type'] == 'send':
            payload = message['payload']
            if payload.get('type') == 'finish':
                print(f"[*] Frida script reports: {payload.get('message')}")
                self.is_done = True
            elif payload.get('type') == 'error':
                print(f"[!] Frida script error: {payload.get('message')}")
                self.is_done = True
            elif message['type'] == 'logd':
                print(f"[*] {payload}")
            elif message['type'] == 'loge':
                print(f"[!] {payload}")
        elif message['type'] == 'error':
            print(f"[!] Frida script error: {message['description']}")
            self.is_done = True

    def run(self):
        try:
            print("[*] Checking for connected devices...")
            device = frida.get_usb_device(timeout=5)
            print(f"[+] Found device: {device.name}")

            # 1. 通过 adb 获取 PID
            pid = self.get_pid_from_adb()
            if pid is None:
                print(f"[!] Error: Process '{self.package_name}' not found. Is the app running?")
                sys.exit(1)

            # 2. 使用 PID attach 进程
            print(f"[*] Attaching to process with PID: {pid}")
            time.sleep(3)
            self.session = device.attach(pid)

            # 3. 加载 Frida 脚本
            # 获取本 py 脚本所在目录
            script_dir = os.path.dirname(os.path.abspath(__file__))
            # 拼接 Frida 脚本文件路径
            frida_script_path = os.path.join(script_dir, FRIDA_SCRIPT_FILE)
            with open(frida_script_path, 'r') as f:
                script_content = f.read()
            
            script_content = script_content.replace("{{save_path}}", self.android_save_path)
            
            self.script = self.session.create_script(script_content)
            self.script.on('message', self.on_message)
            print("[*] Injecting Frida script...")
            self.script.load()

            print("[*] Frida script injected. Waiting for it to finish...")

            while not self.is_done:
                time.sleep(1)

        except frida.ServerNotRunningError:
            print("[!] Error: Frida server is not running on the device. Please start it first.")
            sys.exit(1)
        except Exception as e:
            print(f"[!] An unexpected error occurred: {e}")
            sys.exit(1)
        finally:
            if self.session:
                self.session.detach()
                print("[+] Frida session detached successfully.")

def main():
    parser = argparse.ArgumentParser(description="Export all Bitmaps from a target Android process.")
    parser.add_argument("package_name", help="The package name of the target Android application.")
    args = parser.parse_args()
    package_name = args.package_name

    runner = FridaScriptRunner(package_name, ANDROID_SAVE_DIR)
    runner.run()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    local_path = os.path.join(PC_BASE_DIR, package_name, timestamp)
    
    os.makedirs(local_path, exist_ok=True)
    
    print(f"[*] Pulling files from '{ANDROID_SAVE_DIR}' to '{local_path}'...")
    adb_command = ["adb", "pull", ANDROID_SAVE_DIR, local_path]
    try:
        subprocess.run(adb_command, check=True)
        print("[+] Files pulled successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Adb pull failed: {e}")
    
    # 找到 local_path 第一个文件路径
    reveal_path = os.path.join(local_path, os.listdir(local_path)[0]) if os.listdir(local_path) else local_path
    print(f"[*] Opening local directory: {reveal_path}")
    if sys.platform == "win32":
        os.startfile(reveal_path)
    elif sys.platform == "darwin":  # macOS
        subprocess.Popen(["open", reveal_path])
    else:  # Linux
        subprocess.Popen(["xdg-open", reveal_path])

if __name__ == "__main__":
    main()