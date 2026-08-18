# Android Scripts

English | [简体中文](README_CN.md)

A set of Android development/debugging tools based on ADB and Frida, providing APK management, device debugging, performance analysis, and dynamic instrumentation through a unified CLI.

## Features

- **APK Management**: Pull APKs from device, decompile with apktool
- **Device Debugging**: View current Activity/Fragment, force-stop apps, clear app data, set debugger
- **Performance Analysis**: Export memory heap dumps, capture Perfetto systraces, dump thread stacks
- **Dynamic Instrumentation** (Frida): Export runtime Bitmaps, change system language, inspect View hierarchy
- **Package Management**: Inspect package flags, check/grant/revoke permissions
- **File Operations**: Pull device files/directories to local machine and open them

## Requirements

- Python 3.8+
- Node.js 16+ (`frida-java-bridge` npm package required for Frida 17+)
- Android SDK (`adb` must be available)
- `apktool` and Java runtime (for decompilation)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Gegenbauer/android_scripts.git
cd android_scripts
```

### 2. Create Virtual Environment and Install Dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Install Node.js Dependencies (Required for Frida 17+)

```bash
npm install
```

### 4. Set Environment Variables

```bash
# Android SDK path (required)
export android_sdk_path="/path/to/your/android-sdk"

# Cache/output directory (optional, defaults to current directory)
export cache_files_dir="/path/to/cache"
```

### 5. Verify ADB Connection

```bash
adb devices
```

## Usage

All ADB commands are accessed through the unified `adb.py` entry point:

```bash
python adb.py <command> [options]
```

### Examples

```bash
# Show current foreground Activity and Fragment
python adb.py show-focused-activity

# Pull APK of the current foreground app
python adb.py pull-apk --focused

# Decompile a specific package (requires apktool)
python adb.py decompile -p com.example.app

# Force-stop an app
python adb.py kill --focused

# Clear app data (requires root)
python adb.py clear-data -p com.example.app --all

# Export all runtime Bitmaps (Frida)
python adb.py export-bitmaps -p com.example.app

# Change system language (Frida, no root required)
python adb.py set-language --language zh --country CN

# Export memory heap dump
python adb.py dump-memory -p com.example.app

# Capture Perfetto systrace
python adb.py record-systrace

# Inspect package flags and permissions
python adb.py package-manager show-flags -p com.example.app
python adb.py package-manager check-permission -p com.example.app --permission android.permission.CAMERA

# Pull a device file and open in VSCode
python adb.py view-file -d /sdcard/Download/log.txt --open-in-vscode

# Pull a device directory and open in file manager
python adb.py view-folder -d /sdcard/Download
```

### Multi-device Support

When no `-s` is specified, the first connected device is used automatically. A warning is printed when multiple devices are connected. Use `-s`/`--serial` to select a specific device, or `--suppress-warnings` to hide the warning:

```bash
python adb.py -s <device_serial> pull-apk --focused
python adb.py --suppress-warnings pull-apk --focused
```

### All Commands

| Command | Description |
|---|---|
| `show-focused-activity` | Show current focused Activity, Window, and Fragment info |
| `pull-apk` | Pull APK from device to local machine |
| `decompile` | Decompile APK/JAR (via apktool) |
| `kill` | Force-stop an app |
| `clear-data` | Clear app data (requires root) |
| `export-bitmaps` | Export runtime Bitmaps (Frida) |
| `set-language` | Change system language (Frida) |
| `set-time` | Set device time |
| `set-ui-mode` | Switch dark/light/auto mode |
| `dump-memory` | Export memory heap dump |
| `dump-thread-stack` | Export thread stack traces (for ANR debugging) |
| `record-systrace` | Record Perfetto system trace |
| `package-manager` | Package management: inspect flags, permissions |
| `debugger` | Set/clear app debugger |
| `view-file` | Pull a device file to local machine |
| `view-folder` | Pull a device directory to local machine |

## Frida Setup

This project uses [Frida](https://frida.re/) for dynamic instrumentation of Android apps. The following features require Frida:

- `export-bitmaps`: Export runtime Bitmap objects
- `set-language`: Change system language
- `show-focused-activity`: Get Resumed Fragment info
- `view.js` related features: View hierarchy inspection

### 1. Install Frida Python Tools

Already included in `requirements.txt`. Just run `pip install -r requirements.txt`.

### 2. Download and Push Frida Server to Device

Download the `frida-server` matching your device architecture from [Frida Releases](https://github.com/aspect-build/frida/releases):

```bash
# Check device architecture
adb shell getprop ro.product.cpu.abi

# Download the matching frida-server version (must match the pip-installed frida version)
# e.g. frida 17.3.2, device is arm64:
wget https://github.com/aspect-build/frida/releases/download/17.3.2/frida-server-17.3.2-android-arm64.xz

# Extract and push to device
xz -d frida-server-*.xz
adb push frida-server-*/frida-server /data/local/tmp/frida
adb shell chmod 755 /data/local/tmp/frida
```

### 3. Start Frida Server

```bash
# Start without root
adb shell "/data/local/tmp/frida &"

# Start with root (recommended, more features available)
adb root
adb shell "/data/local/tmp/frida &"
```

### 4. Verify Installation

```bash
# Check frida version
frida --version

# Confirm frida-server is running on device
frida-ps -U
```

### 5. Node.js Dependencies (Frida 17+)

Frida 17+ uses ES Module syntax with `frida-java-bridge`, which must be installed via npm:

```bash
npm install
```

The `FridaScriptExecutor` in this project automatically detects and compiles JS scripts, no manual configuration needed.

### Notes

- **Version Matching**: The host `frida` Python package version must match the device `frida-server` version, otherwise errors will occur
- **Root Privileges**: `export-bitmaps`, `set-language` and similar features work best with root
- **Process Selection**: Frida injection requires the target process to exist. Commands like `export-bitmaps` need `-p <package>` or `--focused`

## Standalone Tools

In addition to `adb.py`, the project includes several standalone scripts:

```bash
# Git/Repo management
python git.py git-sync
python git.py repo-sync-all

# Encode/decode tool
python encoder.py encode --method base64 --input "hello"
python encoder.py decode --method base64 --input "aGVsbG8="

# Markdown image management
python md_image_search.py search-images -f readme.md
```

## Project Structure

```
android_scripts/
├── adb.py                          # Main ADB command entry point
├── git.py                          # Git/Repo command entry point
├── encoder.py                      # Encode/decode tool entry point
├── export_bitmaps.py               # Frida: Export Bitmaps
├── set_language.py                 # Frida: Set language
├── get_resumed_fragment.py         # Frida: Get fragments
├── view.py                         # Frida: View hierarchy inspection
├── requirements.txt                # Python dependencies
├── package.json                    # Node.js dependencies
├── script_base/                    # Shared framework
│   ├── script_manager.py           # CLI framework (ScriptManager + Command)
│   ├── frida_utils.py              # Frida script executor
│   ├── utils.py                    # General utilities
│   ├── log.py                      # Logging module
│   ├── env_setup.py                # Environment path management
│   └── platforms.py                # Platform abstraction layer
├── command/android/                # ADB command implementations
│   ├── base.py                     # AdbCommand base class
│   ├── apk.py                      # APK pull/decompile
│   ├── common_debug.py             # Debug-related commands
│   ├── performance.py              # Performance analysis commands
│   ├── package_manager.py          # Package manager commands
│   ├── setting.py                  # Settings commands
│   └── file.py                     # File operation commands
└── android_util_impls/             # Android device operation wrappers
    ├── base.py                     # AndroidUtilBase (60+ methods)
    ├── manager.py                  # Device implementation manager
    ├── activity_manager_util.py    # Activity Manager operations
    └── package_manager_util.py     # Package Manager operations
```

## License

ISC
