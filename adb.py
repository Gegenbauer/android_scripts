#!/usr/bin/env python3
"""
ADB multi-tool script.
Provides various commands for Android device operations via ADB.
Includes device management, file operations, app management, performance tracing, APK operations, and advanced features.
"""

from command.android.apk import PullApkCommand, DecompileCommand
from command.android.common_debug import ShowFocusedActivityCommand, KillCommand, ClearDataCommand, DebuggerCommand
from command.android.file import ViewFolderCommand, ViewFileCommand
from command.android.package_manager import PackageManagerCommand
from command.android.performance import RecordSystemTraceCommand, ExportBitmapsCommand, DumpMemoryCommand, DumpThreadStackCommand
from command.android.setting import SetTimeCommand, SetUiModeCommand, SetLanguageCommand

from script_base.script_manager import ScriptManager


if __name__ == "__main__":
    # Test if android_sdk_path exists in environment variables
    manager = ScriptManager(
        description="""Android ADB multi-tool script.

Includes comprehensive subcommands for Android device operations:
- Device management: set-time, show-focused-activity, set-ui-mode
- File operations: view-folder, view-file (pull and view device files)
- App management: kill, clear-data, dump-memory, debugger, package-manager, dump-thread-stack
- Performance tracing: record-systrace
- APK operations: pull-apk (extract APK from device), decompile (decompile APK/JAR)
- Advanced features: export-bitmaps, set-language (using Frida)

All commands support device selection via --serial and --suppress-warnings options.

Usage examples:
  python adb.py set-time 2025-10-05-14-30-00
  python adb.py show-focused-activity
  python adb.py view-folder /sdcard/Download --no-open
  python adb.py view-file /sdcard/Download/test.txt --open-in-vscode
  python adb.py set-ui-mode night
  python adb.py dump-memory --focused --convert-mat
  python adb.py kill --focused
  python adb.py clear-data --focused --type cache shared_prefs
  python adb.py pull-apk --focused --show-in-file-manager
  python adb.py decompile --package com.example.app
  python adb.py decompile --local-file /path/to/app.apk --no-open
  python adb.py export-bitmaps --package com.example.app
  python adb.py set-language --language zh --country CN
  python adb.py debugger set --focused
  python adb.py package-manager flags --focused
  python adb.py dump-thread-stack --focused --open-in-vscode
  python adb.py record-systrace --duration 10
"""
    )

    manager.register_command(
        "set-time", SetTimeCommand(), help_text="Set the time on an Android device."
    )
    manager.register_command(
        "show-focused-activity",
        ShowFocusedActivityCommand(),
        help_text="Show the currently focused Activity.",
    )
    manager.register_command(
        "view-folder",
        ViewFolderCommand(),
        help_text="View a device directory: pull to local and open in file manager.",
    )
    manager.register_command(
        "view-file",
        ViewFileCommand(),
        help_text="View a device file: pull to local, can output or open in VSCode.",
    )
    manager.register_command(
        "dump-memory",
        DumpMemoryCommand(),
        help_text="Dump memory snapshot and pull to local, optionally convert to MAT format and show in Finder.",
    )
    manager.register_command(
        "set-ui-mode",
        SetUiModeCommand(),
        help_text="Switch the day/night mode of the Android device.",
    )
    manager.register_command(
        "kill",
        KillCommand(),
        help_text="Force stop an Android application (by package name or focused app).",
    )
    manager.register_command(
        "clear-data",
        ClearDataCommand(),
        help_text="Fine-grained clearing of application data (requires root permission)."
    )
    manager.register_command(
        "export-bitmaps",
        ExportBitmapsCommand(),
        help_text="Export all in-memory Bitmaps from a running Android app process using Frida."
    )
    manager.register_command(
        "set-language",
        SetLanguageCommand(),
        help_text="Set the system language on an Android device using Frida."
    )
    manager.register_command(
        "debugger",
        DebuggerCommand(),
        help_text="Set or clear the application to be debugged."
    )
    manager.register_command(
        "package-manager",
        PackageManagerCommand(),
        help_text="Package Manager Service operations (flags, permissions, etc.)"
    )
    manager.register_command(
        "pull-apk",
        PullApkCommand(),
        help_text="Pull APK file from Android device to local machine."
    )
    manager.register_command(
        "decompile",
        DecompileCommand(),
        help_text="Decompile APK or JAR files using apktool, with support for pulling from device."
    )
    manager.register_command(
        "dump-thread-stack",
        DumpThreadStackCommand(),
        help_text="Dump thread stack traces of a target Android app process."
    )
    manager.register_command(
        "record-systrace",
        RecordSystemTraceCommand(),
        help_text="Record a systrace on the Android device."
    )

    manager.run()
