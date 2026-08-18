# Android Scripts

[English](README.md) | 简体中文

一套基于 ADB 和 Frida 的 Android 开发/调试工具集，通过统一的命令行界面提供 APK 管理、设备调试、性能分析、动态注入等功能。

## 功能概览

- **APK 管理**：从设备提取 APK、反编译（apktool）
- **设备调试**：查看当前 Activity/Fragment、强制停止应用、清除应用数据、设置调试器
- **性能分析**：导出内存堆快照、抓取 Perfetto Systrace、导出线程堆栈
- **动态 Instrumentation**（Frida）：导出运行时 Bitmap、修改系统语言、查看 View 层级
- **包管理**：查看包 Flags、权限检查/授予/撤销
- **文件操作**：拉取设备文件/目录到本地并打开

## 环境要求

- Python 3.8+
- Node.js 16+（Frida 17+ 需要 `frida-java-bridge` npm 包）
- Android SDK（`adb` 命令可用）
- 部分功能需要 `apktool`（反编译）和 Java 运行时

## 安装

### 1. 克隆仓库

```bash
git clone https://github.com/Gegenbauer/android_scripts.git
cd android_scripts
```

### 2. 创建虚拟环境并安装依赖

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. 安装 Node.js 依赖（Frida 17+ 必需）

```bash
npm install
```

### 4. 设置环境变量

```bash
# Android SDK 路径（必须）
export android_sdk_path="/path/to/your/android-sdk"

# 缓存/输出目录（可选，默认为当前目录）
export cache_files_dir="/path/to/cache"
```

### 5. 验证 ADB 连接

```bash
adb devices
```

## 使用方式

所有 ADB 相关命令通过 `adb.py` 统一入口调用：

```bash
python adb.py <command> [options]
```

### 常用命令示例

```bash
# 查看当前前台 Activity 和 Fragment
python adb.py show-focused-activity

# 提取当前前台应用的 APK 到本地
python adb.py pull-apk --focused

# 反编译指定包名的 APK（需要 apktool）
python adb.py decompile -p com.example.app

# 强制停止应用
python adb.py kill --focused

# 清除应用数据（需要 root）
python adb.py clear-data -p com.example.app --all

# 导出应用运行时所有 Bitmap（Frida）
python adb.py export-bitmaps -p com.example.app

# 修改系统语言（Frida，无需 root）
python adb.py set-language --language zh --country CN

# 导出内存堆快照
python adb.py dump-memory -p com.example.app

# 抓取 Perfetto Systrace
python adb.py record-systrace

# 查看应用包 Flags 和权限
python adb.py package-manager show-flags -p com.example.app
python adb.py package-manager check-permission -p com.example.app --permission android.permission.CAMERA

# 拉取设备文件并用 VSCode 打开
python adb.py view-file -d /sdcard/Download/log.txt --open-in-vscode

# 拉取设备目录并在文件管理器中打开
python adb.py view-folder -d /sdcard/Download
```

### 多设备支持

默认不指定 `-s` 时，自动使用第一台已连接的设备。多设备连接时会打印警告提示，使用 `-s`/`--serial` 指定目标设备，或加 `--suppress-warnings` 隐藏警告：

```bash
python adb.py -s <device_serial> pull-apk --focused
python adb.py --suppress-warnings pull-apk --focused
```

### 全部命令列表

| 命令 | 说明 |
|---|---|
| `show-focused-activity` | 显示当前聚焦的 Activity、Window、Fragment 信息 |
| `pull-apk` | 从设备提取 APK 到本地 |
| `decompile` | 反编译 APK/JAR（基于 apktool） |
| `kill` | 强制停止应用 |
| `clear-data` | 清除应用数据（需 root） |
| `export-bitmaps` | 导出应用运行时 Bitmap（Frida） |
| `set-language` | 修改系统语言（Frida） |
| `set-time` | 设置设备时间 |
| `set-ui-mode` | 切换深色/浅色/自动模式 |
| `dump-memory` | 导出内存堆快照 |
| `dump-thread-stack` | 导出线程堆栈（ANR 调试） |
| `record-systrace` | 录制 Perfetto 系统追踪 |
| `package-manager` | 包管理：查看 Flags、权限操作 |
| `debugger` | 设置/清除应用调试器 |
| `view-file` | 拉取设备文件到本地 |
| `view-folder` | 拉取设备目录到本地 |

## Frida 环境配置

本项目使用 [Frida](https://frida.re/) 进行 Android 应用的动态 Instrumentation。以下功能依赖 Frida：

- `export-bitmaps`：导出运行时 Bitmap 对象
- `set-language`：修改系统语言
- `show-focused-activity`：获取 Resumed Fragment 信息
- `view.js` 相关功能：View 层级查看

### 1. 安装 Frida Python 工具

已包含在 `requirements.txt` 中，执行 `pip install -r requirements.txt` 即可。

### 2. 下载并推送 Frida Server 到设备

从 [Frida Releases](https://github.com/aspect-build/frida/releases) 下载对应设备架构的 `frida-server`：

```bash
# 查看设备架构
adb shell getprop ro.product.cpu.abi

# 下载对应版本的 frida-server（版本需与 pip 安装的 frida 一致）
# 例如 frida 17.3.2，设备为 arm64：
wget https://github.com/aspect-build/frida/releases/download/17.3.2/frida-server-17.3.2-android-arm64.xz

# 解压并推送到设备
xz -d frida-server-*.xz
adb push frida-server-*/frida-server /data/local/tmp/frida
adb shell chmod 755 /data/local/tmp/frida
```

### 3. 启动 Frida Server

```bash
# 普通权限启动
adb shell "/data/local/tmp/frida &"

# root 权限启动（推荐，功能更完整）
adb root
adb shell "/data/local/tmp/frida &"
```

### 4. 验证安装

```bash
# 查看 frida 版本
frida --version

# 确认设备上 frida-server 正在运行
frida-ps -U
```

### 5. Node.js 依赖（Frida 17+）

Frida 17+ 使用 ES Module 语法的 `frida-java-bridge`，需要通过 npm 安装：

```bash
npm install
```

项目中的 `FridaScriptExecutor` 会自动检测并编译 JS 脚本，无需手动配置。

### 注意事项

- **版本匹配**：主机端 `frida` Python 包版本必须与设备上 `frida-server` 版本一致，否则会报错
- **Root 权限**：`export-bitmaps`、`set-language` 等功能建议在 root 环境下运行以获得最佳效果
- **进程选择**：Frida 注入需要目标进程存在，`export-bitmaps` 等命令需指定 `-p <package>` 或使用 `--focused`

## 独立工具

除 `adb.py` 外，项目还包含几个独立脚本：

```bash
# Git/Repo 管理工具
python git.py git-sync
python git.py repo-sync-all

# 编码/解码工具
python encoder.py encode --method base64 --input "hello"
python encoder.py decode --method base64 --input "aGVsbG8="

# Markdown 图片管理
python md_image_search.py search-images -f readme.md
```

## 项目结构

```
android_scripts/
├── adb.py                          # ADB 命令主入口
├── git.py                          # Git/Repo 命令入口
├── encoder.py                      # 编码/解码工具入口
├── export_bitmaps.py               # Frida: 导出 Bitmap
├── set_language.py                 # Frida: 设置语言
├── get_resumed_fragment.py         # Frida: 获取 Fragment
├── view.py                         # Frida: View 层级查看
├── requirements.txt                # Python 依赖
├── package.json                    # Node.js 依赖
├── script_base/                    # 共享框架
│   ├── script_manager.py           # CLI 框架（ScriptManager + Command）
│   ├── frida_utils.py              # Frida 脚本执行器
│   ├── utils.py                    # 通用工具函数
│   ├── log.py                      # 日志模块
│   ├── env_setup.py                # 环境路径管理
│   └── platforms.py                # 平台抽象层
├── command/android/                # ADB 命令实现
│   ├── base.py                     # AdbCommand 基类
│   ├── apk.py                      # APK 提取/反编译
│   ├── common_debug.py             # 调试相关命令
│   ├── performance.py              # 性能分析命令
│   ├── package_manager.py          # 包管理命令
│   ├── setting.py                  # 设置类命令
│   └── file.py                     # 文件操作命令
└── android_util_impls/             # Android 设备操作封装
    ├── base.py                     # AndroidUtilBase（60+ 方法）
    ├── manager.py                  # 设备实现管理器
    ├── activity_manager_util.py    # Activity Manager 操作
    └── package_manager_util.py     # Package Manager 操作
```

## License

ISC
