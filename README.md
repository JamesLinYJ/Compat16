<div align="center">

<img src="assets/icon.svg" width="112" height="112" alt="Compat16 icon">

# Compat16

**DOS and Win16 compatibility for modern Windows**

Windows ARM64 · Windows AMD64 · Rust 2024

[English](#english) · [简体中文](#简体中文)

</div>

---

## English

**Run DOS and Win16 applications on modern Windows.**

Compat16 executes guest x86 instructions inside a native Windows process and translates DOS / Win16 interfaces to host services. It reuses Windows APIs for files, windows, and input, while managing guest memory, handles, and calling conventions explicitly.

**Compatibility is under development.** Starting an application does not establish complete support. Some graphics, system interfaces, and interprocess workflows remain incomplete.

### Build and run

From the repository root, run in Windows PowerShell:

```powershell
.\scripts\configure.ps1
.\scripts\build.ps1
```

Configuration prepares the pinned Rust toolchain under `.dev` and checks Microsoft C++ Build Tools and the Windows SDK. Shared build tools are managed by Microsoft's installer. The build script offers an architecture menu; unattended builds can select a target directly:

```powershell
.\scripts\build.ps1 -Architecture arm64 -NonInteractive
.\scripts\build.ps1 -Architecture x64 -NonInteractive
```

The output is placed in `dist/arm64` or `dist/x64`. Keep the four runtime files together:

| File | Purpose |
| --- | --- |
| `compat16.exe` | Console launcher |
| `compat16w.exe` | GUI launcher |
| `compat16.dll` | Runtime and compatibility services |
| `compat16host.exe` | Isolated native API helper |

```powershell
.\dist\arm64\compat16.exe 'D:\LegacyApps\APP.EXE'
```

Supply the legacy application and its companion files yourself. Use the console launcher's `--help` option for available settings.

### Install and uninstall

After building, run from an **administrator PowerShell**:

```powershell
.\scripts\install.ps1
# Remove this installation's integration:
.\scripts\uninstall.ps1
```

Installation copies the native runtime and adds its own Windows legacy application launch entry. Uninstallation removes unchanged files and settings recorded by this installation, retaining other software's settings and additional files.

Double-click launching depends on the Windows `NtVdm64` mechanism. Microsoft documents its absence on Windows 10 ARM; triggering it on Windows 11 ARM64 still requires native validation. Launching an application explicitly does not require this registry integration. [Microsoft documentation](https://learn.microsoft.com/en-us/windows/win32/winprog64/application-installation)

### Development

The architecture separates guest CPU execution, DOS / Win16 ABI translation, and native Windows calls. See [AGENTS.md](AGENTS.md) for concise guidance applicable to all contributors and development tools.

Release builds remap source paths and package only runtime files, required notices, and file checksums. Local toolchains and build caches are excluded from the repository and release package.

See [LICENSE](LICENSE) for project terms. Adopted data, implementations, and dependencies retain their applicable notices.

---

## 简体中文

Compat16 在进程内执行旧程序的 x86 指令，并把 DOS / Win16 接口转换为宿主 Windows 服务。文件、窗口、输入等功能尽量复用系统 API；客体内存、句柄和调用约定由兼容层管理。

**项目仍在开发中。** 程序能启动不代表全部功能兼容；图形布局、部分系统接口及跨程序交互仍需完善。

### 快速开始

在 Windows 的 PowerShell 中，从项目根目录执行：

```powershell
.\scripts\configure.ps1
.\scripts\build.ps1
```

配置脚本准备固定版本的 Rust，并检查 Microsoft C++ 构建工具与 Windows SDK。Rust 环境放在项目的 `.dev` 目录；系统构建工具由微软安装器管理。编译脚本提供架构选择，也可直接指定：

```powershell
.\scripts\build.ps1 -Architecture arm64 -NonInteractive
.\scripts\build.ps1 -Architecture x64 -NonInteractive
```

产物位于 `dist/arm64` 或 `dist/x64`。保持以下四个文件在同一目录：

| 文件 | 用途 |
| --- | --- |
| `compat16.exe` | 控制台启动器 |
| `compat16w.exe` | 图形启动器 |
| `compat16.dll` | 运行时与兼容层 |
| `compat16host.exe` | 隔离原生服务调用的辅助进程 |

```powershell
.\dist\arm64\compat16.exe 'D:\LegacyApps\APP.EXE'
```

旧程序及其配套文件由使用者自行提供。控制台入口支持 `--help`。

### 安装与还原

编译完成后，在**管理员 PowerShell**中执行：

```powershell
.\scripts\install.ps1
```

安装脚本复制当前架构的运行时，并添加自己的 Windows 旧程序启动入口。卸载时只撤销安装记录中未被修改的文件和设置，保留其他软件的设置及额外文件：

```powershell
.\scripts\uninstall.ps1
```

双击启动依赖 Windows 的 `NtVdm64` 机制，不能保证所有系统版本都支持。微软明确记录 Windows 10 ARM 不包含该机制；Windows 11 ARM64 的触发行为仍需实机核验。直接调用启动器不依赖此注册表接管机制。[微软说明](https://learn.microsoft.com/zh-cn/windows/win32/winprog64/application-installation)

### 结构

```text
旧程序机器码 → x86 执行 → DOS / Win16 ABI → 参数与回调转换 → Windows API
```

| 目录 | 职责 |
| --- | --- |
| `crates/cpu` | CPU 状态、解码器适配与指令执行 |
| `crates/dos`、`crates/win16` | 客体接口与数据结构 |
| `crates/runtime` | 程序执行、内存及调用协调 |
| `crates/host` | Windows 服务与原生调用边界 |
| `crates/engine`、`crates/launcher` | 运行入口与动态库加载 |
| `scripts` | 配置、编译、安装与卸载 |

发布构建会映射源码路径，并只打包运行文件、必要许可文本和文件校验清单。编译缓存和本机开发环境不进入仓库或发行包。

### 参与开发

开发约定见 [AGENTS.md](AGENTS.md)。该文件面向所有贡献者和开发工具，不依赖特定编辑器或助手。

项目许可见 [LICENSE](LICENSE)；沿用的数据、实现与依赖保留其各自适用的声明。
