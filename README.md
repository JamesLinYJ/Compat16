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

### Optional profile guided optimization

PGO uses the pinned Rust 1.99.0 profiler runtime, its bundled COFF linker, and the `llvm-tools-preview` component. Install that optional component into the same Rust installation used by the build script. For the project-local toolchain:

```powershell
$previousRustupHome = $env:RUSTUP_HOME
try {
    $env:RUSTUP_HOME = Join-Path $PWD '.dev\rustup'
    .\.dev\cargo\bin\rustup.exe component add llvm-tools-preview --toolchain 1.99.0
} finally { $env:RUSTUP_HOME = $previousRustupHome }
```

Generate, collect real workloads, merge, and rebuild with the profile:

```powershell
.\scripts\build.ps1 -Architecture amd64 -Pgo generate -NonInteractive
.\scripts\pgo.ps1 -Action Collect -Architecture amd64 -Workload app-console -GuestPath 'D:\LegacyApps\APP.EXE'
.\scripts\pgo.ps1 -Action Collect -Architecture amd64 -Launcher windowed -Workload app-gui -GuestPath 'D:\LegacyApps\GUI.EXE'
.\scripts\pgo.ps1 -Action Merge -Architecture amd64
.\scripts\build.ps1 -Architecture amd64 -Pgo use -NonInteractive
```

Use `arm64` for ARM64; collect each architecture separately on Windows that can run it. `Collect` accepts `-GuestArguments`, `-RuntimeArguments`, and `-ExpectedExitCode` and waits for normal application exit. Descendant helpers inherit profiling settings. All four files are instrumented together; collection requires executed functions in the selected launcher and engine DLL, while merging reports unexercised launchers or helper code. Use representative DOS and Win16 operations, including native helper workflows, before comparing performance. Forced termination may lose data. The [LLVM Windows profile writer](https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/profile/InstrProfilingUtil.c) uses ANSI file paths, so collection requires a checkout path representable in the system code page.

Instrumented builds and profiles stay under `target/pgo`; `dist` receives only regular or profile-optimized releases. New generation preserves earlier sessions and selects a fresh one. Profiles from changed source, Rust/LLVM tools, build settings, architecture, or modified profile files are rejected. Missing function warnings remain visible during the profile-use build. PGO availability and speedup require native collection and measurement; flags alone do not establish either. See the [Rust PGO guide](https://doc.rust-lang.org/rustc/profile-guided-optimization.html) and [LLVM profile tool](https://llvm.org/docs/CommandGuide/llvm-profdata.html).

The profiler and LLVM tools are development requirements. Profile-use releases contain no collection instrumentation and keep the regular build's Windows target and CPU baseline; no `target-cpu=native` tuning is added. The runtime compatibility baseline is Windows 10 22H2; actual acceptance on that system is checked separately from compilation.

### Install and uninstall

After building, run from an **administrator PowerShell**:

```powershell
.\scripts\install.ps1
# Remove this installation's integration:
.\scripts\uninstall.ps1
```

Installation copies the native runtime and adds its own Windows legacy application launch entry. Uninstallation removes unchanged files and settings recorded by this installation, retaining other software's settings and additional files.

The ARM64 package includes `system/ntvdm64.dll`, a system launch component built with the runtime. The installer adds it only when the system module is absent and records its hash for removal. Its filename and export follow the Windows launch interface; it is part of Compat16.

Double-click launching requires a Windows legacy-image callback. Microsoft documents the `NtVdm64` mechanism's absence on Windows 10 ARM; availability and behavior on later ARM64 versions require native validation. Explicit launcher invocation does not require system integration. [Microsoft documentation](https://learn.microsoft.com/en-us/windows/win32/winprog64/application-installation)

### Development

The architecture separates guest CPU execution, DOS / Win16 ABI translation, and native Windows calls. See [AGENTS.md](AGENTS.md) for concise guidance applicable to all contributors and development tools.

Windows ARM64 and AMD64 builds use an independent, bounded Cranelift JIT for hot
integer blocks, directly linked integer regions and budgeted checked RAM loops,
with a per-user persistent compilation cache. Normal x87 add/subtract/multiply/divide use generated integer code with
80-bit results and x87 rounding semantics. Bounded floating blocks keep register
state in SSA across arithmetic, stack operations and certified raw 80-bit RAM
loads/stores. The CPU owns checked memory operands and exception
delivery; generated code computes only owned values and flags. Other instructions
retain checked interpreter execution.
Use `--cpu-engine interpreter` to disable JIT, `--no-jit-cache` to disable disk
persistence, and `--jit-stats` to inspect the
active CPU's counters. See [the JIT execution contract](crates/jit/README.md)
for supported instructions, cache ownership and validation limits.

GDI.308 (`GetOutlineTextMetrics`) currently supports MM_TEXT through a bounded modern Unicode GDI query. The 114-byte Win16 layout, relative 16-bit name offsets, partial-prefix copies, low-byte name projection, query size, and rounded stored size were checked against the Windows 3.1 SDK header and static debug-binary evidence ([SDK disk image](https://diskettes.pcjs.org/pcx86/sdk/windows/3.10/WIN31SDK-DISK02.json)). This is limited compatibility evidence, not a clean-room claim or proof of equivalence across fonts, locales, drivers, or mapping modes. Modern per-field checked narrowing, a bounded native allocation, and transactional output are deliberate safety adaptations: unsupported mapping modes, unrepresentable fields/sizes, malformed names, and invalid declared guest buffer capacities are rejected without output. Original debug buffer poisoning, 16-bit overflow, and divide faults are not reproduced. No original binary was executed for this comparison. Existing third-party notices remain applicable.

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

### 可选的 PGO 优化

PGO 使用固定的 Rust 1.99.0，需要对应 Windows 架构的分析运行库及同一工具链中的 `llvm-tools-preview`；项目本地工具链的安装命令和完整流程见上方 [PGO 说明](#optional-profile-guided-optimization)。使用 `build.ps1 -Pgo generate` 生成四个插桩文件，再通过 `pgo.ps1 -Action Collect` 运行实际 DOS / Win16 工作负载，正常退出后执行 `-Action Merge`，最后使用 `build.ps1 -Pgo use` 构建。

ARM64 与 AMD64 的数据分别收集。脚本检查源码、编译设置、工具链、架构及文件校验值，拒绝过期或不兼容的数据；辅助进程继承收集设置，未实际执行的入口会明确提示。插桩文件和数据位于 `target/pgo`，普通或优化发行包位于 `dist`。原生收集是否成功、程序是否正常运行及性能是否改善仍需实际测量。

分析工具只用于开发阶段。最终优化包保留普通构建的 Windows 目标和 CPU 基线，运行时兼容基线为 Windows 10 22H2；目标系统上的运行确认与编译检查分别进行。LLVM 的 Windows 分析写入器使用 ANSI 路径，收集所用的仓库路径需能由系统代码页表示。

### 安装与还原

编译完成后，在**管理员 PowerShell**中执行：

```powershell
.\scripts\install.ps1
```

安装脚本复制当前架构的运行时，并添加自己的 Windows 旧程序启动入口。卸载时只撤销安装记录中未被修改的文件和设置，保留其他软件的设置及额外文件：

```powershell
.\scripts\uninstall.ps1
```

ARM64 包包含与运行时一起构建的系统启动组件 `system/ntvdm64.dll`。安装脚本仅在系统缺少该模块时添加它，并记录哈希以供卸载。文件名和导出名遵循 Windows 启动接口；该组件属于 Compat16。

双击启动需要 Windows 提供旧程序启动回调。微软记录 Windows 10 ARM 不包含 `NtVdm64` 机制；后续 ARM64 版本的接口可用性和行为需实机核验。直接调用启动器不依赖系统集成。[微软说明](https://learn.microsoft.com/zh-cn/windows/win32/winprog64/application-installation)

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
