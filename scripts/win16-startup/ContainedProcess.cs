using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
namespace Compat16.PfeProbe {
    public sealed class Outcome {
        public uint ExitCode; public long ElapsedMilliseconds; public string StopReason;
        public bool ProcessTreeCleaned;
        public bool WindowReadinessObserved;
    }
    public static class ContainedProcess {
        [StructLayout(LayoutKind.Sequential)] struct Security {
            public int Length; public IntPtr Descriptor; public int Inherit;
        }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Startup {
            public int Size; public string Reserved, Desktop, Title;
            public uint X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
            public ushort ShowWindow, ReservedSize; public IntPtr ReservedBytes, Input, Output, Error;
        }
        [StructLayout(LayoutKind.Sequential)] struct StartupEx { public Startup Startup; public IntPtr Attributes; }
        [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }
        [StructLayout(LayoutKind.Sequential)] struct BasicLimit {
            public long ProcessTime, JobTime; public uint Flags;
            public UIntPtr MinimumWorkingSet, MaximumWorkingSet; public uint ActiveProcessLimit;
            public UIntPtr Affinity; public uint PriorityClass, SchedulingClass;
        }
        [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong A, B, C, D, E, F; }
        [StructLayout(LayoutKind.Sequential)] struct ExtendedLimit {
            public BasicLimit Basic; public IoCounters Io;
            public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
        }
        [StructLayout(LayoutKind.Sequential)] struct Accounting {
            public long UserTime, KernelTime, PeriodUserTime, PeriodKernelTime;
            public uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses;
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimit info, uint size);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job, int infoClass, out Accounting info, uint size, IntPtr returned);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateJobObject(IntPtr job, uint code);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr process, uint code);
        [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateFileW(string path, uint access, uint share, ref Security security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
        [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcessW(string app, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory, ref StartupEx startup, out ProcessInfo process);
        static void Check(bool ok, string operation) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), operation); }
        static string Quote(string value) {
            var text = new StringBuilder("\""); int slashes = 0;
            foreach (char c in value) {
                if (c == '\\') { slashes++; continue; }
                text.Append('\\', c == '"' ? slashes * 2 + 1 : slashes); text.Append(c); slashes = 0;
            }
            return text.Append('\\', slashes * 2).Append('"').ToString();
        }
        public static Outcome Run(string executable, string[] args, string directory,
                string[] environment, string[] outputPaths, int timeoutSeconds) {
            return Run(executable, args, directory, environment, outputPaths, timeoutSeconds, null);
        }
        public static Outcome Run(string executable, string[] args, string directory,
                string[] environment, string[] outputPaths, int timeoutSeconds,
                Func<IntPtr, int> readiness) {
            var outcome = new Outcome(); var handles = new List<IntPtr>();
            IntPtr job = IntPtr.Zero, attributes = IntPtr.Zero, handleList = IntPtr.Zero, jobList = IntPtr.Zero, env = IntPtr.Zero;
            var pi = new ProcessInfo(); bool initialized = false, assigned = false;
            var timer = new Stopwatch();
            try {
                job = CreateJobObjectW(IntPtr.Zero, null); Check(job != IntPtr.Zero, "CreateJobObject");
                var limits = new ExtendedLimit();
                limits.Basic.Flags = 0x2000; // KILL_ON_JOB_CLOSE, with neither breakaway flag.
                Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimit>()), "SetInformationJobObject");
                var security = new Security { Length = Marshal.SizeOf<Security>(), Inherit = 1 };
                foreach (string path in new [] { "NUL", outputPaths[0], outputPaths[1] }) {
                    bool input = path == "NUL";
                    IntPtr handle = CreateFileW(path, input ? 0x80000000u : 0x40000000u, 3,
                        ref security, input ? 3u : 1u, 0x80, IntPtr.Zero);
                    Check(handle != new IntPtr(-1), "Create redirected standard handle"); handles.Add(handle);
                }
                IntPtr size = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
                if (size == IntPtr.Zero) throw new InvalidOperationException("No process attribute-list size.");
                attributes = Marshal.AllocHGlobal(size);
                Check(InitializeProcThreadAttributeList(attributes, 2, 0, ref size), "InitializeProcThreadAttributeList"); initialized = true;
                handleList = Marshal.AllocHGlobal(IntPtr.Size * handles.Count);
                for (int i = 0; i < handles.Count; i++) Marshal.WriteIntPtr(handleList, i * IntPtr.Size, handles[i]);
                Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20002), handleList,
                    new IntPtr(IntPtr.Size * handles.Count), IntPtr.Zero, IntPtr.Zero), "Set inherited handle allowlist");
                // PROC_THREAD_ATTRIBUTE_JOB_LIST (Windows 10+): assignment is
                // part of process creation, leaving no uncontained orphan gap.
                jobList = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(jobList, job);
                Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x2000D), jobList,
                    new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero), "Set atomic process job membership");
                Array.Sort(environment, StringComparer.OrdinalIgnoreCase);
                env = Marshal.StringToHGlobalUni(string.Join("\0", environment) + "\0\0");
                var startup = new StartupEx { Attributes = attributes };
                startup.Startup.Size = Marshal.SizeOf<StartupEx>(); startup.Startup.Flags = 0x100;
                startup.Startup.Input = handles[0]; startup.Startup.Output = handles[1]; startup.Startup.Error = handles[2];
                var command = new StringBuilder(Quote(executable));
                foreach (string arg in args) command.Append(' ').Append(Quote(arg));
                // Suspended + Unicode environment + extended startup + no console.
                Check(CreateProcessW(executable, command, IntPtr.Zero, IntPtr.Zero, true,
                    0x08080404, env, directory, ref startup, out pi), "Create suspended launcher");
                assigned = true;
                timer.Start(); Check(ResumeThread(pi.Thread) != uint.MaxValue, "Resume launcher");
                long nextProbe = 3000;
                while (true) {
                    uint wait = WaitForSingleObject(pi.Process, 100);
                    Check(wait != uint.MaxValue, "Wait for launcher");
                    long bytes = 0;
                    foreach (string path in outputPaths) if (File.Exists(path)) bytes += new FileInfo(path).Length;
                    if (bytes > 8 * 1024 * 1024) { outcome.StopReason = "output-limit"; break; }
                    if (wait == 0) { outcome.StopReason = "exited"; break; }
                    if (timer.Elapsed.TotalSeconds >= timeoutSeconds) { outcome.StopReason = "timeout"; break; }
                    if (readiness != null && timer.ElapsedMilliseconds >= nextProbe &&
                            timer.Elapsed.TotalSeconds < timeoutSeconds - 2) {
                        nextProbe = timer.ElapsedMilliseconds + 500;
                        int observed = readiness(job);
                        if (observed > 0) {
                            outcome.WindowReadinessObserved = true;
                            outcome.StopReason = "window-responsive";
                            break;
                        }
                        if (observed < 0) { outcome.StopReason = "window-probe-failed"; break; }
                    }
                }
                outcome.ElapsedMilliseconds = timer.ElapsedMilliseconds;
                if (outcome.StopReason != "exited") Check(TerminateJobObject(job, 125), "Terminate bounded process tree");
                Check(WaitForSingleObject(pi.Process, 5000) == 0, "Wait for terminated launcher");
                Check(GetExitCodeProcess(pi.Process, out outcome.ExitCode), "Get launcher exit code");
            } finally {
                try {
                    if (assigned) {
                        // Also reap helpers left behind after normal launcher exit.
                        Check(TerminateJobObject(job, 125), "Clean up process tree");
                        var cleanup = Stopwatch.StartNew();
                        while (true) {
                            Accounting accounting;
                            Check(QueryInformationJobObject(job, 1, out accounting, (uint)Marshal.SizeOf<Accounting>(), IntPtr.Zero), "Verify process-tree cleanup");
                            if (accounting.ActiveProcesses == 0) { outcome.ProcessTreeCleaned = true; break; }
                            if (cleanup.Elapsed.TotalSeconds >= 5) throw new InvalidOperationException("Process-tree cleanup did not complete.");
                            Thread.Sleep(50);
                        }
                    } else if (pi.Process != IntPtr.Zero) {
                        Check(TerminateProcess(pi.Process, 125), "Terminate unassigned suspended launcher");
                        Check(WaitForSingleObject(pi.Process, 5000) == 0, "Wait for unassigned launcher cleanup");
                    }
                } finally {
                    if (job != IntPtr.Zero) CloseHandle(job); // kill-on-close fallback, including exceptional exits
                    if (pi.Thread != IntPtr.Zero) CloseHandle(pi.Thread);
                    if (pi.Process != IntPtr.Zero) CloseHandle(pi.Process);
                    foreach (IntPtr handle in handles) CloseHandle(handle);
                    if (initialized) DeleteProcThreadAttributeList(attributes);
                    if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
                    if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
                    if (jobList != IntPtr.Zero) Marshal.FreeHGlobal(jobList);
                    if (env != IntPtr.Zero) Marshal.FreeHGlobal(env);
                }
            }
            return outcome;
        }
    }
}
