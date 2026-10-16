// Noninteractive, exact-job window observation for the original Win16 fixture.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Compat16.PfeProbe {
    public struct WindowSnapshot {
        public IntPtr Window;
        public uint ProcessId, ThreadId, Style;
        public bool Owned, Visible, Enabled, HasOwner, HasCaption, Dialog, Iconic, Nonempty;
        public bool IsFrame {
            get { return Window != IntPtr.Zero && Owned && Visible && Enabled && HasCaption &&
                Nonempty && !HasOwner && !Dialog && !Iconic && (Style & 0xc0000000u) == 0; }
        }
        public bool SameIdentity(WindowSnapshot other) {
            return Window == other.Window && ProcessId == other.ProcessId && ThreadId == other.ThreadId;
        }
    }
    public interface IWindowPlatform {
        WindowSnapshot[] Snapshot(IntPtr job);
        bool IsCurrentOwner(IntPtr job, WindowSnapshot expected);
        bool SendNull(IntPtr window, uint timeoutMilliseconds);
    }
    public sealed class NullProbeReceipt {
        public long StartSequence, EndSequence, ElapsedMilliseconds;
        public bool Completed;
    }
    public sealed class WindowReadiness {
        readonly IWindowPlatform platform;
        WindowSnapshot candidate;
        long stableSince, lastProbe;
        public readonly List<NullProbeReceipt> Probes = new List<NullProbeReceipt>();
        public string Failure;
        public int VisibleFrameCount, VisibleDialogCount;
        public WindowReadiness() : this(new NativeWindowPlatform()) { }
        public WindowReadiness(IWindowPlatform platform) { this.platform = platform; }
        public int Observe(IntPtr job, long elapsedMilliseconds, bool getMessageSeen, Func<long> sequence) {
            if (Failure != null) return -1;
            if (Probes.Count == 2) return 1;
            if (!getMessageSeen) return 0;
            WindowSnapshot[] windows = platform.Snapshot(job);
            VisibleFrameCount = 0; VisibleDialogCount = 0;
            WindowSnapshot selected = new WindowSnapshot();
            foreach (WindowSnapshot window in windows) {
                if (window.Owned && window.Visible && window.Dialog) VisibleDialogCount++;
                if (!window.IsFrame) continue;
                VisibleFrameCount++;
                if (selected.Window == IntPtr.Zero || window.SameIdentity(candidate)) selected = window;
            }
            if (VisibleDialogCount != 0 || selected.Window == IntPtr.Zero) {
                if (Probes.Count != 0) { Failure = "window-or-modal-state-changed"; return -1; }
                candidate = new WindowSnapshot(); return 0;
            }
            if (!selected.SameIdentity(candidate)) {
                if (Probes.Count != 0) { Failure = "window-owner-changed"; return -1; }
                candidate = selected; stableSince = elapsedMilliseconds; return 0;
            }
            if (elapsedMilliseconds - stableSince < 500 || elapsedMilliseconds - lastProbe < 500) return 0;
            if (!platform.IsCurrentOwner(job, candidate)) { Failure = "window-owner-lost"; return -1; }
            long start = sequence();
            if (start < 0) return 0;
            var timer = Stopwatch.StartNew();
            // WM_NULL has no operation. The timeout bounds this exact window;
            // no broadcast or interactive keyboard/mouse input is involved.
            bool replied = platform.SendNull(candidate.Window, 1000);
            timer.Stop();
            bool retained = platform.IsCurrentOwner(job, candidate);
            Thread.Sleep(50); // allow complete trace rows to become observable
            var receipt = new NullProbeReceipt { StartSequence = start, EndSequence = sequence(),
                ElapsedMilliseconds = timer.ElapsedMilliseconds, Completed = replied && retained };
            Probes.Add(receipt); lastProbe = elapsedMilliseconds;
            if (!receipt.Completed) { Failure = "window-null-message-failed"; return -1; }
            return Probes.Count == 2 ? 1 : 0;
        }
    }
    public sealed class NativeWindowPlatform : IWindowPlatform {
        delegate bool EnumWindow(IntPtr window, IntPtr parameter);
        [StructLayout(LayoutKind.Sequential)] struct Rect { public int Left, Top, Right, Bottom; }
        [DllImport("user32.dll", SetLastError=true)] static extern bool EnumWindows(EnumWindow callback, IntPtr parameter);
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
        [DllImport("user32.dll")] static extern bool IsWindowEnabled(IntPtr window);
        [DllImport("user32.dll")] static extern bool IsIconic(IntPtr window);
        [DllImport("user32.dll")] static extern IntPtr GetWindow(IntPtr window, uint command);
        [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowLongW(IntPtr window, int index);
        [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowTextLengthW(IntPtr window);
        [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassNameW(IntPtr window, StringBuilder text, int capacity);
        [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr window, out Rect rect);
        [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr SendMessageTimeoutW(IntPtr window, uint message,
            UIntPtr wParam, IntPtr lParam, uint flags, uint timeout, out UIntPtr result);
        [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        static bool Owned(IntPtr job, uint processId) {
            if (job == IntPtr.Zero || processId == 0) return false;
            IntPtr process = OpenProcess(0x1000, false, processId); // query-limited only
            if (process == IntPtr.Zero) return false;
            try { bool owned; return IsProcessInJob(process, job, out owned) && owned; }
            finally { CloseHandle(process); }
        }
        static WindowSnapshot Describe(IntPtr job, IntPtr window) {
            uint process; uint thread = GetWindowThreadProcessId(window, out process);
            var result = new WindowSnapshot { Window = window, ProcessId = process, ThreadId = thread };
            result.Owned = thread != 0 && Owned(job, process);
            if (!result.Owned) return result;
            result.Visible = IsWindowVisible(window); result.Enabled = IsWindowEnabled(window);
            result.HasOwner = GetWindow(window, 4) != IntPtr.Zero; // GW_OWNER
            result.HasCaption = GetWindowTextLengthW(window) > 0;
            result.Style = unchecked((uint)GetWindowLongW(window, -16));
            result.Iconic = IsIconic(window);
            var name = new StringBuilder(256);
            result.Dialog = GetClassNameW(window, name, name.Capacity) != 0 && name.ToString() == "#32770";
            Rect rect; result.Nonempty = GetWindowRect(window, out rect) && rect.Right > rect.Left && rect.Bottom > rect.Top;
            return result;
        }
        public WindowSnapshot[] Snapshot(IntPtr job) {
            var windows = new List<WindowSnapshot>();
            if (!EnumWindows(delegate(IntPtr window, IntPtr ignored) {
                if (IsWindowVisible(window)) windows.Add(Describe(job, window));
                return true;
            }, IntPtr.Zero)) throw new InvalidOperationException("Could not enumerate fixture windows.");
            return windows.ToArray();
        }
        public bool IsCurrentOwner(IntPtr job, WindowSnapshot expected) {
            WindowSnapshot current = Describe(job, expected.Window);
            return current.IsFrame && current.SameIdentity(expected);
        }
        public bool SendNull(IntPtr window, uint timeoutMilliseconds) {
            UIntPtr ignored;
            // BLOCK | ABORTIFHUNG | ERRORONEXIT. HWND is never HWND_BROADCAST.
            return window != IntPtr.Zero && window != new IntPtr(0xffff) &&
                SendMessageTimeoutW(window, 0, UIntPtr.Zero, IntPtr.Zero, 0x23, timeoutMilliseconds, out ignored) != IntPtr.Zero;
        }
    }
}
