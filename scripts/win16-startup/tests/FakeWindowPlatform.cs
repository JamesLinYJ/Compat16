using System;

namespace Compat16.PfeProbe {
    public sealed class FakeWindowPlatform : IWindowPlatform {
        public WindowSnapshot[] Windows;
        public bool Reply = true, OwnerBefore = true, OwnerAfter = true;
        public int Sent, OwnerReads;
        public WindowSnapshot[] Snapshot(IntPtr ignored) { return Windows; }
        public bool IsCurrentOwner(IntPtr ignored, WindowSnapshot expected) {
            OwnerReads++;
            return OwnerReads % 2 == 1 ? OwnerBefore : OwnerAfter;
        }
        public bool SendNull(IntPtr window, uint timeout) {
            if (timeout != 1000 || window == IntPtr.Zero || window == new IntPtr(0xffff))
                throw new InvalidOperationException("Unexpected unbounded or broadcast probe.");
            Sent++; return Reply;
        }
    }
}
