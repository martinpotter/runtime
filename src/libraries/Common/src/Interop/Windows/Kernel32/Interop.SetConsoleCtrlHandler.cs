// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Kernel32
    {
        internal const int CTRL_C_EVENT = 0;
        internal const int CTRL_BREAK_EVENT = 1;
        internal const int CTRL_CLOSE_EVENT = 2;
        internal const int CTRL_LOGOFF_EVENT = 5;
        internal const int CTRL_SHUTDOWN_EVENT = 6;

#if DLLIMPORTGENERATOR_ENABLED
        [GeneratedDllImport(Libraries.Kernel32, SetLastError = true)]
        internal static unsafe partial bool SetConsoleCtrlHandler(delegate* unmanaged<int, BOOL> handler, bool Add);
#else
        [DllImport(Libraries.Kernel32, SetLastError = true)]
        internal static extern unsafe bool SetConsoleCtrlHandler(delegate* unmanaged<int, BOOL> HandlerRoutine, bool Add);
#endif
    }
}
