// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

internal static partial class Interop
{
    internal static partial class Advapi32
    {
#if DLLIMPORTGENERATOR_ENABLED
        [GeneratedDllImport(Interop.Libraries.Advapi32, SetLastError = true)]
        internal static partial bool OpenThreadToken(
#else
        [DllImport(Interop.Libraries.Advapi32, SetLastError = true)]
        internal static extern bool OpenThreadToken(
#endif
            IntPtr ThreadHandle,
            TokenAccessLevels dwDesiredAccess,
            bool bOpenAsSelf,
            out SafeTokenHandle phThreadToken);
    }
}
