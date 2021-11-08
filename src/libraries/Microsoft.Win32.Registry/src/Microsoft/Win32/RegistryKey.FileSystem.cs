// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Win32.SafeHandles;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Security;
using System.Threading;

#nullable disable warnings
#pragma warning disable SA1400, SA1028, SA1000, SA1001, SA1121, CS0168, CS0649

namespace Microsoft.Win32
{
    public sealed partial class RegistryKey : MarshalByRefObject, IDisposable
    {
        private RegistryHive? _hive;

        internal static bool IsEquals(RegistryKey a, RegistryKey b)
        {
            return a._hkey == b._hkey && a._keyName == b._keyName  && a._remoteKey == b._remoteKey && a._state == b._state;
        }

        private void ClosePerfDataKey()
        {
            throw new PlatformNotSupportedException(SR.PlatformNotSupported_Registry);
        }

        private void FlushCore()
        {
            KeyHandler self = KeyHandler.Lookup(this, false);
            if (self == null) {
                // we do not need to flush changes as key is marked for deletion
                return;
            }
            self.Flush();
        }

        private RegistryKey CreateSubKeyInternalCore(string subkey, RegistryKeyPermissionCheck permissionCheck, RegistryOptions registryOptions)
        {
            return CreateSubKey(this, subkey, true, registryOptions == RegistryOptions.Volatile);
        }

        private void DeleteSubKeyCore(string subkey, bool throwOnMissingSubKey)
        {
            KeyHandler self = KeyHandler.Lookup(this, true);
            if (self == null) {
                // key is marked for deletion
                if (!throwOnMissingSubKey)
                    return;
                throw new ArgumentException("the given value does not exist");
            }

            string dir = Path.Combine(self.Dir, ToUnix(subkey));
            
            if (!KeyHandler.Delete(dir) && throwOnMissingSubKey)
                throw new ArgumentException("the given value does not exist");
        }

        private void DeleteSubKeyTreeCore(string subkey)
        {
            throw new PlatformNotSupportedException(SR.PlatformNotSupported_Registry);
        }

        private void DeleteValueCore(string name, bool throwOnMissingValue)
        {
            KeyHandler self = KeyHandler.Lookup(this, true);
            if (self == null) {
                // if key is marked for deletion, report success regardless of
                // throwOnMissingValue
                return;
            }

            if (throwOnMissingValue && !self.ValueExists(name))
                throw new ArgumentException ("the given value does not exist");

            self.RemoveValue(name);
        }

        private static RegistryKey OpenBaseKeyCore(RegistryHive hKeyHive, RegistryView view)
        {
            IntPtr hKey = (IntPtr)((int)hKeyHive);

            int index = ((int)hKey) & 0x0FFFFFFF;
            Debug.Assert(index >= 0 && index < s_hkeyNames.Length, "index is out of range!");
            Debug.Assert((((int)hKey) & 0xFFFFFFF0) == 0x80000000, "Invalid hkey value!");

            bool isPerf = hKey == HKEY_PERFORMANCE_DATA;

            // only mark the SafeHandle as ownsHandle if the key is HKEY_PERFORMANCE_DATA.
            SafeRegistryHandle srh = new SafeRegistryHandle(hKey, isPerf);

            RegistryKey key = new RegistryKey(srh, true, true, false, isPerf, view);
            key._checkMode = RegistryKeyPermissionCheck.Default;
            key._keyName = s_hkeyNames[index];
            key._hive = hKeyHive;

            return key;
        }

        private static RegistryKey OpenRemoteBaseKeyCore(RegistryHive hKey, string machineName, RegistryView view)
        {
            throw new PlatformNotSupportedException(SR.Security_RegistryPermission); // remote stores not supported on Unix
        }

        private RegistryKey InternalOpenSubKeyCore(string name, RegistryKeyPermissionCheck permissionCheck, int rights)
        {
            return InternalOpenSubKeyWithoutSecurityChecksCore(name, permissionCheck == RegistryKeyPermissionCheck.ReadWriteSubTree);
        }

        private RegistryKey InternalOpenSubKeyCore(string name, bool writable)
        {
            var key = InternalOpenSubKeyWithoutSecurityChecksCore(name, writable);
            return key;
        }

        private static string ToUnix(string keyname)
        {
            if (keyname.IndexOf ('\\') != -1)
                keyname = keyname.Replace ('\\', '/');
            return keyname.ToLower();
        }

        private static bool IsWellKnownKey(string parentKeyName, string keyname)
        {
            // FIXME: Add more keys if needed
            if (parentKeyName == Registry.CurrentUser.Name ||
                parentKeyName == Registry.LocalMachine.Name)
                return (0 == String.Compare("software", keyname, true, CultureInfo.InvariantCulture));

            return false;
        }

        internal RegistryKey InternalOpenSubKeyWithoutSecurityChecksCore(string name, bool writable)
        {
            KeyHandler self = KeyHandler.Lookup(this, true);
            if (self == null) {
                // return null if parent is marked for deletion
                return null;
            }

            RegistryKey result = self.Probe(this, ToUnix(name), writable);
            if (result == null && IsWellKnownKey(this.Name, name)) {
                // create the subkey even if its parent was opened read-only
                result = CreateSubKey(this, name, writable);
            }

            return result;
        }

        private SafeRegistryHandle SystemKeyHandle
        {
            get
            {
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_Registry);
            }
        }

        private int InternalSubKeyCountCore()
        {
            KeyHandler self = KeyHandler.Lookup(this, true);
            if (self == null)
                throw RegistryKey.CreateMarkedForDeletionException();

            return self.GetSubKeyCount();
        }

        private string[] InternalGetSubKeyNamesCore(int subkeys)
        {
            KeyHandler self = KeyHandler.Lookup(this, true);
            return self.GetSubKeyNames();
        }

        private int InternalValueCountCore()
        {
            KeyHandler self = KeyHandler.Lookup(this, true);
            if (self == null)
                throw RegistryKey.CreateMarkedForDeletionException();

            return self.ValueCount;
        }

        private string[] GetValueNamesCore(int values)
        {
            KeyHandler self = KeyHandler.Lookup(this, true);
            if (self == null)
                throw RegistryKey.CreateMarkedForDeletionException ();
            return self.GetValueNames();
        }

        private object InternalGetValueCore(string? name, object? defaultValue, bool doNotExpand)
        {
            KeyHandler self = KeyHandler.Lookup(this, true);
            if (self == null) {
                // key was removed since it was opened
                return defaultValue;
            }

            if (self.ValueExists(name))
                return self.GetValue(name, doNotExpand);
            return defaultValue;            
        }

        private RegistryValueKind GetValueKindCore(string? name)
        {
            KeyHandler self = KeyHandler.Lookup(this, true);
            if (self != null) 
                return self.GetValueKind(name);

            // key was removed since it was opened or it does not exist.
            return RegistryValueKind.Unknown;            
        }

        private void SetValueCore(string? name, object value, RegistryValueKind valueKind)
        {
            KeyHandler self = KeyHandler.Lookup(this, true);
            if (self == null)
                throw RegistryKey.CreateMarkedForDeletionException();
            self.SetValue(name, value);
        }

        private static int GetRegistryKeyAccess(bool isWritable)
        {
            throw new PlatformNotSupportedException(SR.PlatformNotSupported_Registry);
        }

        private static int GetRegistryKeyAccess(RegistryKeyPermissionCheck mode)
        {
            throw new PlatformNotSupportedException(SR.PlatformNotSupported_Registry);
        }

        private RegistryKey CreateSubKey(RegistryKey rkey, string keyname, bool writable)
        {
            return CreateSubKey(rkey, keyname, writable, false);
        }

        private RegistryKey CreateSubKey(RegistryKey rkey, string keyname, bool writable, bool is_volatile)
        {
            KeyHandler self = KeyHandler.Lookup(rkey, true);
            if (self == null){
                throw RegistryKey.CreateMarkedForDeletionException();
            }
            if (KeyHandler.VolatileKeyExists(self.Dir) && !is_volatile)
                throw new IOException("Cannot create a non volatile subkey under a volatile key.");

            return self.Ensure(rkey, ToUnix(keyname), writable, is_volatile);
        }

        private static IOException CreateMarkedForDeletionException()
        {
            return new IOException("Illegal operation attempted on a registry key that has been marked for deletion.");
        }

        class ExpandString
        {
            string value;
            
            public ExpandString (string s)
            {
                value = s;
            }

            public override string ToString ()
            {
                return value;
            }

            public string Expand ()
            {
                StringBuilder sb = new StringBuilder ();

                for (int i = 0; i < value.Length; i++){
                    if (value [i] == '%'){
                        int j = i + 1;
                        for (; j < value.Length; j++){
                            if (value [j] == '%'){
                                string key = value.Substring (i + 1, j - i - 1);

                                sb.Append (Environment.GetEnvironmentVariable (key));
                                i += j;
                                break;
                            }
                        }
                        if (j == value.Length){
                            sb.Append ('%');
                        }
                    } else {
                        sb.Append (value [i]);
                    }
                }
                return sb.ToString ();
            }
        }
        
        class RegistryKeyComparer : IEqualityComparer
        {
            public new bool Equals(object? x, object? y)
            {
                return RegistryKey.IsEquals ((RegistryKey?) x, (RegistryKey?) y);
                
            }

            public int GetHashCode(object obj)
            {
                var n = ((RegistryKey) obj).Name;
                if (n == null)
                    return 0;
                return n.GetHashCode ();
            }
        }

        class KeyHandler
        {
            static Hashtable key_to_handler = new Hashtable (new RegistryKeyComparer ());
            static Hashtable dir_to_handler = new Hashtable (StringComparer.InvariantCultureIgnoreCase);
            const string VolatileDirectoryName = "volatile-keys";

            public string Dir;
            string? ActualDir; // Lets keep this one private.
            public bool IsVolatile;

            Hashtable values;
            string? file;
            bool dirty;

            static KeyHandler ()
            {
                CleanVolatileKeys ();
            }

            KeyHandler (RegistryKey rkey, string basedir) : this (rkey, basedir, false)
            {
            }

            KeyHandler (RegistryKey rkey, string basedir, bool is_volatile)
            {
                // Force ourselved to reuse the key, if any.
                string volatile_basedir = GetVolatileDir (basedir);
                string actual_basedir = basedir;

                if (Directory.Exists (basedir))
                    is_volatile = false;
                else if (Directory.Exists (volatile_basedir)) {
                    actual_basedir = volatile_basedir;
                    is_volatile = true;
                } else if (is_volatile)
                    actual_basedir = volatile_basedir;

                if (!Directory.Exists (actual_basedir)) {
                    try {
                        Directory.CreateDirectory (actual_basedir);
                    } catch (UnauthorizedAccessException ex){
                        throw new SecurityException ("No access to the given key", ex);
                    }
                }
                Dir = basedir; // This is our identifier.
                ActualDir = actual_basedir; // This our actual location.
                IsVolatile = is_volatile;
                file = Path.Combine (ActualDir, "values.xml");
                Load ();
            }

            public void Load ()
            {
                values = new Hashtable ();
                if (!File.Exists (file))
                    return;
                
                try {
                    using (FileStream fs = File.OpenRead (file)){
                        StreamReader r = new StreamReader (fs);
                        string xml = r.ReadToEnd ();
                        if (xml.Length == 0)
                            return;
                        
                        SecurityParser sp = new SecurityParser();
                        sp.LoadXml(xml);
                        SecurityElement tree = sp.ToXml();
                        if (tree.Tag == "values" && tree.Children != null){
                            foreach (SecurityElement value in tree.Children){
                                if (value.Tag == "value"){
                                    LoadKey (value);
                                }
                            }
                        }
                    }
                } catch (UnauthorizedAccessException){
                    values.Clear ();
                    throw new SecurityException ("No access to the given key");
                } catch (Exception e){
                    values.Clear ();
                    throw;
                }
            }

            void LoadKey (SecurityElement se)
            {
                Hashtable h = se.Attributes;
                if (h == null)
                    return;

                try {
                    string? name = (string?) h ["name"];
                    if (name == null)
                        return;
                    string? type = (string?) h ["type"];
                    if (type == null)
                        return;
                    
                    switch (type){
                    case "int":
                        values [name] = Int32.Parse (se.Text);
                        break;
                    case "bytearray":
                        values [name] = Convert.FromBase64String (se.Text);
                        break;
                    case "string":
                        values [name] = se.Text == null ? String.Empty : se.Text;
                        break;
                    case "expand":
                        values [name] = new ExpandString (se.Text);
                        break;
                    case "qword":
                        values [name] = Int64.Parse (se.Text);
                        break;
                    case "string-array":
                        var sa = new List<string> ();
                        if (se.Children != null){
                            foreach (SecurityElement stre in se.Children){
                                sa.Add (stre.Text);
                            }
                        }
                        values [name] = sa.ToArray ();
                        break;
                    }
                } catch {
                    // We ignore individual errors in the file.
                }
            }

            public RegistryKey Ensure (RegistryKey rkey, string extra, bool writable)
            {
                return Ensure (rkey, extra, writable, false);
            }

            // 'is_volatile' is used only if the key hasn't been created already.
            public RegistryKey Ensure (RegistryKey rkey, string extra, bool writable, bool is_volatile)
            {
                // lock (typeof (KeyHandler)){
                    string f = Path.Combine (Dir, extra);
                    KeyHandler kh = (KeyHandler) dir_to_handler [f];
                    if (kh == null)
                        kh = new KeyHandler (rkey, f, is_volatile);

                    RegistryKey key = new RegistryKey(rkey._hkey, writable, false, rkey._remoteKey, false, rkey._regView);
                    key._checkMode = RegistryKeyPermissionCheck.Default;
                    key._keyName = CombineName(rkey, extra);

                    key_to_handler [key] = kh;
                    dir_to_handler [f] = kh;
                    return key;
                // }
            }

            public RegistryKey Probe (RegistryKey rkey, string extra, bool writable)
            {
                RegistryKey key = null;

                // lock (typeof (KeyHandler)){
                    string f = Path.Combine (Dir, extra);
                    KeyHandler kh = (KeyHandler) dir_to_handler [f];
                    if (kh != null) {
                        key = new RegistryKey(rkey._hkey, writable, false, rkey._remoteKey, false, rkey._regView);
                        key._checkMode = RegistryKeyPermissionCheck.Default;
                        key._keyName = CombineName(rkey, extra);

                        key_to_handler [key] = kh;
                    } else if (Directory.Exists (f) || VolatileKeyExists (f)) {
                        kh = new KeyHandler (rkey, f);
                        key = new RegistryKey(rkey._hkey, writable, false, rkey._remoteKey, false, rkey._regView);
                        key._checkMode = RegistryKeyPermissionCheck.Default;
                        key._keyName = CombineName(rkey, extra);

                        dir_to_handler [f] = kh;
                        key_to_handler [key] = kh;
                    }
                    return key;
                // }
            }

            static string CombineName (RegistryKey rkey, string extra)
            {
                if (extra.IndexOf ('/') != -1)
                    extra = extra.Replace ('/', '\\');
                
                return String.Concat (rkey.Name, "\\", extra);
            }

            static long GetSystemBootTime ()
            {
                if (!File.Exists ("/proc/stat"))
                    return -1;

                string btime = null;
                string line;

                try {
                    using (StreamReader stat_file = new StreamReader ("/proc/stat", Encoding.ASCII)) {
                        while ((line = stat_file.ReadLine ()) != null)
                            if (line.StartsWith ("btime")) {
                                btime = line;
                                break;
                            }
                    }
                } catch (Exception e) {
                    // Console.Error.WriteLine ("While reading system info {0}", e);
                }

                if (btime == null)
                    return -1;

                int space = btime.IndexOf (' ');
                long res;
                if (!Int64.TryParse (btime.AsSpan (space, btime.Length - space), out res))
                    return -1;

                return res;
            }

            // The registered boot time it's a simple line containing the last system btime.
            static long GetRegisteredBootTime (string path)
            {
                if (!File.Exists (path))
                    return -1;

                string line = null;
                try {
                    using (StreamReader reader = new StreamReader (path, Encoding.ASCII))
                        line = reader.ReadLine ();
                } catch (Exception e) {
                    // Console.Error.WriteLine ("While reading registry data at {0}: {1}", path, e);
                }

                if (line == null)
                    return -1;

                long res;
                if (!Int64.TryParse (line, out res))
                    return -1;

                return res;
            }

            static void SaveRegisteredBootTime (string path, long btime)
            {
                try {
                    using (StreamWriter writer = new StreamWriter (path, false, Encoding.ASCII))
                        writer.WriteLine (btime.ToString ());
                } catch (Exception) {
                    /* This can happen when a user process tries to write to MachineStore */
                    //Console.Error.WriteLine ("While saving registry data at {0}: {1}", path, e);
                }
            }
                
            // We save the last boot time in a last-btime file in every root, and we use it
            // to clean the volatile keys directory in case the system btime changed.
            static void CleanVolatileKeys ()
            {
                long system_btime = GetSystemBootTime ();

                string [] roots = new string [] {
                    UserStore                 
                };

                foreach (string root in roots) {
                    if (!Directory.Exists (root))
                        continue;

                    string btime_file = Path.Combine (root, "last-btime");
                    string volatile_dir = Path.Combine (root, VolatileDirectoryName);

                    if (Directory.Exists (volatile_dir)) {
                        long registered_btime = GetRegisteredBootTime (btime_file);
                        if (system_btime < 0 || registered_btime < 0 || registered_btime != system_btime)
                            Directory.Delete (volatile_dir, true);
                    }

                    SaveRegisteredBootTime (btime_file, system_btime);
                }
            }
        
            public static bool VolatileKeyExists (string dir)
            {
                // lock (typeof (KeyHandler)) {
                    KeyHandler kh = (KeyHandler) dir_to_handler [dir];
                    if (kh != null)
                        return kh.IsVolatile;
                // }

                if (Directory.Exists (dir)) // Non-volatile key exists.
                    return false;

                return Directory.Exists (GetVolatileDir (dir));
            }

            public static string GetVolatileDir (string dir)
            {
                string root = GetRootFromDir (dir);
                string volatile_dir = dir.Replace (root, Path.Combine (root, VolatileDirectoryName));
                return volatile_dir;
            }

            public static KeyHandler Lookup (RegistryKey rkey, bool createNonExisting)
            {
                // lock (typeof (KeyHandler)){
                    KeyHandler k = (KeyHandler) key_to_handler [rkey];
                    if (k != null)
                        return k;

                    // when a non-root key is requested for no keyhandler exist
                    // then that key must have been marked for deletion
                    if (rkey._hive == null || !createNonExisting)
                        return null;

                    RegistryHive x = (RegistryHive) rkey._hive;
                    switch (x){
                    case RegistryHive.CurrentUser:
                        string userDir = Path.Combine (UserStore, x.ToString ());
                        k = new KeyHandler (rkey, userDir);
                        dir_to_handler [userDir] = k;
                        break;
                    case RegistryHive.CurrentConfig:
                    case RegistryHive.ClassesRoot:
                    case RegistryHive.LocalMachine:
                    case RegistryHive.PerformanceData:
                    case RegistryHive.Users:
                        throw new PlatformNotSupportedException(SR.PlatformNotSupported_Registry);
                    default:
                        throw new Exception ("Unknown RegistryHive");
                    }
                    key_to_handler [rkey] = k;
                    return k;
                // }
            }

            static string GetRootFromDir (string dir)
            {
                if (dir.IndexOf (UserStore) > -1)
                    return UserStore;

                throw new Exception ("Could not get root for dir " + dir);
            }

            public static void Drop (RegistryKey rkey)
            {
                // lock (typeof (KeyHandler)) {
                    KeyHandler k = (KeyHandler) key_to_handler [rkey];
                    if (k == null)
                        return;
                    key_to_handler.Remove (rkey);

                    // remove cached KeyHandler if no other keys reference it
                    int refCount = 0;
                    foreach (DictionaryEntry de in key_to_handler)
                        if (de.Value == k)
                            refCount++;
                    if (refCount == 0)
                        dir_to_handler.Remove (k.Dir);
                // }
            }

            public static void Drop (string dir)
            {
                // lock (typeof (KeyHandler)) {
                    KeyHandler kh = (KeyHandler) dir_to_handler [dir];
                    if (kh == null)
                        return;

                    dir_to_handler.Remove (dir);

                    // remove (other) references to keyhandler
                    ArrayList keys = new ArrayList ();
                    foreach (DictionaryEntry de in key_to_handler)
                        if (de.Value == kh)
                            keys.Add (de.Key);

                    foreach (object key in keys)
                        key_to_handler.Remove (key);
                // }
            }

            public static bool Delete (string dir)
            {
                if (!Directory.Exists (dir)) {
                    string volatile_dir = GetVolatileDir (dir);
                    if (!Directory.Exists (volatile_dir))
                        return false;

                    dir = volatile_dir;
                }

                Directory.Delete (dir, true);
                Drop (dir);
                return true;
            }

            public RegistryValueKind GetValueKind (string name)
            {
                if (name == null)
                    return RegistryValueKind.Unknown;
                object value;
                
                // lock (values)
                    value = values [name];
                
                if (value == null)
                    return RegistryValueKind.Unknown;

                if (value is int)
                    return RegistryValueKind.DWord;
                if (value is string [])
                    return RegistryValueKind.MultiString;
                if (value is long)
                    return RegistryValueKind.QWord;
                if (value is byte [])
                    return RegistryValueKind.Binary;
                if (value is string)
                    return RegistryValueKind.String;
                if (value is ExpandString)
                    return RegistryValueKind.ExpandString;
                return RegistryValueKind.Unknown;
            }
            
            public object GetValue (string name, bool doNotExpand)
            {
                if (IsMarkedForDeletion)
                    return null;

                if (name == null)
                    name = string.Empty;
                object value;
                // lock (values)
                    value = values [name];
                ExpandString exp = value as ExpandString;
                if (exp == null)
                    return value;
                if (!doNotExpand)
                    return exp.Expand ();

                return exp.ToString ();
            }

            public void SetValue (string name, object value)
            {
                AssertNotMarkedForDeletion ();

                if (name == null)
                    name = string.Empty;

                // lock (values){
                    // immediately convert non-native registry values to string to avoid
                    // returning it unmodified in calls to UnixRegistryApi.GetValue
                    if (value is int || value is string || value is byte[] || value is string[])
                        values[name] = value;
                    else
                        values[name] = value.ToString ();
                // }
                SetDirty ();
            }

            public string [] GetValueNames ()
            {
                AssertNotMarkedForDeletion ();

                // lock (values){
                    ICollection keys = values.Keys;
                    
                    string [] vals = new string [keys.Count];
                    keys.CopyTo (vals, 0);
                    return vals;
                // }
            }

            public int GetSubKeyCount ()
            {
                return GetSubKeyNames ().Length;
            }

            public string [] GetSubKeyNames ()
            {
                DirectoryInfo selfDir = new DirectoryInfo (ActualDir);
                DirectoryInfo[] subDirs = selfDir.GetDirectories ();
                string[] subKeyNames;

                // for volatile keys (cannot contain non-volatile subkeys) or keys
                // without *any* presence in the volatile key section, we can do it simple.
                if (IsVolatile || !Directory.Exists (GetVolatileDir (Dir))) {
                    subKeyNames = new string[subDirs.Length];
                    for (int i = 0; i < subDirs.Length; i++) {
                        DirectoryInfo subDir = subDirs[i];
                        subKeyNames[i] = subDir.Name;
                    }
                    return subKeyNames;
                }

                // We may have the entries repeated, so keep just one of each one.
                DirectoryInfo volatileDir = new DirectoryInfo (GetVolatileDir (Dir));
                DirectoryInfo [] volatileSubDirs = volatileDir.GetDirectories ();
                Dictionary<string,string> dirs = new Dictionary<string,string> ();

                foreach (DirectoryInfo dir in subDirs)
                    dirs [dir.Name] = dir.Name;
                foreach (DirectoryInfo volDir in volatileSubDirs)
                    dirs [volDir.Name] = volDir.Name;

                subKeyNames = new string [dirs.Count];
                int j = 0;
                foreach (KeyValuePair<string,string> entry in dirs)
                    subKeyNames[j++] = entry.Value;

                return subKeyNames;
            }

            //
            // This version has to do argument validation based on the valueKind
            //
            public void SetValue (string name, object value, RegistryValueKind valueKind)
            {
                SetDirty ();

                if (name == null)
                    name = string.Empty;

                // lock (values){
                    switch (valueKind){
                    case RegistryValueKind.String:
                        if (value is string){
                            values [name] = value;
                            return;
                        }
                        break;
                    case RegistryValueKind.ExpandString:
                        if (value is string){
                            values [name] = new ExpandString ((string)value);
                            return;
                        }
                        break;
                        
                    case RegistryValueKind.Binary:
                        if (value is byte []){
                            values [name] = value;
                            return;
                        }
                        break;
                        
                    case RegistryValueKind.DWord:
                        try {
                            values [name] = Convert.ToInt32 (value);
                            return;
                        } catch (OverflowException) {
                            break;
                        }
                        
                    case RegistryValueKind.MultiString:
                        if (value is string []){
                            values [name] = value;
                            return;
                        }
                        break;
                        
                    case RegistryValueKind.QWord:
                        try {
                            values [name] = Convert.ToInt64 (value);
                            return;
                        } catch (OverflowException) {
                            break;
                        }
                        
                    default:
                        throw new ArgumentException ("unknown value", nameof(valueKind));
                    }
                // }
                throw new ArgumentException ("Value could not be converted to specified type", nameof(valueKind));
            }

            void SetDirty ()
            {
                // lock (typeof (KeyHandler)){
                    if (dirty)
                        return;
                    dirty = true;
                    new Timer (DirtyTimeout, null, 3000, Timeout.Infinite);
                // }
            }

            public void DirtyTimeout (object state)
            {
                try {
                    Flush ();
                } catch {
                    // This was identified as a crasher under some scenarios
                    // Internal MS issue: https://devdiv.visualstudio.com/DevDiv/_workitems/edit/787119
                }
            }

            public void Flush ()
            {
                // lock (typeof (KeyHandler)) {
                    if (dirty) {
                        Save ();
                        dirty = false;
                    }
                // }
            }

            public bool ValueExists (string name)
            {
                if (name == null)
                    name = string.Empty;

                // lock (values)
                    return values.Contains (name);
            }

            public int ValueCount {
                get {
                    // lock (values)
                        return values.Keys.Count;
                }
            }

            public bool IsMarkedForDeletion {
                get {
                    return !dir_to_handler.Contains (Dir);
                }
            }

            public void RemoveValue (string name)
            {
                AssertNotMarkedForDeletion ();

                // lock (values)
                    values.Remove (name);
                SetDirty ();
            }

            ~KeyHandler ()
            {
                Flush ();
            }
            
            void Save ()
            {
                if (IsMarkedForDeletion)
                    return;

                SecurityElement se = new SecurityElement ("values");
                    
                // lock (values){
                    if (!File.Exists (file) && values.Count == 0)
                        return;
        
                    // With SecurityElement.Text = value, and SecurityElement.AddAttribute(key, value)
                    // the values must be escaped prior to being assigned. 
                    foreach (DictionaryEntry de in values){
                        object val = de.Value;
                        SecurityElement value = new SecurityElement ("value");
                        value.AddAttribute ("name", SecurityElement.Escape ((string) de.Key));
                        
                        if (val is string){
                            value.AddAttribute ("type", "string");
                            value.Text = SecurityElement.Escape ((string) val);
                        } else if (val is int){
                            value.AddAttribute ("type", "int");
                            value.Text = val.ToString ();
                        } else if (val is long) {
                            value.AddAttribute ("type", "qword");
                            value.Text = val.ToString ();
                        } else if (val is byte []){
                            value.AddAttribute ("type", "bytearray");
                            value.Text = Convert.ToBase64String ((byte[]) val);
                        } else if (val is ExpandString){
                            value.AddAttribute ("type", "expand");
                            value.Text = SecurityElement.Escape (val.ToString ());
                        } else if (val is string []){
                            value.AddAttribute ("type", "string-array");
        
                            foreach (string ss in (string[]) val){
                                SecurityElement str = new SecurityElement ("string");
                                str.Text = SecurityElement.Escape (ss); 
                                value.AddChild (str);
                            }
                        }
                        se.AddChild (value);
                    }
                // }
                
                using (FileStream fs = File.Create (file)){
                    StreamWriter sw = new StreamWriter (fs);

                    sw.Write (se.ToString ());
                    sw.Flush ();
                }
            }

            private void AssertNotMarkedForDeletion ()
            {
                if (IsMarkedForDeletion)
                    throw RegistryKey.CreateMarkedForDeletionException();
            }

            static string? user_store;

            private static string UserStore {
                get {
                    if (user_store == null)
                        user_store = Path.Combine (Environment.GetFolderPath (Environment.SpecialFolder.Personal),
                        ".mono/registry");

                    return user_store;
                }
            }
        }

        class SmallXmlParser
        {
            public interface IContentHandler
            {
                void OnStartParsing (SmallXmlParser parser);
                void OnEndParsing (SmallXmlParser parser);
                void OnStartElement (string name, IAttrList attrs);
                void OnEndElement (string name);
                void OnProcessingInstruction (string name, string text);
                void OnChars (string text);
                void OnIgnorableWhitespace (string text);
            }

            public interface IAttrList
            {
                int Length { get; }
                bool IsEmpty { get; }
                string GetName (int i);
                string GetValue (int i);
                string GetValue (string name);
                string [] Names { get; }
                string [] Values { get; }
            }

            class AttrListImpl : IAttrList
            {
                public int Length {
                    get { return attrNames.Count; }
                }
                public bool IsEmpty {
                    get { return attrNames.Count == 0; }
                }
                public string GetName (int i)
                {
                    return attrNames [i];
                }
                public string GetValue (int i)
                {
                    return attrValues [i];
                }
                public string GetValue (string name)
                {
                    for (int i = 0; i < attrNames.Count; i++)
                        if (attrNames [i] == name)
                            return attrValues [i];
                    return null;
                }
                public string [] Names {
                    get { return attrNames.ToArray (); }
                }
                public string [] Values {
                    get { return attrValues.ToArray (); }
                }

                List<string> attrNames = new List<string> ();
                List<string> attrValues = new List<string> ();

                internal void Clear ()
                {
                    attrNames.Clear ();
                    attrValues.Clear ();
                }

                internal void Add (string name, string value)
                {
                    attrNames.Add (name);
                    attrValues.Add (value);
                }
            }

            IContentHandler handler;
            TextReader reader;
            Stack<string> elementNames = new Stack<string> ();
            Stack<string> xmlSpaces = new Stack<string> ();
            string xmlSpace;
            StringBuilder buffer = new StringBuilder (200);
            char [] nameBuffer = new char [30];
            bool isWhitespace;

            AttrListImpl attributes = new AttrListImpl ();
            int line = 1, column;
            bool resetColumn;

            public SmallXmlParser ()
            {
            }

            private Exception Error (string msg)
            {
                return new SmallXmlParserException (msg, line, column);
            }

            private Exception UnexpectedEndError ()
            {
                string [] arr = new string [elementNames.Count];
                elementNames.CopyTo (arr, 0);
                return Error (String.Format (
                    "Unexpected end of stream. Element stack content is {0}", String.Join (",", arr)));
            }


            private bool IsNameChar (char c, bool start)
            {
                switch (c) {
                case ':':
                case '_':
                    return true;
                case '-':
                case '.':
                    return !start;
                }
                if (c > 0x100) { // optional condition for optimization
                    switch (c) {
                    case '\u0559':
                    case '\u06E5':
                    case '\u06E6':
                        return true;
                    }
                    if ('\u02BB' <= c && c <= '\u02C1')
                        return true;
                }
                switch (Char.GetUnicodeCategory (c)) {
                case UnicodeCategory.LowercaseLetter:
                case UnicodeCategory.UppercaseLetter:
                case UnicodeCategory.OtherLetter:
                case UnicodeCategory.TitlecaseLetter:
                case UnicodeCategory.LetterNumber:
                    return true;
                case UnicodeCategory.SpacingCombiningMark:
                case UnicodeCategory.EnclosingMark:
                case UnicodeCategory.NonSpacingMark:
                case UnicodeCategory.ModifierLetter:
                case UnicodeCategory.DecimalDigitNumber:
                    return !start;
                default:
                    return false;
                }
            }

            private bool IsWhitespace (int c)
            {
                switch (c) {
                case ' ':
                case '\r':
                case '\t':
                case '\n':
                    return true;
                default:
                    return false;
                }
            }


            public void SkipWhitespaces ()
            {
                SkipWhitespaces (false);
            }

            private void HandleWhitespaces ()
            {
                while (IsWhitespace (Peek ()))
                    buffer.Append ((char) Read ());
                if (Peek () != '<' && Peek () >= 0)
                    isWhitespace = false;
            }

            public void SkipWhitespaces (bool expected)
            {
                while (true) {
                    switch (Peek ()) {
                    case ' ':
                    case '\r':
                    case '\t':
                    case '\n':
                        Read ();
                        if (expected)
                            expected = false;
                        continue;
                    }
                    if (expected)
                        throw Error ("Whitespace is expected.");
                    return;
                }
            }


            private int Peek ()
            {
                return reader.Peek ();
            }

            private int Read ()
            {
                int i = reader.Read ();
                if (i == '\n')
                    resetColumn = true;
                if (resetColumn) {
                    line++;
                    resetColumn = false;
                    column = 1;
                }
                else
                    column++;
                return i;
            }

            public void Expect (int c)
            {
                int p = Read ();
                if (p < 0)
                    throw UnexpectedEndError ();
                else if (p != c)
                    throw Error (String.Format ("Expected '{0}' but got {1}", (char) c, (char) p));
            }

            private string ReadUntil (char until, bool handleReferences)
            {
                while (true) {
                    if (Peek () < 0)
                        throw UnexpectedEndError ();
                    char c = (char) Read ();
                    if (c == until)
                        break;
                    else if (handleReferences && c == '&')
                        ReadReference ();
                    else
                        buffer.Append (c);
                }
                string ret = buffer.ToString ();
                buffer.Length = 0;
                return ret;
            }

            public string ReadName ()
            {
                int idx = 0;
                if (Peek () < 0 || !IsNameChar ((char) Peek (), true))
                    throw Error ("XML name start character is expected.");
                for (int i = Peek (); i >= 0; i = Peek ()) {
                    char c = (char) i;
                    if (!IsNameChar (c, false))
                        break;
                    if (idx == nameBuffer.Length) {
                        char [] tmp = new char [idx * 2];
                        Array.Copy (nameBuffer, tmp, idx);
                        nameBuffer = tmp;
                    }
                    nameBuffer [idx++] = c;
                    Read ();
                }
                if (idx == 0)
                    throw Error ("Valid XML name is expected.");
                return new string (nameBuffer, 0, idx);
            }


            public void Parse (TextReader input, IContentHandler handler)
            {
                this.reader = input;
                this.handler = handler;

                handler.OnStartParsing (this);

                while (Peek () >= 0)
                    ReadContent ();
                HandleBufferedContent ();
                if (elementNames.Count > 0)
                    throw Error (String.Format ("Insufficient close tag: {0}", elementNames.Peek ()));

                handler.OnEndParsing (this);

                Cleanup ();
            }

            private void Cleanup ()
            {
                line = 1;
                column = 0;
                handler = null;
                reader = null;
                elementNames.Clear ();
                xmlSpaces.Clear ();
                attributes.Clear ();
                buffer.Length = 0;
                xmlSpace = null;
                isWhitespace = false;
            }

            public void ReadContent ()
            {
                string name;
                if (IsWhitespace (Peek ())) {
                    if (buffer.Length == 0)
                        isWhitespace = true;
                    HandleWhitespaces ();
                }
                if (Peek () == '<') {
                    Read ();
                    switch (Peek ()) {
                    case '!': // declarations
                        Read ();
                        if (Peek () == '[') {
                            Read ();
                            if (ReadName () != "CDATA")
                                throw Error ("Invalid declaration markup");
                            Expect ('[');
                            ReadCDATASection ();
                            return;
                        }
                        else if (Peek () == '-') {
                            ReadComment ();
                            return;
                        }
                        else if (ReadName () != "DOCTYPE")
                            throw Error ("Invalid declaration markup.");
                        else
                            throw Error ("This parser does not support document type.");
                    case '?': // PIs
                        HandleBufferedContent ();
                        Read ();
                        name = ReadName ();
                        SkipWhitespaces ();
                        string text = String.Empty;
                        if (Peek () != '?') {
                            while (true) {
                                text += ReadUntil ('?', false);
                                if (Peek () == '>')
                                    break;
                                text += "?";
                            }
                        }
                        handler.OnProcessingInstruction (
                            name, text);
                        Expect ('>');
                        return;
                    case '/': // end tags
                        HandleBufferedContent ();
                        if (elementNames.Count == 0)
                            throw UnexpectedEndError ();
                        Read ();
                        name = ReadName ();
                        SkipWhitespaces ();
                        string expected = (string) elementNames.Pop ();
                        xmlSpaces.Pop ();
                        if (xmlSpaces.Count > 0)
                            xmlSpace = (string) xmlSpaces.Peek ();
                        else
                            xmlSpace = null;
                        if (name != expected)
                            throw Error (String.Format ("End tag mismatch: expected {0} but found {1}", expected, name));
                        handler.OnEndElement (name);
                        Expect ('>');
                        return;
                    default: // start tags (including empty tags)
                        HandleBufferedContent ();
                        name = ReadName ();
                        while (Peek () != '>' && Peek () != '/')
                            ReadAttribute (attributes);
                        handler.OnStartElement (name, attributes);
                        attributes.Clear ();
                        SkipWhitespaces ();
                        if (Peek () == '/') {
                            Read ();
                            handler.OnEndElement (name);
                        }
                        else {
                            elementNames.Push (name);
                            xmlSpaces.Push (xmlSpace);
                        }
                        Expect ('>');
                        return;
                    }
                }
                else
                    ReadCharacters ();
            }

            private void HandleBufferedContent ()
            {
                if (buffer.Length == 0)
                    return;
                if (isWhitespace)
                    handler.OnIgnorableWhitespace (buffer.ToString ());
                else
                    handler.OnChars (buffer.ToString ());
                buffer.Length = 0;
                isWhitespace = false;
            }

            private void ReadCharacters ()
            {
                isWhitespace = false;
                while (true) {
                    int i = Peek ();
                    switch (i) {
                    case -1:
                        return;
                    case '<':
                        return;
                    case '&':
                        Read ();
                        ReadReference ();
                        continue;
                    default:
                        buffer.Append ((char) Read ());
                        continue;
                    }
                }
            }

            private void ReadReference ()
            {
                if (Peek () == '#') {
                    // character reference
                    Read ();
                    ReadCharacterReference ();
                } else {
                    string name = ReadName ();
                    Expect (';');
                    switch (name) {
                    case "amp":
                        buffer.Append ('&');
                        break;
                    case "quot":
                        buffer.Append ('"');
                        break;
                    case "apos":
                        buffer.Append ('\'');
                        break;
                    case "lt":
                        buffer.Append ('<');
                        break;
                    case "gt":
                        buffer.Append ('>');
                        break;
                    default:
                        throw Error ("General non-predefined entity reference is not supported in this parser.");
                    }
                }
            }

            private int ReadCharacterReference ()
            {
                int n = 0;
                if (Peek () == 'x') { // hex
                    Read ();
                    for (int i = Peek (); i >= 0; i = Peek ()) {
                        if ('0' <= i && i <= '9')
                            n = n << 4 + i - '0';
                        else if ('A' <= i && i <='F')
                            n = n << 4 + i - 'A' + 10;
                        else if ('a' <= i && i <='f')
                            n = n << 4 + i - 'a' + 10;
                        else
                            break;
                        Read ();
                    }
                } else {
                    for (int i = Peek (); i >= 0; i = Peek ()) {
                        if ('0' <= i && i <= '9')
                            n = n << 4 + i - '0';
                        else
                            break;
                        Read ();
                    }
                }
                return n;
            }

            private void ReadAttribute (AttrListImpl a)
            {
                SkipWhitespaces (true);
                if (Peek () == '/' || Peek () == '>')
                    // came here just to spend trailing whitespaces
                    return;

                string name = ReadName ();
                string value;
                SkipWhitespaces ();
                Expect ('=');
                SkipWhitespaces ();
                switch (Read ()) {
                case '\'':
                    value = ReadUntil ('\'', true);
                    break;
                case '"':
                    value = ReadUntil ('"', true);
                    break;
                default:
                    throw Error ("Invalid attribute value markup.");
                }
                if (name == "xml:space")
                    xmlSpace = value;
                a.Add (name, value);
            }

            private void ReadCDATASection ()
            {
                int nBracket = 0;
                while (true) {
                    if (Peek () < 0)
                        throw UnexpectedEndError ();
                    char c = (char) Read ();
                    if (c == ']')
                        nBracket++;
                    else if (c == '>' && nBracket > 1) {
                        for (int i = nBracket; i > 2; i--)
                            buffer.Append (']');
                        break;
                    }
                    else {
                        for (int i = 0; i < nBracket; i++)
                            buffer.Append (']');
                        nBracket = 0;
                        buffer.Append (c);
                    }
                }
            }

            private void ReadComment ()
            {
                Expect ('-');
                Expect ('-');
                while (true) {
                    if (Read () != '-')
                        continue;
                    if (Read () != '-')
                        continue;
                    if (Read () != '>')
                        throw Error ("'--' is not allowed inside comment markup.");
                    break;
                }
            }
        }

        class SmallXmlParserException : SystemException
        {
            int line;
            int column;

            public SmallXmlParserException (string msg, int line, int column)
                : base (String.Format ("{0}. At ({1},{2})", msg, line, column))
            {
                this.line = line;
                this.column = column;
            }

            public int Line {
                get { return line; }
            }

            public int Column {
                get { return column; }
            }
        }

        class SecurityParser : SmallXmlParser, SmallXmlParser.IContentHandler
        {

            private SecurityElement root;

            public SecurityParser () : base () 
            {
                stack = new Stack<SecurityElement> ();
            }

            public void LoadXml (string xml) 
            {
                root = null;
                stack.Clear ();
                Parse (new StringReader (xml), this);
            }

            public SecurityElement ToXml () 
            {
                return root;
            }

            // IContentHandler

            private SecurityElement current;
            private Stack<SecurityElement> stack;

            public void OnStartParsing (SmallXmlParser parser) {}

            public void OnProcessingInstruction (string name, string text) {}

            public void OnIgnorableWhitespace (string s) {}

            public void OnStartElement (string name, SmallXmlParser.IAttrList attrs) 
            {
                SecurityElement newel = new SecurityElement (name); 
                if (root == null) {
                    root = newel;
                    current = newel;
                }
                else {
                    SecurityElement parent = (SecurityElement) stack.Peek ();
                    parent.AddChild (newel);
                }
                stack.Push (newel);
                current = newel;
                // attributes
                int n = attrs.Length;
                for (int i=0; i < n; i++)
                    current.AddAttribute (attrs.GetName (i), SecurityElement.Escape (attrs.GetValue (i)));
            }

            public void OnEndElement (string name) 
            {
                current = (SecurityElement) stack.Pop ();
            }

            public void OnChars (string ch) 
            {
                current.Text = SecurityElement.Escape (ch);
            }

            public void OnEndParsing (SmallXmlParser parser) {}
        }
    }
}
