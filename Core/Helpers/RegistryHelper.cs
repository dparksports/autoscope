using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;
using AutoScope.Models;

namespace AutoScope.Helpers
{
    public static class RegistryHelper
    {
        // ── LSA & UAC Hardening ──
        
        public static bool GetLsaProtectionStatus()
        {
            try
            {
                object value = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 0);
                return value != null && Convert.ToInt32(value) == 1;
            }
            catch { return false; }
        }

        public static void SetLsaProtectionStatus(bool enable)
        {
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", enable ? 1 : 0, RegistryValueKind.DWord);
        }

        public static bool GetUacStrictness()
        {
            try
            {
                object lua = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 0);
                object consent = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 0);
                
                return (lua != null && Convert.ToInt32(lua) == 1) && 
                       (consent != null && Convert.ToInt32(consent) == 2);
            }
            catch { return false; }
        }

        public static void SetUacStrictness(bool strict)
        {
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1, RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", strict ? 2 : 5, RegistryValueKind.DWord);
        }

        // ── IPv6 Hardening ──
        public static bool GetIpv6DisabledStatus()
        {
            try
            {
                object value = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisabledComponents", 0);
                // 0xFF (255) means disabled all IPv6 components
                return value != null && Convert.ToInt32(value) == 255;
            }
            catch { return false; }
        }

        public static void SetIpv6DisabledStatus(bool disable)
        {
            // 0xFF to disable, 0 to re-enable default behavior
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisabledComponents", disable ? 0xFF : 0x00, RegistryValueKind.DWord);
        }

        // ── Startup Persistence ──

        public static List<StartupItem> GetStartupItems()
        {
            var items = new List<StartupItem>();

            // 1. HKCU Run
            GetRegistryStartupItems(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run", items);
            // 2. HKLM Run
            GetRegistryStartupItems(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run", items);
            
            // 3. Current User Startup Folder
            GetFolderStartupItems(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "User Startup", items);
            // 4. Common Startup Folder
            GetFolderStartupItems(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Common Startup", items);

            return items;
        }

        private static void GetRegistryStartupItems(RegistryKey rootKey, string subKeyPath, string locationName, List<StartupItem> items)
        {
            try
            {
                using (RegistryKey key = rootKey.OpenSubKey(subKeyPath))
                {
                    if (key != null)
                    {
                        foreach (string valueName in key.GetValueNames())
                        {
                            object value = key.GetValue(valueName);
                            items.Add(new StartupItem
                            {
                                Name = valueName,
                                Value = value?.ToString() ?? "",
                                Location = locationName,
                                TargetPath = subKeyPath
                            });
                        }
                    }
                }
            }
            catch { }
        }

        private static void GetFolderStartupItems(string folderPath, string locationName, List<StartupItem> items)
        {
            try
            {
                if (Directory.Exists(folderPath))
                {
                    foreach (string file in Directory.GetFiles(folderPath))
                    {
                        items.Add(new StartupItem
                        {
                            Name = Path.GetFileName(file),
                            Value = file,
                            Location = locationName,
                            TargetPath = folderPath
                        });
                    }
                }
            }
            catch { }
        }

        public static void DeleteStartupItem(StartupItem item)
        {
            try
            {
                if (item.Location.Contains("Run"))
                {
                    RegistryKey root = item.Location.StartsWith("HKLM") ? Registry.LocalMachine : Registry.CurrentUser;
                    using (RegistryKey key = root.OpenSubKey(item.TargetPath, writable: true))
                    {
                        if (key != null)
                        {
                            key.DeleteValue(item.Name, throwOnMissingValue: false);
                        }
                    }
                }
                else if (item.Location.Contains("Startup"))
                {
                    if (File.Exists(item.Value))
                    {
                        File.Delete(item.Value);
                    }
                }
            }
            catch { }
        }
    }
}
