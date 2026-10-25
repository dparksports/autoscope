using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace AutoScope.Helpers
{
    /// <summary>
    /// Native device removal using SetupAPI P/Invoke.
    /// Ported from DeviceMonitorCS — removes WAN Miniports, WiFi Direct, KDNET adapters.
    /// </summary>
    public static class WanMiniportRemover
    {
        private static readonly Guid NetworkClassGuid = new Guid("4d36e972-e325-11ce-bfc1-08002be10318");
        private const int DIF_REMOVE          = 0x00000005;
        private const int DIF_PROPERTYCHANGE  = 0x00000012;
        private const int DICS_ENABLE         = 0x00000001;
        private const int DICS_DISABLE        = 0x00000002;
        private const int DICS_FLAG_GLOBAL    = 0x00000001;

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVINFO_DATA
        {
            public int cbSize;
            public Guid ClassGuid;
            public uint DevInst;
            public IntPtr Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_PROPCHANGE_PARAMS
        {
            public SP_CLASSINSTALL_HEADER ClassInstallHeader;
            public int StateChange;   // DICS_ENABLE / DICS_DISABLE
            public int Scope;         // DICS_FLAG_GLOBAL
            public int HwProfile;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_CLASSINSTALL_HEADER
        {
            public int cbSize;
            public int InstallFunction;
        }

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern IntPtr SetupDiGetClassDevs(ref Guid ClassGuid, IntPtr Enumerator, IntPtr hwndParent, int Flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInfo(IntPtr DeviceInfoSet, uint MemberIndex, ref SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SetupDiGetDeviceInstanceId(IntPtr DeviceInfoSet, ref SP_DEVINFO_DATA DeviceInfoData, System.Text.StringBuilder DeviceInstanceId, int DeviceInstanceIdSize, out int RequiredSize);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiCallClassInstaller(int InstallFunction, IntPtr DeviceInfoSet, ref SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiSetClassInstallParams(IntPtr DeviceInfoSet, ref SP_DEVINFO_DATA DeviceInfoData, ref SP_PROPCHANGE_PARAMS ClassInstallParams, int ClassInstallParamsSize);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        public static List<string> Execute()          => ExecuteInternal(null,      remove: true);
        public static List<string> RemoveWifiDirect() => ExecuteInternal("MS_VWIFI", remove: true);
        public static List<string> RemoveKdnet()      => ExecuteInternal("KDNIC",    remove: true);

        /// <summary>Permanently removes all SSTP-related WAN Miniport adapters.</summary>
        public static List<string> RemoveSstpMiniports() => ExecuteInternal(null, remove: true, sstpOnly: true);

        /// <summary>
        /// Enables or disables all SSTP-related WAN Miniport adapters without removing them.
        /// Pass <c>enable = false</c> to disable; <c>true</c> to re-enable.
        /// </summary>
        public static List<string> SetSstpMiniportsEnabled(bool enable)
            => ExecuteInternal(null, remove: false, sstpOnly: true, enableDevice: enable);

        private static List<string> ExecuteInternal(
            string specificPattern,
            bool remove       = true,
            bool sstpOnly     = false,
            bool enableDevice = false)
        {
            var results = new List<string>();
            Guid guid = NetworkClassGuid;

            IntPtr hDevInfo = SetupDiGetClassDevs(ref guid, IntPtr.Zero, IntPtr.Zero, 0);
            if (hDevInfo == IntPtr.Zero)
            {
                results.Add("Failed to get device information set.");
                return results;
            }

            try
            {
                SP_DEVINFO_DATA devInfo = new SP_DEVINFO_DATA();
                devInfo.cbSize = Marshal.SizeOf(typeof(SP_DEVINFO_DATA));

                uint index = 0;
                while (SetupDiEnumDeviceInfo(hDevInfo, index, ref devInfo))
                {
                    bool acted = false;
                    string instanceId = GetDeviceInstanceId(hDevInfo, devInfo);

                    bool match = specificPattern != null
                        ? (instanceId != null && instanceId.Contains(specificPattern))
                        : sstpOnly ? IsSstpMiniport(instanceId) : IsWanMiniport(instanceId);

                    if (match)
                    {
                        try
                        {
                            if (remove)
                            {
                                if (SetupDiCallClassInstaller(DIF_REMOVE, hDevInfo, ref devInfo))
                                {
                                    results.Add($"Removed: {instanceId}");
                                    acted = true;
                                }
                                else
                                    results.Add($"Failed to remove: {instanceId} (Error {Marshal.GetLastWin32Error()})");
                            }
                            else
                            {
                                // Enable / Disable using DIF_PROPERTYCHANGE
                                var propParams = new SP_PROPCHANGE_PARAMS
                                {
                                    ClassInstallHeader = new SP_CLASSINSTALL_HEADER
                                    {
                                        cbSize          = Marshal.SizeOf(typeof(SP_CLASSINSTALL_HEADER)),
                                        InstallFunction = DIF_PROPERTYCHANGE
                                    },
                                    StateChange = enableDevice ? DICS_ENABLE : DICS_DISABLE,
                                    Scope       = DICS_FLAG_GLOBAL,
                                    HwProfile   = 0
                                };

                                if (SetupDiSetClassInstallParams(hDevInfo, ref devInfo, ref propParams, Marshal.SizeOf(typeof(SP_PROPCHANGE_PARAMS)))
                                    && SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, ref devInfo))
                                {
                                    results.Add($"{(enableDevice ? "Enabled" : "Disabled")}: {instanceId}");
                                }
                                else
                                    results.Add($"Failed to {(enableDevice ? "enable" : "disable")}: {instanceId} (Error {Marshal.GetLastWin32Error()})");
                            }
                        }
                        catch (Exception ex)
                        {
                            results.Add($"Exception on {instanceId}: {ex.Message}");
                        }
                    }

                    // Only advance index if we didn't remove the device (removal shifts the list)
                    if (remove && acted) { /* stay at same index */ }
                    else index++;
                }
            }
            finally
            {
                SetupDiDestroyDeviceInfoList(hDevInfo);
            }

            return results;
        }

        private static string GetDeviceInstanceId(IntPtr hDevInfo, SP_DEVINFO_DATA devInfo)
        {
            int requiredSize;
            SetupDiGetDeviceInstanceId(hDevInfo, ref devInfo, null, 0, out requiredSize);
            var sb = new System.Text.StringBuilder(requiredSize);
            SetupDiGetDeviceInstanceId(hDevInfo, ref devInfo, sb, requiredSize, out requiredSize);
            return sb.ToString().ToUpper();
        }

        private static bool IsSstpMiniport(string instanceId)
        {
            if (string.IsNullOrEmpty(instanceId)) return false;
            return instanceId.Contains("MS_SSTPMINIPORT")  ||
                   instanceId.Contains("MS_IKEV2MINIPORT") ||
                   instanceId.Contains("MS_L2TPMINIPORT")  ||
                   instanceId.Contains("MS_PPTPMINIPORT")  ||
                   instanceId.Contains("MS_AGILEVPNMINIPORT") ||
                   instanceId.Contains("MS_NDISWANIP")     ||
                   instanceId.Contains("MS_NDISWANIPV6")   ||
                   instanceId.Contains("MS_NDISWANBH")     ||
                   instanceId.Contains("MS_PPPOEMINIPORT");
        }

        private static bool IsWanMiniport(string instanceId)
        {
            if (string.IsNullOrEmpty(instanceId)) return false;
            return instanceId.Contains("MS_L2TPMINIPORT") ||
                   instanceId.Contains("MS_PPTPMINIPORT") ||
                   instanceId.Contains("MS_SSTPMINIPORT") ||
                   instanceId.Contains("MS_IKEV2MINIPORT") ||
                   instanceId.Contains("MS_AGILEVPNMINIPORT") ||
                   instanceId.Contains("MS_NDISWANIP") ||
                   instanceId.Contains("MS_NDISWANIPV6") ||
                   instanceId.Contains("MS_PPPOEMINIPORT") ||
                   instanceId.Contains("MS_NDISWANBH") ||
                   instanceId.Contains("MS_VWIFI") ||
                   instanceId.Contains("KDNIC");
        }
    }
}

