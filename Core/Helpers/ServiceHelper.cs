using System;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Diagnostics;

namespace AutoScope.Helpers
{
    /// <summary>
    /// Native service management — replaces PowerShell Set-Service -StartupType.
    /// Uses advapi32 P/Invoke for ChangeServiceConfig.
    /// </summary>
    public static class ServiceHelper
    {
        private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
        private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
        private const uint SERVICE_CHANGE_CONFIG = 0x0002;
        private const uint SERVICE_QUERY_CONFIG = 0x0001;

        // Start types
        public const uint SERVICE_AUTO_START = 2;
        public const uint SERVICE_DEMAND_START = 3; // Manual
        public const uint SERVICE_DISABLED = 4;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenService(IntPtr hSCManager, string serviceName, uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool ChangeServiceConfig(
            IntPtr hService,
            uint dwServiceType,
            uint dwStartType,
            uint dwErrorControl,
            string lpBinaryPathName,
            string lpLoadOrderGroup,
            IntPtr lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword,
            string lpDisplayName);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        /// <summary>
        /// Set service startup type using native API.
        /// </summary>
        public static bool SetStartupType(string serviceName, uint startType)
        {
            IntPtr scManager = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;
            try
            {
                scManager = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
                if (scManager == IntPtr.Zero) return false;

                service = OpenService(scManager, serviceName, SERVICE_CHANGE_CONFIG);
                if (service == IntPtr.Zero) return false;

                return ChangeServiceConfig(
                    service,
                    SERVICE_NO_CHANGE,
                    startType,
                    SERVICE_NO_CHANGE,
                    null, null, IntPtr.Zero, null, null, null, null);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"ServiceHelper Error: {ex.Message}");
                return false;
            }
            finally
            {
                if (service != IntPtr.Zero) CloseServiceHandle(service);
                if (scManager != IntPtr.Zero) CloseServiceHandle(scManager);
            }
        }

        /// <summary>
        /// Stop and disable a service.
        /// </summary>
        public static void StopAndDisable(string serviceName)
        {
            try
            {
                using (var sc = new ServiceController(serviceName))
                {
                    if (sc.Status != ServiceControllerStatus.Stopped)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
                    }
                }
            }
            catch { }
            SetStartupType(serviceName, SERVICE_DISABLED);
        }

        /// <summary>
        /// Enable (manual) and start a service.
        /// </summary>
        public static void EnableAndStart(string serviceName)
        {
            SetStartupType(serviceName, SERVICE_DEMAND_START);
            try
            {
                using (var sc = new ServiceController(serviceName))
                {
                    if (sc.Status == ServiceControllerStatus.Stopped)
                    {
                        sc.Start();
                    }
                }
            }
            catch { }
        }

        /// <summary>
        /// Get the current start mode of a service via WMI.
        /// </summary>
        public static string GetStartMode(string serviceName)
        {
            try
            {
                using (var service = new System.Management.ManagementObject(
                    new System.Management.ManagementPath($"Win32_Service.Name='{serviceName}'")))
                {
                    return service["StartMode"]?.ToString() ?? "Unknown";
                }
            }
            catch
            {
                return "Unknown";
            }
        }
    }
}

