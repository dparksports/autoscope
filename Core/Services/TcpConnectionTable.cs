using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace AutoScope.Services
{
    /// <summary>
    /// Atomic enumeration of established TCP connections with their owning
    /// PID, via the IP Helper API (GetExtendedTcpTable) — both address
    /// families. One syscall per family returns the whole table at a single
    /// kernel instant: no child process, no text to parse, microseconds of
    /// skew (this replaced spawning netstat.exe, which also never showed
    /// IPv6 rows on some builds — a held [::1] connection was invisible to
    /// every sampled view while the kernel had it all along). Destination
    /// strings are bare addresses; endpoints are "ip:port" for IPv4 and
    /// "[addr]:port" for IPv6, matching netstat's display convention.
    /// </summary>
    public static class TcpConnectionTable
    {
        public sealed record Row(
            string LocalEndPoint, string RemoteEndPoint,
            string RemoteIp, int RemotePort, int Pid, bool IsIpv6);

        private const int AfInet = 2;               // AF_INET
        private const int AfInet6 = 23;             // AF_INET6
        private const int TcpTableOwnerPidAll = 5;  // TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL
        private const uint MibTcpStateEstablished = 5;
        private const uint ErrorInsufficientBuffer = 122;

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint State;
            public uint LocalAddr;
            public uint LocalPort;   // network byte order in the low two bytes
            public uint RemoteAddr;
            public uint RemotePort;  // network byte order in the low two bytes
            public uint OwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddr;
            public uint LocalScopeId;
            public uint LocalPort;   // network byte order in the low two bytes
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] RemoteAddr;
            public uint RemoteScopeId;
            public uint RemotePort;  // network byte order in the low two bytes
            public uint State;
            public uint OwningPid;
        }

        [DllImport("iphlpapi.dll")]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable, ref int dwOutBufLen, bool bOrder,
            int ulAf, int tableClass, uint reserved);

        /// <summary>
        /// All ESTABLISHED TCP rows, IPv4 and IPv6, including loopback
        /// (filtering is the caller's policy, same as with netstat output).
        /// Empty on any failure — callers degrade exactly the way they did
        /// when the netstat spawn failed.
        /// </summary>
        public static List<Row> GetEstablished()
        {
            var rows = new List<Row>();
            rows.AddRange(GetEstablishedV4());
            rows.AddRange(GetEstablishedV6());
            return rows;
        }

        private static List<Row> GetEstablishedV4()
        {
            var rows = new List<Row>();
            int size = 0;
            if (GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidAll, 0) != ErrorInsufficientBuffer || size < 4)
                return rows;

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidAll, 0) != 0)
                    return rows;

                int count = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                for (int i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(
                        buffer + 4 + (nint)(i * rowSize));
                    if (row.State != MibTcpStateEstablished) continue;

                    var localIp = new IPAddress(row.LocalAddr);
                    var remoteIp = new IPAddress(row.RemoteAddr);
                    rows.Add(new Row(
                        $"{localIp}:{Port(row.LocalPort)}",
                        $"{remoteIp}:{Port(row.RemotePort)}",
                        remoteIp.ToString(), Port(row.RemotePort), (int)row.OwningPid, false));
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
            return rows;
        }

        private static List<Row> GetEstablishedV6()
        {
            var rows = new List<Row>();
            int size = 0;
            if (GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet6, TcpTableOwnerPidAll, 0) != ErrorInsufficientBuffer || size < 4)
                return rows;

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(buffer, ref size, false, AfInet6, TcpTableOwnerPidAll, 0) != 0)
                    return rows;

                int count = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
                for (int i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(
                        buffer + 4 + (nint)(i * rowSize));
                    if (row.State != MibTcpStateEstablished) continue;

                    var localIp = new IPAddress(row.LocalAddr);
                    var remoteIp = new IPAddress(row.RemoteAddr);
                    rows.Add(new Row(
                        $"[{localIp}]:{Port(row.LocalPort)}",
                        $"[{remoteIp}]:{Port(row.RemotePort)}",
                        remoteIp.ToString(), Port(row.RemotePort), (int)row.OwningPid, true));
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
            return rows;
        }

        /// <summary>
        /// True for destinations a monitor row should not be created for:
        /// loopback, link-local, ULA (the IPv6 equivalent of RFC1918),
        /// multicast, and broadcast — both families.
        /// </summary>
        public static bool IsLocalOrNonRoutable(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return true;
            if (IPAddress.TryParse(ip, out var addr))
            {
                if (addr.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    if (addr.IsIPv6LinkLocal) return true;                 // fe80::/10
                    var b = addr.GetAddressBytes();
                    if (b[0] == 0xFF) return true;                         // multicast ff00::/8
                    if ((b[0] & 0xFE) == 0xFC) return true;                // ULA fc00::/7
                    return addr.Equals(IPAddress.IPv6Loopback) ||          // ::1
                           addr.Equals(IPAddress.IPv6Any) ||
                           addr.Equals(IPAddress.IPv6None);
                }
                if (addr.Equals(IPAddress.Loopback)) return true;          // 127.0.0.0/8 (IsLoopback covers it)
            }

            // Unparseable or IPv4 string form: fall through to the string
            // checks the app has always used.
            if (ip.StartsWith("127.")) return true;
            if (ip.StartsWith("192.168.") || ip.StartsWith("10.")) return true;
            if (ip == "255.255.255.255") return true;
            var parts = ip.Split('.');
            if (parts.Length == 4 && parts[0] == "172" && int.TryParse(parts[1], out int p2) && p2 >= 16 && p2 <= 31)
                return true;
            if (parts.Length == 4 && int.TryParse(parts[0], out int p1) && p1 >= 224 && p1 <= 239)
                return true;
            return false;
        }

        // The DWORD carries the port in network byte order: swap the low two bytes.
        private static int Port(uint networkOrder) =>
            (int)(((networkOrder & 0xFF) << 8) | ((networkOrder >> 8) & 0xFF));
    }
}
