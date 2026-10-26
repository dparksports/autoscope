// F# port of Core\Services\TcpConnectionTable.cs (namespace
// AutoScope.Services). Behavioral faithfulness is the contract: one
// GetExtendedTcpTable syscall per family, same struct layouts, same
// endpoint string shapes ("ip:port" v4, "[addr]:port" v6), same
// non-routable filter — callers (svchost monitor, connect watchers, PID
// inquiries) feed these rows straight into row attribution.
//
// F# port notes (deviations forced by F#, none behavioral):
//   • C# `public static class` with a nested record → an F# module, so the
//     Row type and the two private marshaling structs stay NESTED exactly
//     as in C# (TcpConnectionTable+Row is the same symbol from either
//     language). Modules compile to static classes.
//   • Row is an F# record: from C# it has the same six read-only
//     properties, the same all-fields constructor, and structural
//     equality — but no ToString/Deconstruct of the C# positional record.
//     No caller pattern-matches or deconstructs it today (verified by
//     grep); if one appears, promote Row to a class with Deconstruct.

namespace AutoScope.Engines.Watch

open System
open System.Collections.Generic
open System.Net
open System.Net.Sockets
open System.Runtime.InteropServices

/// <summary>
/// Atomic enumeration of established TCP connections with their owning PID,
/// via the IP Helper API (GetExtendedTcpTable) — both address families. One
/// syscall per family returns the whole table at a single kernel instant: no
/// child process, no text to parse, microseconds of skew (this replaced
/// spawning netstat.exe, which also never showed IPv6 rows on some builds —
/// a held [::1] connection was invisible to every sampled view while the
/// kernel had it all along). Destination strings are bare addresses;
/// endpoints are "ip:port" for IPv4 and "[addr]:port" for IPv6, matching
/// netstat's display convention.
/// </summary>
module TcpConnectionTable =

    // F# port of the C# nested `public sealed record Row(...)`: same six
    // properties in the same order, structural equality, one constructor.
    type Row =
        { LocalEndPoint: string
          RemoteEndPoint: string
          RemoteIp: string
          RemotePort: int
          Pid: int
          IsIpv6: bool }

    let private afInet = 2 // AF_INET
    let private afInet6 = 23 // AF_INET6
    let private tcpTableOwnerPidAll = 5 // TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL
    let private mibTcpStateEstablished = 5u
    let private errorInsufficientBuffer = 122u

    // F# port: C# had these private nested inside the static class; F#
    module private Interop =

        [<Struct; StructLayout(LayoutKind.Sequential)>]
        type MIB_TCPROW_OWNER_PID =
            val State: uint32
            val LocalAddr: uint32
            val LocalPort: uint32 // network byte order in the low two bytes
            val RemoteAddr: uint32
            val RemotePort: uint32 // network byte order in the low two bytes
            val OwningPid: uint32

        [<Struct; StructLayout(LayoutKind.Sequential)>]
        type MIB_TCP6ROW_OWNER_PID =
            [<MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)>]
            val LocalAddr: byte[]

            val LocalScopeId: uint32
            val LocalPort: uint32 // network byte order in the low two bytes
            [<MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)>]
            val RemoteAddr: byte[]

            val RemoteScopeId: uint32
            val RemotePort: uint32 // network byte order in the low two bytes
            val State: uint32
            val OwningPid: uint32

        [<DllImport("iphlpapi.dll")>]
        extern uint32 GetExtendedTcpTable(
            nativeint pTcpTable,
            int& dwOutBufLen,
            bool bOrder,
            int ulAf,
            int tableClass,
            uint32 reserved)

    // The DWORD carries the port in network byte order: swap the low two bytes.
    // (Parens are load-bearing: F# <<< binds LOWER than |||.)
    let private port (networkOrder: uint32) : int =
        int (((networkOrder &&& 0xFFu) <<< 8) ||| ((networkOrder >>> 8) &&& 0xFFu))

    let private getEstablishedV4() : ResizeArray<Row> =
        let rows = ResizeArray<Row>()
        let mutable size = 0

        if
            Interop.GetExtendedTcpTable(IntPtr.Zero, &size, false, afInet, tcpTableOwnerPidAll, 0u)
            <> errorInsufficientBuffer
            || size < 4
        then
            rows
        else
            let buffer = Marshal.AllocHGlobal size

            try
                if
                    Interop.GetExtendedTcpTable(buffer, &size, false, afInet, tcpTableOwnerPidAll, 0u)
                    <> 0u
                then
                    rows
                else
                    let count = Marshal.ReadInt32 buffer
                    let rowSize = Marshal.SizeOf<Interop.MIB_TCPROW_OWNER_PID>()

                    for i = 0 to count - 1 do
                        let row =
                            Marshal.PtrToStructure<Interop.MIB_TCPROW_OWNER_PID>(
                                buffer + nativeint 4 + nativeint (i * rowSize)
                            )

                        if row.State <> mibTcpStateEstablished then ()
                        else
                            // F# port: `new IPAddress(uint)` relies on C#'s
                            // implicit uint→long zero-extension; F# makes it explicit.
                            let localIp = IPAddress(int64 row.LocalAddr)
                            let remoteIp = IPAddress(int64 row.RemoteAddr)

                            rows.Add
                                { LocalEndPoint = $"{localIp}:{port row.LocalPort}"
                                  RemoteEndPoint = $"{remoteIp}:{port row.RemotePort}"
                                  RemoteIp = remoteIp.ToString()
                                  RemotePort = port row.RemotePort
                                  Pid = int row.OwningPid
                                  IsIpv6 = false }

                    rows
            finally
                Marshal.FreeHGlobal buffer

    let private getEstablishedV6() : ResizeArray<Row> =
        let rows = ResizeArray<Row>()
        let mutable size = 0

        if
            Interop.GetExtendedTcpTable(IntPtr.Zero, &size, false, afInet6, tcpTableOwnerPidAll, 0u)
            <> errorInsufficientBuffer
            || size < 4
        then
            rows
        else
            let buffer = Marshal.AllocHGlobal size

            try
                if
                    Interop.GetExtendedTcpTable(buffer, &size, false, afInet6, tcpTableOwnerPidAll, 0u)
                    <> 0u
                then
                    rows
                else
                    let count = Marshal.ReadInt32 buffer
                    let rowSize = Marshal.SizeOf<Interop.MIB_TCP6ROW_OWNER_PID>()

                    for i = 0 to count - 1 do
                        let row =
                            Marshal.PtrToStructure<Interop.MIB_TCP6ROW_OWNER_PID>(
                                buffer + nativeint 4 + nativeint (i * rowSize)
                            )

                        if row.State <> mibTcpStateEstablished then ()
                        else
                            let localIp = IPAddress row.LocalAddr
                            let remoteIp = IPAddress row.RemoteAddr

                            rows.Add
                                { LocalEndPoint = $"[{localIp}]:{port row.LocalPort}"
                                  RemoteEndPoint = $"[{remoteIp}]:{port row.RemotePort}"
                                  RemoteIp = remoteIp.ToString()
                                  RemotePort = port row.RemotePort
                                  Pid = int row.OwningPid
                                  IsIpv6 = true }

                    rows
            finally
                Marshal.FreeHGlobal buffer

    /// <summary>
    /// All ESTABLISHED TCP rows, IPv4 and IPv6, including loopback (filtering
    /// is the caller's policy, same as with netstat output). Empty on any
    /// failure — callers degrade exactly the way they did when the netstat
    /// spawn failed.
    /// </summary>
    let GetEstablished() : ResizeArray<Row> =
        let rows = ResizeArray<Row>()
        rows.AddRange(getEstablishedV4 ())
        rows.AddRange(getEstablishedV6 ())
        rows

    /// <summary>
    /// True for destinations a monitor row should not be created for: loopback,
    /// link-local, ULA (the IPv6 equivalent of RFC1918), multicast, and
    /// broadcast — both families.
    /// </summary>
    let IsLocalOrNonRoutable(ip: string) : bool =
        if String.IsNullOrEmpty ip then
            true
        else
            // Unparseable or IPv4 string form: fall through to the string
            // checks the app has always used.
            let stringChecks () =
                if ip.StartsWith "127." then true
                elif ip.StartsWith "192.168." || ip.StartsWith "10." then true
                elif ip = "255.255.255.255" then true
                else
                    let parts = ip.Split('.')
                    let mutable hit =
                        parts.Length = 4
                        && parts.[0] = "172"
                        && (match Int32.TryParse parts.[1] with
                            | true, p2 when p2 >= 16 && p2 <= 31 -> true
                            | _ -> false)

                    if
                        not hit
                        && parts.Length = 4
                    then
                        hit <-
                            match Int32.TryParse parts.[0] with
                            | true, p1 when p1 >= 224 && p1 <= 239 -> true
                            | _ -> false

                    hit

            match IPAddress.TryParse ip with
            | true, addr when addr.AddressFamily = AddressFamily.InterNetworkV6 ->
                if addr.IsIPv6LinkLocal then true // fe80::/10
                else
                    let b = addr.GetAddressBytes()

                    if b.[0] = 0xFFuy then true // multicast ff00::/8
                    elif (b.[0] &&& 0xFEuy) = 0xFCuy then true // ULA fc00::/7
                    else
                        addr.Equals IPAddress.IPv6Loopback // ::1
                        || addr.Equals IPAddress.IPv6Any
                        || addr.Equals IPAddress.IPv6None
            | true, addr ->

                // 127.0.0.0/8 (IsLoopback covers it)
                if addr.Equals IPAddress.Loopback then true else stringChecks ()
            | _ -> stringChecks ()

