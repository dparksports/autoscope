// F# port of Core\Services\RawSocketSnifferService.cs (namespace
// AutoScope.Services). Behavioral faithfulness is the contract: same
// SIO_RCVALL sockets (v4 primary, v6 best-effort silent), same receive
// timeout loop, same packet→row attribution, same OnError surface the
// svchost monitor subscribes to.
//
// F# port notes (deviations, none behavioral):
//   • The C# constructor takes only the shared tracked-rows dictionary
//     (no DnsResolutionService — the resolver is injected into the row
//     model at the view layer, not into the sniffer); mirrored exactly.
//   • `event Action<string> OnError` is a DelegateEvent publishing the
//     same Action<string> delegate type — C# `svc.OnError += msg => ...`
//     compiles unchanged.

namespace AutoScope.Engines.Watch

open System
open System.Collections.Concurrent
open System.Net
open System.Net.Sockets
open System.Threading
open System.Threading.Tasks

/// <summary>
/// The Process Monitor's traffic sensor: a pair of raw sockets with
/// SIO_RCVALL that watch every packet crossing the NIC and attribute each
/// one to any tracked row by its endpoints (remote as source = receive,
/// remote as destination = transmit).
/// </summary>
type RawSocketSnifferService(trackedIps: ConcurrentDictionary<string, SvchostMonitorItem>) as this =

    let onError = DelegateEvent<Action<string>>()

    let mutable cts: CancellationTokenSource = null
    let mutable mainSocket: Socket = null // IPv4 capture — the primary path
    let mutable v6Socket: Socket = null // IPv6 capture — best-effort companion

    /// <summary>Background capture failure surfaced to the view.</summary>
    [<CLIEvent>]
    member _.OnError = onError.Publish

    member _.Start() : unit =
        cts <- new CancellationTokenSource()

        Task.Run(
            Action(fun () ->
                // F# port: C# try-catch-finally becomes a nested
                // try-finally around try-with (F# has no combined form).
                try
                    try
                        let localIp = RawSocketSnifferService.GetLocalIpAddress()

                        if isNull localIp then
                            onError.Trigger [| box "Could not determine local IP address for raw socket binding." |]
                        else
                            mainSocket <- RawSocketSnifferService.CreateReceiveAllSocket(AddressFamily.InterNetwork, localIp)
                            this.ReceiveLoop(mainSocket, this.ParseIpv4Packet)
                    with
                    | :? SocketException as ex when ex.SocketErrorCode = SocketError.AccessDenied ->
                        onError.Trigger
                            [| box "Raw socket binding failed: Access Denied. Ensure the application is running as Administrator." |]
                    | ex ->
                        onError.Trigger [| box $"Raw socket sniffer error: {ex.Message}" |]
                finally
                    if not (isNull mainSocket) then mainSocket.Close())
        )
        |> ignore

        Task.Run(
            Action(fun () ->
                // IPv6 capture is best-effort: some environments refuse a v6
                // raw socket, and a failure here must not disable the working
                // v4 path (OnError stops the whole monitor), so it stays
                // silent — IPv6 rows then rely on their Sysmon-seeded
                // LastSeen for the "Last Update" column.
                try
                    try
                        let localIp =
                            match RawSocketSnifferService.GetLocalIpv6Address() with
                            | null -> IPAddress.IPv6Any
                            | ip -> ip

                        v6Socket <- RawSocketSnifferService.CreateReceiveAllSocket(AddressFamily.InterNetworkV6, localIp)
                        this.ReceiveLoop(v6Socket, this.ParseIpv6Packet)
                    with _ -> ()
                finally
                    if not (isNull v6Socket) then v6Socket.Close())
        )
        |> ignore

    member _.Stop() : unit =
        if not (isNull cts) then cts.Cancel()

        if not (isNull mainSocket) then mainSocket.Close()
        if not (isNull v6Socket) then v6Socket.Close()

    /// <summary>
    /// Creates a raw socket bound to the given local address with SIO_RCVALL
    /// enabled.
    /// </summary>
    static member private CreateReceiveAllSocket(family: AddressFamily, localIp: IPAddress) : Socket =
        let v4 = family = AddressFamily.InterNetwork

        let socket =
            new Socket(family, SocketType.Raw, (if v4 then ProtocolType.IP else ProtocolType.IPv6))

        socket.Bind(IPEndPoint(localIp, 0))

        socket.SetSocketOption(
            (if v4 then SocketOptionLevel.IP else SocketOptionLevel.IPv6),
            SocketOptionName.HeaderIncluded,
            true
        )

        // RCVALL_ON
        let inValue: byte[] = [| 1uy; 0uy; 0uy; 0uy |]
        let outValue: byte[] = [| 0uy; 0uy; 0uy; 0uy |]
        socket.IOControl(IOControlCode.ReceiveAll, inValue, outValue) |> ignore
        socket

    member private _.ReceiveLoop(socket: Socket, parsePacket: byte[] * int -> unit) : unit =
        let buffer: byte[] = Array.zeroCreate 65535

        // Using a reasonable timeout so we can still check for cancellation periodically
        socket.ReceiveTimeout <- 2000

        // F# port: `while (!_cts.Token.IsCancellationRequested)` with a null
        // guard — C# dereferences the same field, which Stop() leaves non-null
        // after Start(); the guard only covers Start-never-called misuse.
        let mutable keepGoing = true

        while
            (keepGoing
             && not (isNull cts)
             && not cts.Token.IsCancellationRequested) do
            try
                // Blocking call to prevent CPU spinning.
                // ReceiveTimeout ensures it unblocks occasionally to check _cts.
                let bytesRead = socket.Receive buffer

                if bytesRead > 0 then parsePacket (buffer, bytesRead)
            with
            | :? SocketException as ex ->
                // SocketError.TimedOut is expected and normal due to ReceiveTimeout
                if
                    ex.SocketErrorCode <> SocketError.TimedOut
                    && ex.SocketErrorCode <> SocketError.Interrupted
                    && ex.SocketErrorCode <> SocketError.WouldBlock
                then
                    // Log unexpected socket errors if necessary, but keep the loop
                    // running unless it's a critical error (like socket closed)
                    ()
            | :? ObjectDisposedException ->
                // Stop() closed the socket under us — normal shutdown, not an error
                keepGoing <- false

    member private _.ParseIpv4Packet(buffer: byte[], length: int) : unit =
        try
            if length < 20 then
                () // minimum IPv4 header
            else
                // IPv4 header addresses are at offset 12 (src) and 16 (dst)
                this.AttributePacket(
                    IPAddress(ReadOnlySpan<byte>(buffer, 12, 4)),
                    IPAddress(ReadOnlySpan<byte>(buffer, 16, 4)),
                    length
                )
        with _ -> ()

    member private _.ParseIpv6Packet(buffer: byte[], length: int) : unit =
        try
            if length < 40 then
                () // fixed IPv6 header size
            else
                // IPv6 header addresses sit at offset 8 (src) and 24 (dst);
                // they stay put even when extension headers follow
                this.AttributePacket(
                    IPAddress(ReadOnlySpan<byte>(buffer, 8, 16)),
                    IPAddress(ReadOnlySpan<byte>(buffer, 24, 16)),
                    length
                )
        with _ -> ()

    /// <summary>
    /// Attributes one observed packet to any tracked row matching its
    /// endpoints.
    /// </summary>
    member private _.AttributePacket(source: IPAddress, destination: IPAddress, length: int) : unit =
        // Remote IP as source = reply traffic (receive)
        let mutable srcItem = Unchecked.defaultof<SvchostMonitorItem>

        if trackedIps.TryGetValue(source.ToString(), &srcItem) then
            srcItem.RxPackets <- srcItem.RxPackets + 1L
            srcItem.RxBytes <- srcItem.RxBytes + int64 length
            srcItem.LastSeen <- DateTime.UtcNow

        // Remote IP as destination = traffic leaving (transmit)
        let mutable dstItem = Unchecked.defaultof<SvchostMonitorItem>

        if trackedIps.TryGetValue(destination.ToString(), &dstItem) then
            dstItem.TxPackets <- dstItem.TxPackets + 1L
            dstItem.TxBytes <- dstItem.TxBytes + int64 length
            dstItem.LastSeen <- DateTime.UtcNow

    static member private GetLocalIpAddress() : IPAddress =
        try
            use socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, enum<ProtocolType> 0)

            // Connects to a dummy external IP to resolve routing table local IP
            socket.Connect("8.8.8.8", 65530)

            match socket.LocalEndPoint with
            | :? IPEndPoint as endPoint -> endPoint.Address
            | _ -> null
        with _ ->
            // Fallback to DNS
            let host = Dns.GetHostEntry(Dns.GetHostName())

            let picked =
                host.AddressList
                |> Array.tryFind (fun ip -> ip.AddressFamily = AddressFamily.InterNetwork)

            match picked with
            | Some ip -> ip
            | None -> null

    /// <summary>
    /// Local IPv6 address the default route uses, or null when the machine
    /// has no IPv6 connectivity.
    /// </summary>
    static member private GetLocalIpv6Address() : IPAddress =
        try
            use socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, enum<ProtocolType> 0)
            socket.Connect(IPAddress.Parse("2001:4860:4860::8888"), 65530)

            match socket.LocalEndPoint with
            | :? IPEndPoint as endPoint -> endPoint.Address
            | _ -> null
        with _ ->
            null
