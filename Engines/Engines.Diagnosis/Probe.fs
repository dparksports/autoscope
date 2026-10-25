// F# port of Core\Services\SiteProbeService.cs (namespace AutoScope.Services)
// for the Engines library. Behavioral faithfulness is the contract: same
// probe sequence, same caps, same timeouts, same operation log, same
// progress strings — validated by the Site Doctor self-test's live
// loopback section.
//
// F# port notes (deviations forced by F#/C# interop, none behavioral):
//   • Result models are TOP-LEVEL types in this namespace. F# cannot nest
//     type declarations inside a class, so what C# addressed as
//     SiteProbeService.EdgeProbe is, from C#, AutoScope.Engines.Diagnosis
//     EdgeProbe (import the namespace and drop the qualification).
//   • Result models are mutable classes (member val ... with get, set),
//     not F# records: the C# self-test constructs them with object
//     initializers (new EdgeProbe { Ip = ..., TcpConnectMs = 30 }) and
//     nothing anywhere mutates them after construction.
//   • The nullable millisecond fields are Nullable<double>, exactly the
//     C# `double?` (the self-test assigns EdgeProbe.TcpConnectMs straight
//     into ControlProbe.TcpConnectMs, so all ms fields share one type).
//   • Optional parameters use [<Optional; DefaultParameterValue>], not F#
//     `?` optionals — F# optionals surface as FSharpOption<T> in metadata
//     and would be uncallable with the C# source's default-omission
//     shapes (progress: null, omitted cancel, named dnsSampleInterval).
//   • ProbeEdgeAsync/HandshakeAsync are public here (internal in C#):
//     the C# self-test compiled the sources directly into the test
//     assembly; this library is referenced instead, and the F# project
//     declares no InternalsVisibleTo.

// FS3211 fires on every [<Optional; DefaultParameterValue(null)>] below
// ("default value does not have the same type ... will be ignored"), but
// the emitted metadata is exactly what C# needs — every such parameter
// reflects as IsOptional=true with default null (i.e. default(T), the
// same semantics as the C# source's `= null` / `= default`) — verified
// by reflection and by the ported call shapes compiling and running.
#nowarn "3211"

namespace AutoScope.Engines.Diagnosis

open System
open System.Collections.Generic
open System.Net
open System.Net.Security
open System.Net.Sockets
open System.Diagnostics
open System.Runtime.InteropServices
open System.Security.Authentication
open System.Text.RegularExpressions
open System.Threading
open System.Threading.Tasks

// ── result models (JSON-serializable for the MCP tool) ───────────

type DnsSample() =
    member val AtUtc = DateTime() with get, set
    member val Ips = ResizeArray<string>() with get, set
    member val Error: string = null with get, set

type DnsResult() =
    member val Host: string = null with get, set
    member val Samples = ResizeArray<DnsSample>() with get, set
    /// <summary>Distinct addresses across all samples.</summary>
    member val DistinctIps = ResizeArray<string>() with get, set
    /// <summary>True when the answer changed between samples —
    /// short-TTL steering, the "dice roll" refresh pattern.</summary>
    member this.AnswerRotated =
        // F# port: the C# `Samples.Count >= 2 && distinctCount > firstCount`
        // written as a match so Samples[0] is only read after the count
        // guard, exactly like the C# short-circuiting &&.
        match this.Samples with
        | samples when samples.Count >= 2 ->
            let distinctCount =
                samples
                |> Seq.collect (fun s -> match s.Ips with null -> Seq.empty :> seq<_> | ips -> ips :> seq<_>)
                |> Seq.distinct
                |> Seq.length
            let firstCount = if isNull samples[0].Ips then 0 else samples[0].Ips.Count
            distinctCount > firstCount
        | _ -> false
    member this.AnySuccess =
        this.Samples |> Seq.exists (fun s -> not (isNull s.Ips) && s.Ips.Count > 0)

type EdgeProbe() =
    member val Ip: string = null with get, set
    member val Port = 443 with get, set
    /// <summary>TCP connect time in ms; null when the connection itself failed.</summary>
    member val TcpConnectMs = Nullable<double>() with get, set
    member val TcpError: string = null with get, set
    /// <summary>OS-default ClientHello (the shape Windows apps send).</summary>
    member val TlsDefaultMs = Nullable<double>() with get, set
    member val TlsDefaultError: string = null with get, set
    member val TlsDefaultVersion: string = null with get, set
    /// <summary>Plain TLS 1.2-only ClientHello (the comparison shape).</summary>
    member val TlsPlainMs = Nullable<double>() with get, set
    member val TlsPlainError: string = null with get, set
    member val TlsPlainVersion: string = null with get, set

type ControlProbe() =
    member val Host: string = null with get, set
    member val TcpConnectMs = Nullable<double>() with get, set
    member val TlsMs = Nullable<double>() with get, set
    member val Error: string = null with get, set

type ProbeOperation() =
    member val AtUtc = DateTime() with get, set
    member val Kind: string = null with get, set    // dns · tcp · tls · control
    member val Detail: string = null with get, set  // plain-English one-liner

type SiteProbeReport() =
    member val Host: string = null with get, set
    member val StartedUtc = DateTime() with get, set
    member val EndedUtc = DateTime() with get, set
    member val Dns = DnsResult() with get, set
    member val Edges = ResizeArray<EdgeProbe>() with get, set
    member val Controls = ResizeArray<ControlProbe>() with get, set
    member val Operations = ResizeArray<ProbeOperation>() with get, set

// ── run ───────────────────────────────────────────────────────────

/// <summary>
/// Active probe engine behind the Site Doctor tab. Sends a small,
/// itemized, strictly capped set of connections — every single one is
/// recorded in the report's Operations log, because "what did you send
/// and what came back" is the whole point of the tab. Nothing here
/// blocks, kills, or reconfigures anything; the worst it can do is open
/// a TCP connection and close it.
///
/// Three instruments, each the one that mattered in a real diagnosis:
///
///   • DNS sampler — resolves the same name repeatedly. A name whose
///     answer keeps changing is on short-TTL CDN steering; every browse
///     or refresh is a new dice roll for server quality.
///   • Edge probes — for each server address: TCP connect time, then
///     TWO TLS handshakes with different ClientHello shapes. Windows'
///     default hello (TLS 1.3-era, post-quantum keyshare) and a plain
///     TLS 1.2-only hello. A server that accepts one shape and silently
///     drops the other explains "works in one app, hangs in another" —
///     observed in the wild when a CDN's edges stopped answering
///     default-shaped hellos while a plain hello sailed through.
///   • Control probes — the same handshake against a comparison host,
///     so "your PC and line are fine" is measured, not assumed.
///
/// Caps (enforced, not guidelines): at most 4 edges, 2 handshakes per
/// edge, 5 DNS resolves, 2 controls. ≈21 operations per run.
/// </summary>
type SiteProbeService() =

    static let shared = Lazy<SiteProbeService>(fun () -> SiteProbeService())

    static let hostnamePattern =
        Regex(@"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$",
              RegexOptions.Compiled)

    // F# port: const → plain static members ([<Literal>] is not valid on
    // members); readable from C# with the exact same values.
    static member MaxEdgesPerRun = 4
    static member MaxHandshakesPerEdge = 2
    static member MaxDnsSamples = 5
    static member MaxControlHosts = 2
    static member TcpConnectTimeout = TimeSpan.FromSeconds 4.0
    static member HandshakeTimeout = TimeSpan.FromSeconds 6.0
    static member DnsSampleInterval = TimeSpan.FromSeconds 12.0

    static member Shared = shared.Value

    /// <summary>
    /// One full capped run. extraEdges lets the caller seed known server
    /// addresses (e.g. from the archive fingerprint) alongside what DNS
    /// hands back. progress receives one line per phase for the UI.
    /// </summary>
    member this.RunAsync(
        host: string,
        [<Optional; DefaultParameterValue(null)>] extraEdges: IEnumerable<string>,
        [<Optional; DefaultParameterValue(null)>] controlHosts: IEnumerable<string>,
        [<Optional; DefaultParameterValue(null)>] progress: IProgress<string>,
        [<Optional; DefaultParameterValue(null)>] cancel: CancellationToken,
        [<Optional; DefaultParameterValue(null)>] dnsSampleInterval: Nullable<TimeSpan>) : Task<SiteProbeReport> =
        task {
            let host = (if isNull host then "" else host).Trim().TrimEnd('.')
            if not (hostnamePattern.IsMatch host) &&
               not (match IPAddress.TryParse host with true, _ -> true | _ -> false) then
                raise (ArgumentException(String.Format("'{0}' is not a hostname this tab can probe.", host)))

            let interval =
                if dnsSampleInterval.HasValue then dnsSampleInterval.Value
                else SiteProbeService.DnsSampleInterval

            let report = SiteProbeReport(Host = host, StartedUtc = DateTime.UtcNow)
            let ops = report.Operations

            // F# port: the C# local void Log(kind, detail) closure.
            let log =
                Action<string, string>(fun kind detail ->
                    ops.Add(ProbeOperation(AtUtc = DateTime.UtcNow, Kind = kind, Detail = detail))
                    if not (isNull progress) then progress.Report(detail))

            // Phase A — DNS sampling. GetHostAddressesAsync (not the cached
            // ResolveForwardAsync): rotation is the thing being measured.
            report.Dns.Host <- host
            for i = 0 to SiteProbeService.MaxDnsSamples - 1 do
                cancel.ThrowIfCancellationRequested()
                if i > 0 then do! Task.Delay(interval, cancel)
                let sample = DnsSample(AtUtc = DateTime.UtcNow)
                try
                    let! addrs = Dns.GetHostAddressesAsync(host, cancel)
                    sample.Ips <-
                        ResizeArray<string>(
                            addrs
                            |> Seq.filter (fun a -> a.AddressFamily = AddressFamily.InterNetwork)
                            |> Seq.map (fun a -> a.ToString()))
                    log.Invoke(
                        "dns",
                        String.Format(
                            "DNS sample {0}/{1}: {2} → {3}",
                            i + 1, SiteProbeService.MaxDnsSamples, host,
                            (if sample.Ips.Count > 0 then String.Join(", ", sample.Ips) else "no IPv4 answer")))
                with ex ->
                    sample.Error <- ex.Message
                    log.Invoke(
                        "dns",
                        String.Format(
                            "DNS sample {0}/{1}: {2} failed — {3}",
                            i + 1, SiteProbeService.MaxDnsSamples, host, ex.Message))
                report.Dns.Samples.Add(sample)
            report.Dns.DistinctIps <-
                ResizeArray<string>(
                    report.Dns.Samples
                    |> Seq.collect (fun s -> match s.Ips with null -> Seq.empty :> seq<_> | ips -> ips :> seq<_>)
                    |> Seq.distinct)

            // Phase B — edge probes (DNS answers first, caller-supplied next).
            let edgeQueue = ResizeArray<string>(report.Dns.DistinctIps)
            if not (isNull extraEdges) then
                for edge in extraEdges do
                    if (match IPAddress.TryParse edge with true, _ -> true | _ -> false)
                       && not (edgeQueue.Contains edge) then
                        edgeQueue.Add(edge)

            for ip in Seq.truncate SiteProbeService.MaxEdgesPerRun edgeQueue do
                cancel.ThrowIfCancellationRequested()
                let! edge = this.ProbeEdgeAsync(ip, host, log, cancel, 443)
                report.Edges.Add(edge)

            // Phase C — controls: one default-shape handshake each.
            let controls =
                if isNull controlHosts then ResizeArray<string>() :> seq<string> else controlHosts
            for control in Seq.truncate SiteProbeService.MaxControlHosts controls do
                cancel.ThrowIfCancellationRequested()
                let! controlProbe = this.ProbeControlAsync(control, log, cancel)
                report.Controls.Add(controlProbe)

            report.EndedUtc <- DateTime.UtcNow
            return report
        }

    // ── instruments ───────────────────────────────────────────────────

    /// <summary>internal for the offline self-test, which drives it
    /// against loopback listeners on non-443 ports.
    /// F# port: public (not internal) — see the note at the top of this
    /// file.</summary>
    member this.ProbeEdgeAsync(
        ip: string, host: string, log: Action<string, string>, cancel: CancellationToken,
        [<Optional; DefaultParameterValue(443)>] port: int) : Task<EdgeProbe> =
        task {
            let probe = EdgeProbe(Ip = ip, Port = port)
            let tcp = new TcpClient()
            let sw = Stopwatch.StartNew()
            // F# port: C# returns early from the catch; the task builder
            // needs both branches to agree, so a flag mirrors the flow.
            let mutable tcpFailed = false
            try
                let connect = tcp.ConnectAsync(ip, port, cancel).AsTask()
                let! winner = Task.WhenAny(connect, Task.Delay(SiteProbeService.TcpConnectTimeout, cancel))
                if not (obj.ReferenceEquals(winner, connect)) then
                    raise (TimeoutException(
                        String.Format("no TCP answer in {0:0}ms", SiteProbeService.TcpConnectTimeout.TotalMilliseconds)))
                do! connect
                probe.TcpConnectMs <- Nullable(Math.Round(sw.Elapsed.TotalMilliseconds))
                log.Invoke("tcp", String.Format("TCP {0}:{1} connected in {2:0} ms", ip, port, probe.TcpConnectMs))
            with ex ->
                tcpFailed <- true
                probe.TcpError <- ex.Message
                log.Invoke("tcp", String.Format("TCP {0}:{1} FAILED — {2}", ip, port, ex.Message))
                tcp.Dispose()
            if tcpFailed then
                return probe
            else
                // Two hello shapes, each on its own connection so one cannot
                // poison the other's session state.
                let! struct (defaultMs, defaultError, defaultVersion) = this.HandshakeAsync(ip, host, false, log, cancel, port)
                probe.TlsDefaultMs <- defaultMs
                probe.TlsDefaultError <- defaultError
                probe.TlsDefaultVersion <- defaultVersion
                let! struct (plainMs, plainError, plainVersion) = this.HandshakeAsync(ip, host, true, log, cancel, port)
                probe.TlsPlainMs <- plainMs
                probe.TlsPlainError <- plainError
                probe.TlsPlainVersion <- plainVersion

                tcp.Dispose()
                return probe
        }

    /// <summary>
    /// One TLS handshake. Certificates are deliberately NOT validated —
    /// the probe measures transport behavior (does the server answer
    /// this hello shape at all), not identity; no credentials ever flow.
    /// </summary>
    member this.HandshakeAsync(
        ip: string, host: string, plainShape: bool, log: Action<string, string>, cancel: CancellationToken,
        [<Optional; DefaultParameterValue(443)>] port: int) : Task<struct (Nullable<double> * string * string)> =
        task {
            let shapeName = if plainShape then "plain TLS 1.2 hello" else "Windows default hello"
            let tcp = new TcpClient()
            let sw = Stopwatch.StartNew()
            try
                try
                    let connect = tcp.ConnectAsync(ip, port, cancel).AsTask()
                    let! winner = Task.WhenAny(connect, Task.Delay(SiteProbeService.TcpConnectTimeout, cancel))
                    if not (obj.ReferenceEquals(winner, connect)) then
                        raise (TimeoutException "no TCP answer")
                    do! connect

                    let stream = tcp.GetStream()
                    stream.ReadTimeout <- int SiteProbeService.HandshakeTimeout.TotalMilliseconds
                    stream.WriteTimeout <- int SiteProbeService.HandshakeTimeout.TotalMilliseconds
                    let ssl = new SslStream(stream, false, fun _ _ _ _ -> true)

                    let handshake =
                        if plainShape then ssl.AuthenticateAsClientAsync(host, null, SslProtocols.Tls12, false)
                        else ssl.AuthenticateAsClientAsync(host, null, SslProtocols.None, false)

                    let! handshakeWinner = Task.WhenAny(handshake, Task.Delay(SiteProbeService.HandshakeTimeout, cancel))
                    if not (obj.ReferenceEquals(handshakeWinner, handshake)) then
                        raise (TimeoutException(
                            String.Format(
                                "server never answered the handshake ({0:0}ms)",
                                SiteProbeService.HandshakeTimeout.TotalMilliseconds)))
                    do! handshake

                    let ms = Math.Round(sw.Elapsed.TotalMilliseconds)
                    let version = ssl.SslProtocol.ToString()
                    // F# port: ":443" is hardcoded in the C# success line
                    // (even when probing a non-443 port, as the loopback
                    // self-test does) — preserved verbatim.
                    log.Invoke("tls", String.Format("TLS {0} {1}:443 → {2} in {3:0} ms", shapeName, ip, version, ms))
                    ssl.Dispose()
                    return struct (Nullable ms, null, version)
                with ex ->
                    let msg = if isNull ex.InnerException then ex.Message else ex.InnerException.Message
                    log.Invoke("tls", String.Format("TLS {0} {1}:{2} FAILED — {3}", shapeName, ip, port, msg))
                    return struct (Nullable<double>(), msg, null)
            finally
                tcp.Dispose()
                sw.Stop()
        }

    member private this.ProbeControlAsync(host: string, log: Action<string, string>, cancel: CancellationToken) : Task<ControlProbe> =
        task {
            let result = ControlProbe(Host = host)
            try
                let! addrs = Dns.GetHostAddressesAsync(host, cancel)
                let ip =
                    match Array.tryFind (fun (a: IPAddress) -> a.AddressFamily = AddressFamily.InterNetwork) addrs with
                    | Some a -> a
                    | None -> match Array.tryHead addrs with Some a -> a | None -> null
                if isNull ip then
                    raise (SocketException(int SocketError.HostNotFound))

                let tcp = new TcpClient()
                let sw = Stopwatch.StartNew()
                let connect = tcp.ConnectAsync(ip, 443, cancel).AsTask()
                let! winner = Task.WhenAny(connect, Task.Delay(SiteProbeService.TcpConnectTimeout, cancel))
                if not (obj.ReferenceEquals(winner, connect)) then
                    raise (TimeoutException "no TCP answer")
                do! connect
                result.TcpConnectMs <- Nullable(Math.Round(sw.Elapsed.TotalMilliseconds))

                let stream = tcp.GetStream()
                stream.ReadTimeout <- int SiteProbeService.HandshakeTimeout.TotalMilliseconds
                let ssl = new SslStream(stream, false, fun _ _ _ _ -> true)
                let handshake = ssl.AuthenticateAsClientAsync(host, null, SslProtocols.None, false)
                let! handshakeWinner = Task.WhenAny(handshake, Task.Delay(SiteProbeService.HandshakeTimeout, cancel))
                if not (obj.ReferenceEquals(handshakeWinner, handshake)) then
                    raise (TimeoutException "control handshake timed out")
                do! handshake
                result.TlsMs <- Nullable(Math.Round(sw.Elapsed.TotalMilliseconds))
                ssl.Dispose()
                tcp.Dispose()

                log.Invoke(
                    "control",
                    String.Format(
                        "Control {0} → TCP {1:0} ms, TLS {2:0} ms (healthy line = fast control)",
                        host, result.TcpConnectMs, result.TlsMs))
            with ex ->
                let msg = if isNull ex.InnerException then ex.Message else ex.InnerException.Message
                result.Error <- msg
                log.Invoke("control", String.Format("Control {0} FAILED — {1}", host, result.Error))
            return result
        }
