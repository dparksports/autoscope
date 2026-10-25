using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace AutoScope.Services
{
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
    public sealed class SiteProbeService
    {
        public const int MaxEdgesPerRun = 4;
        public const int MaxHandshakesPerEdge = 2;
        public const int MaxDnsSamples = 5;
        public const int MaxControlHosts = 2;
        public static readonly TimeSpan TcpConnectTimeout = TimeSpan.FromSeconds(4);
        public static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(6);
        public static readonly TimeSpan DnsSampleInterval = TimeSpan.FromSeconds(12);

        private static readonly Regex HostnamePattern = new(
            @"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$",
            RegexOptions.Compiled);

        // ── result models (JSON-serializable for the MCP tool) ───────────

        public sealed class DnsSample
        {
            public DateTime AtUtc { get; set; }
            public List<string> Ips { get; set; } = new();
            public string Error { get; set; }
        }

        public sealed class DnsResult
        {
            public string Host { get; set; }
            public List<DnsSample> Samples { get; set; } = new();
            /// <summary>Distinct addresses across all samples.</summary>
            public List<string> DistinctIps { get; set; } = new();
            /// <summary>True when the answer changed between samples —
            /// short-TTL steering, the "dice roll" refresh pattern.</summary>
            public bool AnswerRotated => Samples.Count >= 2 &&
                                         Samples.SelectMany(s => s.Ips ?? new List<string>())
                                                .Distinct().Count() > (Samples[0].Ips?.Count ?? 0);
            public bool AnySuccess => Samples.Any(s => s.Ips is { Count: > 0 });
        }

        public sealed class EdgeProbe
        {
            public string Ip { get; set; }
            public int Port { get; set; } = 443;
            /// <summary>TCP connect time in ms; null when the connection itself failed.</summary>
            public double? TcpConnectMs { get; set; }
            public string TcpError { get; set; }
            /// <summary>OS-default ClientHello (the shape Windows apps send).</summary>
            public double? TlsDefaultMs { get; set; }
            public string TlsDefaultError { get; set; }
            public string TlsDefaultVersion { get; set; }
            /// <summary>Plain TLS 1.2-only ClientHello (the comparison shape).</summary>
            public double? TlsPlainMs { get; set; }
            public string TlsPlainError { get; set; }
            public string TlsPlainVersion { get; set; }
        }

        public sealed class ControlProbe
        {
            public string Host { get; set; }
            public double? TcpConnectMs { get; set; }
            public double? TlsMs { get; set; }
            public string Error { get; set; }
        }

        public sealed class ProbeOperation
        {
            public DateTime AtUtc { get; set; }
            public string Kind { get; set; }   // dns · tcp · tls · control
            public string Detail { get; set; } // plain-English one-liner
        }

        public sealed class SiteProbeReport
        {
            public string Host { get; set; }
            public DateTime StartedUtc { get; set; }
            public DateTime EndedUtc { get; set; }
            public DnsResult Dns { get; set; } = new();
            public List<EdgeProbe> Edges { get; set; } = new();
            public List<ControlProbe> Controls { get; set; } = new();
            public List<ProbeOperation> Operations { get; set; } = new();
        }

        // ── run ───────────────────────────────────────────────────────────

        private static readonly Lazy<SiteProbeService> _shared = new(() => new SiteProbeService());
        public static SiteProbeService Shared => _shared.Value;

        /// <summary>
        /// One full capped run. extraEdges lets the caller seed known server
        /// addresses (e.g. from the archive fingerprint) alongside what DNS
        /// hands back. progress receives one line per phase for the UI.
        /// </summary>
        public async Task<SiteProbeReport> RunAsync(
            string host,
            IEnumerable<string> extraEdges = null,
            IEnumerable<string> controlHosts = null,
            IProgress<string> progress = null,
            CancellationToken cancel = default,
            TimeSpan? dnsSampleInterval = null)
        {
            host = (host ?? "").Trim().TrimEnd('.');
            if (!HostnamePattern.IsMatch(host) && !IPAddress.TryParse(host, out _))
                throw new ArgumentException($"'{host}' is not a hostname this tab can probe.");

            var report = new SiteProbeReport { Host = host, StartedUtc = DateTime.UtcNow };
            var ops = report.Operations;
            void Log(string kind, string detail)
            {
                ops.Add(new ProbeOperation { AtUtc = DateTime.UtcNow, Kind = kind, Detail = detail });
                progress?.Report(detail);
            }

            // Phase A — DNS sampling. GetHostAddressesAsync (not the cached
            // ResolveForwardAsync): rotation is the thing being measured.
            report.Dns.Host = host;
            for (int i = 0; i < MaxDnsSamples; i++)
            {
                cancel.ThrowIfCancellationRequested();
                if (i > 0) await Task.Delay(dnsSampleInterval ?? DnsSampleInterval, cancel);
                var sample = new DnsSample { AtUtc = DateTime.UtcNow };
                try
                {
                    var addrs = await Dns.GetHostAddressesAsync(host, cancel);
                    sample.Ips = addrs.Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                                      .Select(a => a.ToString())
                                      .ToList();
                    Log("dns", $"DNS sample {i + 1}/{MaxDnsSamples}: {host} → {(sample.Ips.Count > 0 ? string.Join(", ", sample.Ips) : "no IPv4 answer")}");
                }
                catch (Exception ex)
                {
                    sample.Error = ex.Message;
                    Log("dns", $"DNS sample {i + 1}/{MaxDnsSamples}: {host} failed — {ex.Message}");
                }
                report.Dns.Samples.Add(sample);
            }
            report.Dns.DistinctIps = report.Dns.Samples.SelectMany(s => s.Ips ?? new List<string>())
                .Distinct().ToList();

            // Phase B — edge probes (DNS answers first, caller-supplied next).
            var edgeQueue = new List<string>(report.Dns.DistinctIps);
            foreach (var edge in extraEdges ?? Array.Empty<string>())
                if (IPAddress.TryParse(edge, out _) && !edgeQueue.Contains(edge))
                    edgeQueue.Add(edge);

            foreach (var ip in edgeQueue.Take(MaxEdgesPerRun))
            {
                cancel.ThrowIfCancellationRequested();
                report.Edges.Add(await ProbeEdgeAsync(ip, host, Log, cancel));
            }

            // Phase C — controls: one default-shape handshake each.
            foreach (var control in (controlHosts ?? Array.Empty<string>()).Take(MaxControlHosts))
            {
                cancel.ThrowIfCancellationRequested();
                report.Controls.Add(await ProbeControlAsync(control, Log, cancel));
            }

            report.EndedUtc = DateTime.UtcNow;
            return report;
        }

        // ── instruments ───────────────────────────────────────────────────

        /// <summary>internal for the offline self-test, which drives it
        /// against loopback listeners on non-443 ports.</summary>
        internal async Task<EdgeProbe> ProbeEdgeAsync(
            string ip, string host, Action<string, string> log, CancellationToken cancel, int port = 443)
        {
            var probe = new EdgeProbe { Ip = ip, Port = port };
            var tcp = new TcpClient();
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                var connect = tcp.ConnectAsync(ip, port, cancel).AsTask();
                if (await Task.WhenAny(connect, Task.Delay(TcpConnectTimeout, cancel)) != connect)
                    throw new TimeoutException($"no TCP answer in {TcpConnectTimeout.TotalMilliseconds:0}ms");
                await connect;
                probe.TcpConnectMs = Math.Round(sw.Elapsed.TotalMilliseconds);
                log("tcp", $"TCP {ip}:{port} connected in {probe.TcpConnectMs:0} ms");
            }
            catch (Exception ex)
            {
                probe.TcpError = ex.Message;
                log("tcp", $"TCP {ip}:{port} FAILED — {ex.Message}");
                tcp.Dispose();
                return probe;
            }

            // Two hello shapes, each on its own connection so one cannot
            // poison the other's session state.
            (probe.TlsDefaultMs, probe.TlsDefaultError, probe.TlsDefaultVersion) =
                await HandshakeAsync(ip, host, plainShape: false, log, cancel, port);
            (probe.TlsPlainMs, probe.TlsPlainError, probe.TlsPlainVersion) =
                await HandshakeAsync(ip, host, plainShape: true, log, cancel, port);

            tcp.Dispose();
            return probe;
        }

        /// <summary>
        /// One TLS handshake. Certificates are deliberately NOT validated —
        /// the probe measures transport behavior (does the server answer
        /// this hello shape at all), not identity; no credentials ever flow.
        /// </summary>
        internal async Task<(double? ms, string error, string version)> HandshakeAsync(
            string ip, string host, bool plainShape, Action<string, string> log, CancellationToken cancel, int port = 443)
        {
            string shapeName = plainShape ? "plain TLS 1.2 hello" : "Windows default hello";
            var tcp = new TcpClient();
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                var connect = tcp.ConnectAsync(ip, port, cancel).AsTask();
                if (await Task.WhenAny(connect, Task.Delay(TcpConnectTimeout, cancel)) != connect)
                    throw new TimeoutException("no TCP answer");
                await connect;

                var stream = tcp.GetStream();
                stream.ReadTimeout = (int)HandshakeTimeout.TotalMilliseconds;
                stream.WriteTimeout = (int)HandshakeTimeout.TotalMilliseconds;
                var ssl = new SslStream(stream, leaveInnerStreamOpen: false,
                    userCertificateValidationCallback: (_, _, _, _) => true);

                var handshake = plainShape
                    ? ssl.AuthenticateAsClientAsync(host, clientCertificates: null,
                        enabledSslProtocols: SslProtocols.Tls12, checkCertificateRevocation: false)
                    : ssl.AuthenticateAsClientAsync(host, clientCertificates: null,
                        enabledSslProtocols: SslProtocols.None, checkCertificateRevocation: false);

                if (await Task.WhenAny(handshake, Task.Delay(HandshakeTimeout, cancel)) != handshake)
                    throw new TimeoutException($"server never answered the handshake ({HandshakeTimeout.TotalMilliseconds:0}ms)");
                await handshake;

                double ms = Math.Round(sw.Elapsed.TotalMilliseconds);
                string version = ssl.SslProtocol.ToString();
                log("tls", $"TLS {shapeName} {ip}:443 → {version} in {ms:0} ms");
                ssl.Dispose();
                return (ms, null, version);
            }
            catch (Exception ex)
            {
                string msg = ex.InnerException?.Message ?? ex.Message;
                log("tls", $"TLS {shapeName} {ip}:{port} FAILED — {msg}");
                return (null, msg, null);
            }
            finally
            {
                tcp.Dispose();
                sw.Stop();
            }
        }

        private async Task<ControlProbe> ProbeControlAsync(
            string host, Action<string, string> log, CancellationToken cancel)
        {
            var result = new ControlProbe { Host = host };
            try
            {
                var addrs = await Dns.GetHostAddressesAsync(host, cancel);
                var ip = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                         ?? addrs.FirstOrDefault();
                if (ip == null) throw new SocketException((int)SocketError.HostNotFound);

                var tcp = new TcpClient();
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var connect = tcp.ConnectAsync(ip, 443, cancel).AsTask();
                if (await Task.WhenAny(connect, Task.Delay(TcpConnectTimeout, cancel)) != connect)
                    throw new TimeoutException("no TCP answer");
                await connect;
                result.TcpConnectMs = Math.Round(sw.Elapsed.TotalMilliseconds);

                var stream = tcp.GetStream();
                stream.ReadTimeout = (int)HandshakeTimeout.TotalMilliseconds;
                var ssl = new SslStream(stream, false, (_, _, _, _) => true);
                var handshake = ssl.AuthenticateAsClientAsync(host, null, SslProtocols.None, false);
                if (await Task.WhenAny(handshake, Task.Delay(HandshakeTimeout, cancel)) != handshake)
                    throw new TimeoutException("control handshake timed out");
                await handshake;
                result.TlsMs = Math.Round(sw.Elapsed.TotalMilliseconds);
                ssl.Dispose();
                tcp.Dispose();

                log("control", $"Control {host} → TCP {result.TcpConnectMs:0} ms, TLS {result.TlsMs:0} ms (healthy line = fast control)");
            }
            catch (Exception ex)
            {
                result.Error = ex.InnerException?.Message ?? ex.Message;
                log("control", $"Control {host} FAILED — {result.Error}");
            }
            return result;
        }
    }
}
