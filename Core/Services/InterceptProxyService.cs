using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AutoScope.Models;

namespace AutoScope.Services
{
    /// <summary>
    /// Layer 3: a local TLS-terminating intercept proxy, scoped to ONE pid
    /// per session. Driverless by design — on Windows 11 26H2 the
    /// transparent-redirect route the open-source tools use (WinDivert)
    /// fights HVCI, Smart App Control and the 2026 cross-signing removal,
    /// while the system-proxy route below works everywhere because Windows
    /// services route through WinHTTP:
    ///
    ///   - session installs the loopback proxy as the temporary WinHTTP +
    ///     WinINET proxy (InterceptSystemHooks, journaled + crash-safe)
    ///   - every accepted connection is attributed to its owning PID via
    ///     the kernel TCP table; TARGET traffic is MITM'd (leaf cert from
    ///     the session CA, upstream validated for real — both legs TLS),
    ///     everything else is tunnelled byte-for-byte, untouched
    ///   - decrypted directions are decoded by the same HttpStreamDecoder
    ///     and ingested into the Transmissions tab with status
    ///     "decrypted · intercept"
    ///   - certificate-pinned clients fail loudly; that failure is recorded
    ///     as "refused intercept (pinning)" — a signal, not an error
    ///   - the session is time-boxed (default 15 minutes) and ends by
    ///     itself: proxy settings restored, CA removed from the Root store
    /// </summary>
    public sealed class InterceptProxyService
    {
        public static InterceptProxyService Shared { get; } = new();

        public static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(15);
        private const long TeeCapPerDirection = 8 * 1024 * 1024;

        /// <summary>Session lifecycle + background errors, for the tab's banner.</summary>
        public event Action<string> OnSessionEnded;
        public event Action<string> OnStatus;

        private readonly object _gate = new();
        private TcpListener _listener;
        private CancellationTokenSource _cts;
        private System.Timers.Timer _ttl;
        private readonly HashSet<int> _targetPids = new();
        private string _targetImage;
        private string _targetDisplay;
        private int _port;
        private DateTime _endsAtUtc;
        private readonly List<Socket> _liveSockets = new();
        private bool _running;

        private static readonly string[] SharedHostImages =
            { "svchost.exe", "taskhostw.exe", "runtimebroker.exe", "dllhost.exe", "explorer.exe", "conhost.exe", "csrss.exe" };

        public bool IsRunning { get { lock (_gate) return _running; } }
        public DateTime EndsAtUtc { get { lock (_gate) return _endsAtUtc; } }
        public string TargetDisplay { get { lock (_gate) return _targetDisplay; } }
        public int Port { get { lock (_gate) return _port; } }

        private InterceptProxyService() { }

        // -----------------------------------------------------------------------
        // Session lifecycle
        // -----------------------------------------------------------------------

        /// <summary>Returns an error string on failure, null on success.</summary>
        public string StartSession(int pid, string image, TimeSpan? ttl = null)
        {
            lock (_gate)
            {
                if (_running)
                    return "An intercept session is already active — stop it first.";

                try
                {
                    var ca = InterceptCaService.GetOrCreateCa();
                    InterceptCaService.InstallToRoot();

                    _listener = new TcpListener(IPAddress.Loopback, 0);
                    _listener.Start(64);
                    _port = ((IPEndPoint)_listener.LocalEndpoint).Port;

                    _targetPids.Clear();
                    _targetPids.Add(pid);
                    _targetImage = image;
                    _targetDisplay = $"{Path.GetFileName(image ?? "?")} (PID {pid})";
                    _endsAtUtc = DateTime.UtcNow.Add(ttl ?? DefaultTtl);
                    _cts = new CancellationTokenSource();
                    _running = true;

                    var journal = InterceptSystemHooks.InstallAll(_port, pid, image, ca.Thumbprint);
                    Volatile.Write(ref _journal, journal);

                    _ttl = new System.Timers.Timer((ttl ?? DefaultTtl).TotalMilliseconds) { AutoReset = false };
                    _ttl.Elapsed += (_, _) => StopSession("time-box expired");
                    _ttl.Start();

                    var listener = _listener;
                    _ = Task.Run(() => AcceptLoopAsync(listener, _cts.Token));
                    return null;
                }
                catch (Exception ex)
                {
                    StopSession("startup failed");
                    return $"Intercept session could not start: {ex.Message}";
                }
            }
        }

        private InterceptSystemHooks.Journal _journal;

        public void StopSession(string reason)
        {
            TcpListener listener;
            System.Timers.Timer ttl;
            List<Socket> sockets;
            CancellationTokenSource cts;
            InterceptSystemHooks.Journal journal;

            lock (_gate)
            {
                if (!_running && _listener == null) return;
                listener = _listener;
                ttl = _ttl;
                sockets = new List<Socket>(_liveSockets);
                cts = _cts;
                journal = Volatile.Read(ref _journal);

                _listener = null;
                _ttl = null;
                _cts = null;
                Volatile.Write(ref _journal, null);
                _liveSockets.Clear();
                _targetPids.Clear();
                _targetImage = null;
                _running = false;
            }

            try { listener?.Stop(); } catch { }
            ttl?.Dispose();
            try { cts?.Cancel(); } catch { }
            foreach (var socket in sockets)
            {
                try { socket.Close(); } catch { }
            }

            // Hooks and CA come out AFTER the listener stops, so no client
            // is mid-handshake against a CA that is about to vanish.
            try { InterceptSystemHooks.UndoAll(journal); }
            catch (Exception ex) { OnStatus?.Invoke($"Intercept teardown warning: {ex.Message}"); }

            OnSessionEnded?.Invoke(reason);
        }

        private async Task AcceptLoopAsync(TcpListener listener, CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                Socket client;
                try { client = await listener.AcceptSocketAsync(); }
                catch (ObjectDisposedException) { return; }
                catch (SocketException) { continue; }
                catch { return; }

                lock (_gate) _liveSockets.Add(client);
                _ = Task.Run(() => HandleConnectionAsync(client, token), token);
            }
        }

        // -----------------------------------------------------------------------
        // Per-connection handling
        // -----------------------------------------------------------------------

        private async Task HandleConnectionAsync(Socket client, CancellationToken token)
        {
            try
            {
                client.ReceiveTimeout = 15000;
                client.SendTimeout = 15000;
                using var stream = new NetworkStream(client, ownsSocket: true);

                var head = await ReadHttpHeadAsync(stream);
                if (head == null) return;
                head.Peer = client.RemoteEndPoint?.ToString();

                string firstLine = head.Lines.FirstOrDefault() ?? "";
                if (firstLine.StartsWith("CONNECT ", StringComparison.OrdinalIgnoreCase))
                {
                    string target = firstLine.Substring(8).Split(' ')[0].Trim();
                    await HandleConnectAsync(stream, client, head.Peer, target, head.Leftover);
                }
                else
                {
                    await HandlePlainHttpAsync(stream, head);
                }
            }
            catch { /* client vanished mid-conversation — the tee (if any) already emitted */ }
            finally
            {
                lock (_gate) _liveSockets.Remove(client);
                try { client.Close(); } catch { }
            }
        }

        private sealed class HttpHead
        {
            public List<string> Lines = new();
            public string Peer;              // "127.0.0.1:port" of the connecting side
            public byte[] Leftover = Array.Empty<byte>(); // bytes after the header block (a pipelined body start)
        }

        private async Task<HttpHead> ReadHttpHeadAsync(NetworkStream stream)
        {
            // Bytes are accumulated raw: anything after the header block is
            // payload that must be forwarded, not re-encoded through a
            // string round-trip.
            var buffer = new byte[16384];
            var collected = new MemoryStream();
            int headerEnd = -1;
            while (collected.Length < 16384)
            {
                int read = await stream.ReadAsync(buffer, 0, buffer.Length);
                if (read <= 0) break;
                collected.Write(buffer, 0, read);
                headerEnd = IndexOfHeaderEnd(collected.GetBuffer(), (int)collected.Length);
                if (headerEnd >= 0) break;
            }

            byte[] all = collected.ToArray();
            int blockEnd = headerEnd >= 0 ? headerEnd + 4 : all.Length;
            string headerBlock = Encoding.ASCII.GetString(all, 0, Math.Min(blockEnd, all.Length)).TrimEnd('\r', '\n');

            var head = new HttpHead
            {
                Lines = headerBlock.Split("\r\n").Where(l => l.Length > 0).ToList(),
                Leftover = all[Math.Min(blockEnd, all.Length)..],
            };
            return head.Lines.Count > 0 ? head : null;
        }

        private static int IndexOfHeaderEnd(byte[] haystack, int length)
        {
            for (int i = 0; i + 3 < length; i++)
                if (haystack[i] == 13 && haystack[i + 1] == 10 && haystack[i + 2] == 13 && haystack[i + 3] == 10)
                    return i;
            return -1;
        }

        private async Task HandleConnectAsync(NetworkStream clientStream, Socket client, string peer, string target, byte[] leftover)
        {
            int port = 443;
            string host = target;
            int colon = target.LastIndexOf(':');
            if (colon > 0 && int.TryParse(target[(colon + 1)..], out int parsed))
            {
                host = target[..colon];
                port = parsed;
            }

            bool isTarget = await IsTargetConnectionAsync(peer);
            byte[] ok = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
            await clientStream.WriteAsync(ok, 0, ok.Length);

            if (!isTarget)
            {
                await TunnelAsync(clientStream, host, port, tee: false, initialClientBytes: leftover);
                return;
            }

            // Upstream: real validation, no downgrade anywhere.
            TcpClient upstream;
            SslStream upstreamTls;
            try
            {
                upstream = new TcpClient();
                await upstream.ConnectAsync(host, port);
                upstreamTls = new SslStream(upstream.GetStream(), leaveInnerStreamOpen: false);
                await upstreamTls.AuthenticateAsClientAsync(host);
            }
            catch (Exception ex)
            {
                IngestIntercepted(pid: 0, host, port, null, null,
                    $"connect failed ({ex.GetType().Name})", tlsVersion: null, cipher: null);
                return;
            }

            // Server side: our minted leaf. Pinned clients abort here/next.
            // A pre-read prefix replays any bytes that arrived with the
            // CONNECT head before the SslStream starts reading.
            SslStream clientTls;
            try
            {
                var leaf = InterceptCaService.GetOrMintLeaf(host);
                clientTls = new SslStream(new PrefixedStream(clientStream, leftover), leaveInnerStreamOpen: false);
                await clientTls.AuthenticateAsServerAsync(leaf, clientCertificateRequired: false,
                    enabledSslProtocols: SslProtocols.None, checkCertificateRevocation: false);
            }
            catch
            {
                upstreamTls?.Dispose();
                IngestIntercepted(pid: 0, host, port, null, null,
                    "refused intercept (pinning)", tlsVersion: null, cipher: null);
                return;
            }

            string tlsVersion = TlsName(clientTls.SslProtocol);
            string cipher = clientTls.CipherAlgorithm.ToString();

            var requestTee = new MemoryStream();
            var responseTee = new MemoryStream();
            var upTask = PumpAsync(clientTls, upstreamTls, requestTee);
            var downTask = PumpAsync(upstreamTls, clientTls, responseTee);
            try { await Task.WhenAll(upTask, downTask); } catch { /* half-close and errors are normal here */ }

            clientTls.Dispose();
            upstreamTls.Dispose();

            string status = requestTee.Length == 0 && responseTee.Length == 0
                ? "refused intercept (client sent nothing after handshake)"
                : "decrypted · intercept";
            IngestIntercepted(0, host, port, requestTee.ToArray(), responseTee.ToArray(),
                status, tlsVersion, cipher);
        }

        private async Task HandlePlainHttpAsync(NetworkStream clientStream, HttpHead head)
        {
            // Explicit-proxy absolute form: "GET http://host:port/path
            // HTTP/1.1" — the origin server wants "GET /path HTTP/1.1".
            string firstLine = head.Lines[0];
            string host = null;
            int port = 80;
            int space1 = firstLine.IndexOf(' ');
            int lastSpace = firstLine.LastIndexOf(' ');
            if (space1 > 0 && lastSpace > space1 &&
                firstLine.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                string rest = firstLine[(space1 + 1)..lastSpace];
                string authority = rest.Split('/')[0];
                string path = rest.Length > authority.Length ? rest[authority.Length..] : "/";
                int colon = authority.LastIndexOf(':');
                if (colon > 0 && int.TryParse(authority[(colon + 1)..], out int parsed))
                {
                    host = authority[..colon];
                    port = parsed;
                }
                else host = authority;
                head.Lines[0] = $"{firstLine[..space1]} {path} {firstLine[(lastSpace + 1)..]}";
            }
            if (host == null)
            {
                foreach (var line in head.Lines)
                    if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                        host = line.Substring(5).Trim();
            }
            if (host == null) return;

            bool isTarget = await IsTargetConnectionAsync(head.Peer);

            TcpClient upstream;
            try
            {
                upstream = new TcpClient();
                await upstream.ConnectAsync(host, port);
            }
            catch { return; }

            using (upstream)
            using (var upstreamStream = upstream.GetStream())
            {
                byte[] headBytes = Encoding.ASCII.GetBytes(string.Join("\r\n", head.Lines) + "\r\n\r\n");
                await upstreamStream.WriteAsync(headBytes, 0, headBytes.Length);
                await upstreamStream.FlushAsync();
                if (head.Leftover.Length > 0)
                {
                    await upstreamStream.WriteAsync(head.Leftover, 0, head.Leftover.Length);
                    await upstreamStream.FlushAsync();
                }

                var requestTee = isTarget ? new MemoryStream() : null;
                var responseTee = isTarget ? new MemoryStream() : null;
                if (requestTee != null)
                {
                    requestTee.Write(headBytes, 0, headBytes.Length);
                    if (head.Leftover.Length > 0)
                        requestTee.Write(head.Leftover, 0, Math.Min(head.Leftover.Length, (int)(TeeCapPerDirection - requestTee.Length)));
                }

                var up = PumpAsync(clientStream, upstreamStream, requestTee);
                var down = PumpAsync(upstreamStream, clientStream, responseTee);
                try { await Task.WhenAll(up, down); } catch { }

                if (isTarget && (requestTee.Length > 0 || responseTee.Length > 0))
                    IngestIntercepted(0, host, port, requestTee.ToArray(), responseTee.ToArray(),
                        "decrypted · intercept (plaintext http)", "http", null);
            }
        }

        /// <summary>Byte-for-byte relay, optionally teeing both directions
        /// for later HTTP decoding (plaintext HTTP only).</summary>
        private static async Task TunnelAsync(NetworkStream clientStream, string host, int port, bool tee, byte[] initialClientBytes)
        {
            TcpClient upstream;
            try
            {
                upstream = new TcpClient();
                await upstream.ConnectAsync(host, port);
            }
            catch { return; }
            using (upstream)
            using (var upstreamStream = upstream.GetStream())
            {
                if (initialClientBytes is { Length: > 0 })
                {
                    await upstreamStream.WriteAsync(initialClientBytes, 0, initialClientBytes.Length);
                    await upstreamStream.FlushAsync();
                }
                var up = PumpAsync(clientStream, upstreamStream, null);
                var down = PumpAsync(upstreamStream, clientStream, null);
                try { await Task.WhenAll(up, down); } catch { }
            }
        }

        private static async Task PumpAsync(Stream from, Stream to, MemoryStream tee)
        {
            var buffer = new byte[65536];
            try
            {
                int read;
                while ((read = await from.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    await to.WriteAsync(buffer, 0, read);
                    await to.FlushAsync();
                    if (tee != null && tee.Length < TeeCapPerDirection)
                    {
                        int take = (int)Math.Min(read, TeeCapPerDirection - tee.Length);
                        tee.Write(buffer, 0, take);
                    }
                }
            }
            catch { /* a broken direction ends its pump; the other finishes */ }
            try { to.Dispose(); } catch { } // half-close so the peer sees EOF
        }

        // -----------------------------------------------------------------------
        // Scoping: which connection belongs to the target
        // -----------------------------------------------------------------------

        private async Task<bool> IsTargetConnectionAsync(string peer)
        {
            // PID attribution from the kernel TCP table (loopback rows are
            // included). The table lags a just-accepted socket by a few
            // milliseconds, hence the small retry.
            for (int attempt = 0; attempt < 10; attempt++)
            {
                int? pid = null;
                try
                {
                    string remote = $"127.0.0.1:{Port}";
                    foreach (var row in TcpConnectionTable.GetEstablished())
                        if (row.RemoteEndPoint == remote &&
                            (peer == null || row.LocalEndPoint == peer))
                        {
                            pid = row.Pid;
                            break;
                        }
                }
                catch { }

                if (pid.HasValue) return IsTargetPid(pid.Value);
                await Task.Delay(50);
            }
            return false; // unattributed: tunnel, never guess
        }

        private bool IsTargetPid(int pid)
        {
            lock (_gate)
            {
                if (!_running) return false;
                if (_targetPids.Contains(pid)) return true;

                // Same image counts as the target ONLY for non-shared-host
                // images — matching "svchost.exe" would swallow every
                // service on the machine.
                if (_targetImage == null) return false;
                string name = Path.GetFileName(_targetImage);
                if (SharedHostImages.Contains(name, StringComparer.OrdinalIgnoreCase)) return false;
                return string.Equals(ImageOfPid(pid), _targetImage, StringComparison.OrdinalIgnoreCase);
            }
        }

        private static string ImageOfPid(int pid)
        {
            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById(pid);
                return proc.MainModule?.FileName;
            }
            catch { return null; }
        }

        // -----------------------------------------------------------------------
        // Ingest into the Transmissions pipeline
        // -----------------------------------------------------------------------

        private void IngestIntercepted(int pid, string host, int port,
            byte[] request, byte[] response, string status, string tlsVersion, string cipher)
        {
            try
            {
                if (pid <= 0)
                    lock (_gate) pid = _targetPids.FirstOrDefault();

                string image = pid > 0 ? ImageOfPid(pid) : _targetImage;

                var record = new TransmissionRecord
                {
                    TsUtc = DateTime.UtcNow,
                    Pid = pid,
                    Image = image,
                    RemoteIp = host,
                    RemotePort = port,
                    Sni = host,
                    TlsVersion = tlsVersion,
                    CipherSuite = cipher,
                    ClientBytes = request?.Length ?? 0,
                    ServerBytes = response?.Length ?? 0,
                    ClientAppBytes = request?.Length ?? 0,
                    ServerAppBytes = response?.Length ?? 0,
                    Status = status,
                };
                TransmissionsPipelineService.Shared.IngestIntercepted(record, request, response, host);
            }
            catch (Exception ex)
            {
                OnStatus?.Invoke($"Intercept ingest failed: {ex.Message}");
            }
        }

        private static string TlsName(SslProtocols protocol) => protocol switch
        {
            SslProtocols.Tls13 => "TLS 1.3",
            SslProtocols.Tls12 => "TLS 1.2",
            SslProtocols.Tls11 => "TLS 1.1",
            SslProtocols.Tls => "TLS 1.0",
            _ => protocol.ToString(),
        };

        /// <summary>Replays pre-read bytes before delegating to the inner
        /// stream — lets the server-side SslStream see a ClientHello that
        /// arrived glued to the CONNECT head.</summary>
        private sealed class PrefixedStream : Stream
        {
            private readonly byte[] _prefix;
            private int _prefixPos;
            private readonly Stream _inner;

            public PrefixedStream(Stream inner, byte[] prefix)
            {
                _inner = inner;
                _prefix = prefix ?? Array.Empty<byte>();
            }

            public override bool CanRead => _inner.CanRead;
            public override bool CanSeek => false;
            public override bool CanWrite => _inner.CanWrite;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => 0; set => throw new NotSupportedException(); }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (_prefixPos < _prefix.Length)
                {
                    int take = Math.Min(count, _prefix.Length - _prefixPos);
                    Array.Copy(_prefix, _prefixPos, buffer, offset, take);
                    _prefixPos += take;
                    return take;
                }
                return _inner.Read(buffer, offset, count);
            }

            public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                if (_prefixPos < _prefix.Length)
                {
                    int take = Math.Min(count, _prefix.Length - _prefixPos);
                    Array.Copy(_prefix, _prefixPos, buffer, offset, take);
                    _prefixPos += take;
                    return take;
                }
                return await _inner.ReadAsync(buffer, offset, count, cancellationToken);
            }

            public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);
            public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
                _inner.WriteAsync(buffer, offset, count, cancellationToken);
            public override void Flush() => _inner.Flush();
            public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
        }
    }
}
