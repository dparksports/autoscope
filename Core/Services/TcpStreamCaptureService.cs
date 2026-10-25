using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using AutoScope.Models;

namespace AutoScope.Services
{
    /// <summary>
    /// Retains (instead of discarding) the TCP payloads crossing the NIC on a
    /// private raw socket, reassembling each direction of every IPv4 TCP
    /// conversation into byte streams the TLS decryptor can consume. This is
    /// a separate socket and separate counters from the Process Monitor's
    /// RawSocketSnifferService — the svchost tab is untouched.
    ///
    /// Known gaps (by design, documented in the README): loopback traffic
    /// never crosses the NIC so SIO_RCVALL never sees it; IPv6 and UDP/QUIC
    /// are out of scope.
    /// </summary>
    public class TcpStreamCaptureService
    {
        // Per-flow memory discipline: head + tail retention around a dropped
        // middle once a direction exceeds its budget.
        public long MaxBytesPerDirection { get; set; } = 8 * 1024 * 1024;
        public int MaxConcurrentFlows { get; set; } = 4096;
        public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromSeconds(60);
        public bool PersistFlows { get; set; } = false;
        public long PersistDirBudgetBytes { get; set; } = 64 * 1024 * 1024;

        public event Action<string> OnError;
        public event Action<TcpFlowRecord> OnFlowFinalized;

        private readonly ConcurrentDictionary<string, TcpFlow> _flows = new(StringComparer.Ordinal);
        private Socket _socket;
        private CancellationTokenSource _cts;
        private Timer _sweepTimer;
        private int _running;

        // Direction visibility for the whole capture session. Some NIC/driver
        // combos deliver only outbound packets to a receive-all socket; when
        // that happens the UI must say "not observed" instead of letting a
        // zero read as "nothing ever came back".
        private IPAddress _localIp;
        private long _inboundPackets;
        private long _outboundPackets;
        private string _captureMode = "off";

        /// <summary>Packets whose source was the local address (sent by this PC).</summary>
        public long OutboundPackets => Interlocked.Read(ref _outboundPackets);
        /// <summary>Packets whose source was a remote address (replies and other inbound).</summary>
        public long InboundPackets => Interlocked.Read(ref _inboundPackets);
        /// <summary>True once the session has seen at least one inbound packet.</summary>
        public bool InboundSeen => Interlocked.Read(ref _inboundPackets) > 0;
        /// <summary>"ip-level" · "on" · "off" — which SIO_RCVALL flavor is live.</summary>
        public string CaptureMode => _captureMode;
        public bool IsRunning => _running == 1;

        private static string FlowDir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoScope", "pytrace", "flows");

        public int LiveFlowCount => _flows.Count;

        // -----------------------------------------------------------------------
        // App-level sharing
        // -----------------------------------------------------------------------

        private static readonly Lazy<TcpStreamCaptureService> _shared = new(() => new TcpStreamCaptureService());

        /// <summary>
        /// The app-level instance shared by every view that captures (Python
        /// Spawns, Traffic Patterns) — one raw socket instead of one per tab.
        /// Views hold it with AddRef/Release so it runs exactly while at least
        /// one of them wants it; settings like IdleTimeout are per-instance,
        /// so the last tab to load them configures the shared socket.
        /// </summary>
        public static TcpStreamCaptureService Shared => _shared.Value;

        private int _refs;

        /// <summary>Reference-counted start: the first holder starts the capture.</summary>
        public void AddRef()
        {
            if (Interlocked.Increment(ref _refs) == 1)
                Start();
        }

        /// <summary>Reference-counted stop: runs until the last holder releases.</summary>
        public void Release()
        {
            int refs = Interlocked.Decrement(ref _refs);
            if (refs == 0) Stop();
            else if (refs < 0) Interlocked.Exchange(ref _refs, 0); // over-release guard
        }

        public void Start()
        {
            if (Interlocked.Exchange(ref _running, 1) == 1) return;
            _cts = new CancellationTokenSource();

            Task.Run(() =>
            {
                try
                {
                    IPAddress localIp = GetLocalIpAddress();
                    if (localIp == null)
                    {
                        OnError?.Invoke("Could not determine the local IPv4 address for TCP stream capture.");
                        return;
                    }

                    _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                    _socket.Bind(new IPEndPoint(localIp, 0));
                    _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

                    // RCVALL_IPLEVEL first: it captures both directions at the
                    // IP layer and, unlike RCVALL_ON, does not depend on the
                    // NIC honoring promiscuous mode (on hardware that ignores
                    // it, RCVALL_ON silently yields outbound-only captures).
                    // RCVALL_ON stays as the fallback for older stacks.
                    byte[] ipLevel = { 3, 0, 0, 0 };
                    byte[] on = { 1, 0, 0, 0 };
                    try
                    {
                        _socket.IOControl(IOControlCode.ReceiveAll, ipLevel, new byte[4]);
                        _captureMode = "ip-level";
                    }
                    catch (SocketException)
                    {
                        _socket.IOControl(IOControlCode.ReceiveAll, on, new byte[4]);
                        _captureMode = "on";
                    }
                    Interlocked.Exchange(ref _inboundPackets, 0);
                    Interlocked.Exchange(ref _outboundPackets, 0);
                    _localIp = localIp;
                    _socket.ReceiveTimeout = 2000;

                    var buffer = new byte[65535];
                    while (!_cts.Token.IsCancellationRequested)
                    {
                        try
                        {
                            int received = _socket.Receive(buffer);
                            if (received >= 20)
                                ProcessIpPacket(buffer, received);
                        }
                        catch (SocketException ex)
                        {
                            if (ex.SocketErrorCode != SocketError.TimedOut &&
                                ex.SocketErrorCode != SocketError.Interrupted &&
                                ex.SocketErrorCode != SocketError.WouldBlock)
                            {
                                // transient NIC-level errors: keep the loop alive
                            }
                        }
                    }
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
                {
                    OnError?.Invoke("TCP stream capture needs elevation (raw socket access denied). Run AutoScope as Administrator.");
                }
                catch (ObjectDisposedException)
                {
                    // Stop() closed the socket mid-receive — normal shutdown
                }
                catch (Exception ex)
                {
                    OnError?.Invoke($"TCP stream capture error: {ex.Message}");
                }
            }, _cts.Token);

            _sweepTimer = new Timer(_ => FinalizeIdleFlows(), null,
                TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        }

        public void Stop()
        {
            if (Interlocked.Exchange(ref _running, 0) == 0) return;
            _sweepTimer?.Dispose();
            _sweepTimer = null;
            _cts?.Cancel();
            _socket?.Close();
            _socket = null;

            // Everything still open finalizes so the UI keeps what was captured
            foreach (var flow in _flows.Values.ToList()) Finalize(flow);
            _flows.Clear();
        }

        /// <summary>
        /// Parses one IPv4 packet. Public for the offline self-test, which
        /// feeds synthetic IP/TCP buffers through the reassembler.
        /// </summary>
        public void ProcessIpPacket(byte[] buffer, int length)
        {
            try
            {
                int version = buffer[0] >> 4;
                if (version != 4) return;
                int ihl = (buffer[0] & 0x0F) * 4;
                if (ihl < 20 || length < ihl) return;

                int totalLength = (buffer[2] << 8) | buffer[3];
                if (totalLength < ihl || totalLength > length) totalLength = length;

                if (buffer[9] != 6) return; // TCP only

                var srcIp = new IPAddress(new ReadOnlySpan<byte>(buffer, 12, 4));
                var dstIp = new IPAddress(new ReadOnlySpan<byte>(buffer, 16, 4));

                // Session-level direction tally (null local IP = offline
                // self-test feeding synthetic buffers — nothing to count).
                if (_localIp != null)
                {
                    if (srcIp.Equals(_localIp)) Interlocked.Increment(ref _outboundPackets);
                    else Interlocked.Increment(ref _inboundPackets);
                }

                int tcpOffset = ihl;
                if (tcpOffset + 20 > totalLength) return;
                int srcPort = (buffer[tcpOffset] << 8) | buffer[tcpOffset + 1];
                int dstPort = (buffer[tcpOffset + 2] << 8) | buffer[tcpOffset + 3];
                uint seq = (uint)((buffer[tcpOffset + 4] << 24) | (buffer[tcpOffset + 5] << 16) |
                                  (buffer[tcpOffset + 6] << 8) | buffer[tcpOffset + 7]);
                byte flags = buffer[tcpOffset + 13];
                int dataOffset = (buffer[tcpOffset + 12] >> 4) * 4;
                if (dataOffset < 20) return;

                int payloadStart = tcpOffset + dataOffset;
                int payloadLen = totalLength - payloadStart;
                if (payloadLen < 0) payloadLen = 0;

                var flow = GetOrCreateFlow(srcIp, srcPort, dstIp, dstPort, out bool fromLow);
                if (flow == null) return;

                lock (flow)
                {
                    flow.LastSeenUtc = DateTime.UtcNow;
                    const byte fin = 0x01, syn = 0x02, rst = 0x04;
                    if ((flags & rst) != 0) flow.Reset = true;
                    if ((flags & syn) != 0)
                    {
                        if (flow.ClientEndpoint == null) flow.ClientEndpoint = (srcIp.ToString(), srcPort);
                        flow.SynSeen = true;
                    }
                    if ((flags & fin) != 0)
                    {
                        var dir = flow.DirectionOf(fromLow);
                        dir.FinSent = true;
                        if (flow.ClientDir.FinSent && flow.ServerDir.FinSent) flow.GracefulClose = true;
                    }

                    if (payloadLen > 0)
                    {
                        var dir = flow.DirectionOf(fromLow);
                        uint dataSeq = seq;
                        if ((flags & syn) != 0 && dir.NextSeq == null)
                        {
                            // A SYN consumes one sequence number before its payload
                            dir.NextSeq = unchecked(seq + 1);
                            dataSeq = unchecked(seq + 1);
                        }
                        FeedSegment(dir, dataSeq, buffer, payloadStart, payloadLen);
                    }

                    if (flow.GracefulClose || flow.Reset)
                        Finalize(flow);
                }
            }
            catch { /* one malformed packet never stops the capture */ }
        }

        /// <summary>
        /// Tags the flow matching this Sysmon EID 3 connect with the python
        /// pid/image. The first attribution wins — endpoints are unique per
        /// connect while the connection lives.
        /// </summary>
        public bool TagFlow(string srcIp, int srcPort, string dstIp, int dstPort, int pid, string image)
        {
            string key = CanonicalKey(srcIp, srcPort, dstIp, dstPort, out _);
            if (!_flows.TryGetValue(key, out var flow)) return false;
            lock (flow)
            {
                if (flow.Pid != 0) return false;
                flow.Pid = pid;
                flow.Image = image;
                return true;
            }
        }

        // -----------------------------------------------------------------------
        // Flow management
        // -----------------------------------------------------------------------

        private TcpFlow GetOrCreateFlow(IPAddress srcIp, int srcPort, IPAddress dstIp, int dstPort, out bool fromLow)
        {
            string src = $"{srcIp}:{srcPort}";
            string dst = $"{dstIp}:{dstPort}";
            bool low = string.CompareOrdinal(src, dst) < 0;
            fromLow = low;
            string key = low ? $"{src}|{dst}" : $"{dst}|{src}";

            var flow = _flows.GetOrAdd(key, _ => new TcpFlow
            {
                Key = key,
                LowEndpoint = low ? src : dst,
                HighEndpoint = low ? dst : src,
                StartedUtc = DateTime.UtcNow
            });

            if (_flows.Count > MaxConcurrentFlows)
                FinalizeIdleFlows(); // cheap pressure valve: idle flows finalize first

            return flow;
        }

        private static string CanonicalKey(string srcIp, int srcPort, string dstIp, int dstPort, out bool lowIsSource)
        {
            string src = $"{srcIp}:{srcPort}";
            string dst = $"{dstIp}:{dstPort}";
            lowIsSource = string.CompareOrdinal(src, dst) < 0;
            return lowIsSource ? $"{src}|{dst}" : $"{dst}|{src}";
        }

        private void FinalizeIdleFlows()
        {
            try
            {
                DateTime now = DateTime.UtcNow;
                foreach (var kv in _flows)
                {
                    var flow = kv.Value;
                    lock (flow)
                    {
                        if (flow.Finalized) return;
                        if (now - flow.LastSeenUtc >= IdleTimeout || flow.GracefulClose || flow.Reset)
                            Finalize(flow);
                    }
                }
            }
            catch { /* the sweep is opportunistic */ }
        }

        private void Finalize(TcpFlow flow)
        {
            bool removed = _flows.TryRemove(flow.Key, out var _);
            if (!removed && flow.Finalized) return;
            flow.Finalized = true;

            var record = flow.ToRecord(MaxBytesPerDirection);
            if (record == null) return;

            if (PersistFlows)
                Persist(record);

            OnFlowFinalized?.Invoke(record);
        }

        // -----------------------------------------------------------------------
        // Optional persistence (JSONL with base64 payloads, rotated by budget)
        // -----------------------------------------------------------------------

        private void Persist(TcpFlowRecord record)
        {
            try
            {
                Directory.CreateDirectory(FlowDir);
                string path = Path.Combine(FlowDir, $"flows-{DateTime.Now:yyyyMMdd}.jsonl");

                var entry = new Dictionary<string, object>
                {
                    ["ts"] = record.EndedUtc,
                    ["key"] = record.Key,
                    ["client"] = record.ClientEndpoint,
                    ["server"] = record.ServerEndpoint,
                    ["pid"] = record.Pid,
                    ["image"] = record.Image,
                    ["client_b64"] = Convert.ToBase64String(record.ClientData ?? Array.Empty<byte>()),
                    ["server_b64"] = Convert.ToBase64String(record.ServerData ?? Array.Empty<byte>()),
                    ["truncated"] = record.Truncated
                };
                File.AppendAllText(path, System.Text.Json.JsonSerializer.Serialize(entry) + Environment.NewLine);

                // Rotation: keep the newest files within the budget
                var files = new DirectoryInfo(FlowDir)
                    .GetFiles("flows-*.jsonl")
                    .OrderByDescending(f => f.Name)
                    .ToList();
                long budget = PersistDirBudgetBytes;
                foreach (var file in files)
                {
                    budget -= file.Length;
                    if (budget < 0) file.Delete();
                }
            }
            catch { /* persistence is optional; capture itself already succeeded */ }
        }

        private static IPAddress GetLocalIpAddress()
        {
            try
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0);
                socket.Connect("8.8.8.8", 65530); // resolves the routing-table local IP without sending
                return (socket.LocalEndPoint as IPEndPoint)?.Address;
            }
            catch
            {
                foreach (var ip in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                        return ip;
                return null;
            }
        }

        // -----------------------------------------------------------------------
        // Reassembly
        // -----------------------------------------------------------------------

        /// <summary>
        /// Feeds one TCP segment into a direction's reassembler: in-order
        /// segments append; ahead-of-order segments buffer until the gap
        /// closes; behind-order bytes are the retransmit/overlap tail.
        /// </summary>
        private void FeedSegment(TcpDirection dir, uint seq, byte[] buffer, int start, int length)
        {
            dir.EnsureBudget(MaxBytesPerDirection);
            if (dir.NextSeq == null)
            {
                // Mid-stream capture: take this segment's sequence as the start
                dir.NextSeq = seq;
            }

            long delta = SeqDelta(seq, dir.NextSeq.Value);
            if (delta == 0)
            {
                dir.Append(buffer, start, length);
                dir.NextSeq = unchecked(seq + (uint)length);
                DrainBuffered(dir);
            }
            else if (delta > 0)
            {
                // Out of order (or a gap we haven't seen the cause of yet)
                if (!dir.OutOfOrder.ContainsKey(seq) && dir.OutOfOrder.Count < 512)
                    dir.OutOfOrder[seq] = buffer.Skip(start).Take(length).ToArray();
            }
            else
            {
                // Retransmit overlapping what we already have: keep only the new tail
                long skip = -delta;
                if (skip < length)
                {
                    dir.Append(buffer, start + (int)skip, length - (int)skip);
                    dir.NextSeq = unchecked(seq + (uint)length);
                    DrainBuffered(dir);
                }
            }
        }

        private static void DrainBuffered(TcpDirection dir)
        {
            while (dir.NextSeq.HasValue && dir.OutOfOrder.TryGetValue(dir.NextSeq.Value, out var segment))
            {
                dir.OutOfOrder.Remove(dir.NextSeq.Value);
                dir.Append(segment, 0, segment.Length);
                dir.NextSeq = unchecked(dir.NextSeq.Value + (uint)segment.Length);
            }
        }

        /// <summary>Signed distance from base to seq, handling 32-bit wraparound.</summary>
        private static long SeqDelta(uint seq, uint baseSeq)
        {
            long delta = (long)seq - baseSeq;
            if (delta > int.MaxValue) delta -= (long)uint.MaxValue + 1;
            if (delta < -(long)int.MaxValue) delta += (long)uint.MaxValue + 1;
            return delta;
        }

        // -----------------------------------------------------------------------
        // Internal flow state
        // -----------------------------------------------------------------------

        private sealed class TcpFlow
        {
            public string Key;
            public string LowEndpoint;   // lexicographically smaller ip:port
            public string HighEndpoint;
            public (string Ip, int Port)? ClientEndpoint; // SYN sender, learned from the first SYN
            public TcpDirection ClientDir = new(); // Low  → High
            public TcpDirection ServerDir = new(); // High → Low
            public DateTime StartedUtc;
            public DateTime LastSeenUtc = DateTime.UtcNow;
            public bool SynSeen;
            public bool GracefulClose;
            public bool Reset;
            public bool Finalized;
            public int Pid;
            public string Image;

            public TcpDirection DirectionOf(bool fromLow)
            {
                // ClientDir carries Low→High. Until a SYN names the client, the
                // first payload direction is treated as the client.
                bool lowIsClient = ClientEndpoint == null ||
                                   $"{ClientEndpoint.Value.Ip}:{ClientEndpoint.Value.Port}" == LowEndpoint;
                return fromLow == lowIsClient ? ClientDir : ServerDir;
            }

            public TcpFlowRecord ToRecord(long maxBytesPerDirection)
            {
                string client, server;
                if (ClientEndpoint != null)
                {
                    bool clientIsLow = $"{ClientEndpoint.Value.Ip}:{ClientEndpoint.Value.Port}" == LowEndpoint;
                    client = clientIsLow ? LowEndpoint : HighEndpoint;
                    server = clientIsLow ? HighEndpoint : LowEndpoint;
                }
                else
                {
                    client = LowEndpoint;   // no SYN seen: assume, the record says so via SynSeen
                    server = HighEndpoint;
                }

                return new TcpFlowRecord
                {
                    Key = Key,
                    ClientEndpoint = client,
                    ServerEndpoint = server,
                    StartedUtc = StartedUtc,
                    EndedUtc = LastSeenUtc,
                    ClientBytes = ClientDir.TotalBytes,
                    ServerBytes = ServerDir.TotalBytes,
                    FinBoth = ClientDir.FinSent && ServerDir.FinSent,
                    Reset = Reset,
                    Truncated = ClientDir.Truncated || ServerDir.Truncated,
                    Pid = Pid,
                    Image = Image,
                    ClientData = ClientDir.ToBytes(),
                    ServerData = ServerDir.ToBytes()
                };
            }
        }

        /// <summary>
        /// One direction of a flow: in-order byte stream with head+tail
        /// retention once the per-direction budget is exceeded (the middle is
        /// dropped and the flow is flagged truncated).
        /// </summary>
        private sealed class TcpDirection
        {
            public uint? NextSeq;
            public readonly SortedDictionary<uint, byte[]> OutOfOrder = new();
            public bool FinSent;
            public long TotalBytes;

            private readonly MemoryStream _head = new();
            private readonly Queue<byte[]> _tail = new();
            private long _tailBytes;
            public bool Truncated;

            private long _headBudget;   // 0 until EnsureBudget wires the owner's cap
            private long _tailBudget;

            public void EnsureBudget(long totalPerDirection)
            {
                if (_headBudget != 0) return;
                _headBudget = totalPerDirection * 3 / 4;
                _tailBudget = totalPerDirection - _headBudget;
            }

            public void Append(byte[] buffer, int start, int length)
            {
                TotalBytes += length;

                if (_head.Length < _headBudget)
                {
                    long room = _headBudget - _head.Length;
                    if (length <= room)
                    {
                        _head.Write(buffer, start, length);
                        return;
                    }
                    _head.Write(buffer, start, (int)room);
                    start += (int)room;
                    length -= (int)room;
                }

                // Head full: coalesce into ~64KB tail chunks, evicting the oldest
                while (length > 0)
                {
                    int take = Math.Min(length, 65536);
                    var chunk = new byte[take];
                    Array.Copy(buffer, start, chunk, 0, take);
                    _tail.Enqueue(chunk);
                    _tailBytes += take;
                    start += take;
                    length -= take;
                }
                while (_tailBytes > _tailBudget && _tail.Count > 1)
                {
                    _tailBytes -= _tail.Peek().Length;
                    _tail.Dequeue();
                    Truncated = true;
                }
            }

            public byte[] ToBytes()
            {
                long total = _head.Length + _tailBytes;
                if (total == 0) return Array.Empty<byte>();
                var result = new byte[total];
                _head.Position = 0;
                _head.ReadExactly(result, 0, (int)_head.Length);
                int offset = (int)_head.Length;
                foreach (var chunk in _tail)
                {
                    Array.Copy(chunk, 0, result, offset, chunk.Length);
                    offset += chunk.Length;
                }
                return result;
            }
        }
    }
}
