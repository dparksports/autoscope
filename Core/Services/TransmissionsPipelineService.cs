using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoScope.Models;

namespace AutoScope.Services
{
    /// <summary>
    /// The Transmissions pipeline: every finalized TCP flow from the shared
    /// raw-socket capture is run through the TLS decryptor (keys from the
    /// keylog the python hook and/or SSLKEYLOGFILE-supporting apps wrote),
    /// the decrypted directions are decoded into HTTP messages, the row is
    /// archived (metadata always when archived; full bodies when they
    /// decrypted), and the UI gets an event per new row.
    ///
    /// PID attribution is Sysmon EID 3 via this service's own connect
    /// watcher feeding TagFlow — first-writer-wins, so the python tab's
    /// identical tagging is harmless.
    ///
    /// Archiving rule: a flow earns a row when it decrypted to content OR
    /// when it pushed more than 10 KB upstream (the threshold this tab
    /// exists for — a big upload deserves a record even when no keys
    /// existed). Everything else is counted and discarded.
    /// </summary>
    public sealed class TransmissionsPipelineService
    {
        public static TransmissionsPipelineService Shared { get; } = new();

        private readonly TcpStreamCaptureService _capture = TcpStreamCaptureService.Shared;
        private readonly TlsKeylogService _keylog = new();
        private SysmonConnectWatcherService _connectWatcher;
        private Thread _worker;
        private CancellationTokenSource _cts;
        // Recreated on every Start: CompleteAdding is permanent, so a
        // stopped-and-restarted watch needs a fresh queue.
        private BlockingCollection<TcpFlowRecord> _queue = new(boundedCapacity: 512);
        private int _running;

        // Recent bodies kept in memory for instant viewer access; archived
        // rows fall back to disk. FIFO with a byte budget.
        private readonly object _bodiesLock = new();
        private readonly LinkedList<(string Id, long Bytes)> _bodyOrder = new();
        private readonly Dictionary<string, (byte[] Request, byte[] Response)> _bodies = new();
        private const long BodyCacheBytes = 96 * 1024 * 1024;
        private long _bodyCacheUsed;

        public event Action<TransmissionRecord> OnRecord;
        public event Action<string> OnError;

        /// <summary>
        /// Every &gt;10KB upload that arrived encrypted with no keys — one
        /// event per flow, deliberately unthrottled. The ignore-list filter
        /// and any pacing live on the consumer (the view), not here: the
        /// pipeline reports, it does not decide.
        /// </summary>
        public event Action<TransmissionRecord> OnBigEncryptedUpload;

        public long ProcessedCount => Interlocked.Read(ref _processed);
        public long DecryptedCount => Interlocked.Read(ref _decrypted);
        public long EncryptedNoKeysCount => Interlocked.Read(ref _noKeys);
        public long DroppedCount => Interlocked.Read(ref _queueDropped);
        public int LiveQueueDepth => _queue.Count;

        private TransmissionsPipelineService() { }

        public bool IsRunning => Volatile.Read(ref _running) == 1;

        public void Start()
        {
            if (Interlocked.Exchange(ref _running, 1) == 1) return;
            _queue = new BlockingCollection<TcpFlowRecord>(boundedCapacity: 512);
            _cts = new CancellationTokenSource();

            TlsKeylogService.EnsureHygiene();

            _connectWatcher = new SysmonConnectWatcherService();
            _connectWatcher.OnError += e => OnError?.Invoke(e);
            _connectWatcher.OnConnect += OnConnect;
            _connectWatcher.Start();

            _capture.OnFlowFinalized += OnFlowFinalized;
            _capture.AddRef(); // balanced by Stop() — the raw socket runs while the pipeline does

            _worker = new Thread(ProcessQueue) { IsBackground = true, Name = "TransmissionsPipeline" };
            _worker.Start();
        }

        public void Stop()
        {
            if (Interlocked.Exchange(ref _running, 0) == 0) return;
            _capture.OnFlowFinalized -= OnFlowFinalized;
            _connectWatcher?.Stop();
            _connectWatcher = null;
            _capture.Release();

            _queue.CompleteAdding();
            try { _worker?.Join(TimeSpan.FromSeconds(3)); } catch { }
            _cts?.Cancel();
        }

        private void OnConnect(SysmonConnectEvent evt)
        {
            if (!evt.IsTcp) return;
            _capture.TagFlow(evt.SourceIp, evt.SourcePort, evt.DestIp, evt.DestPort, evt.Pid, evt.Image);
        }

        private void OnFlowFinalized(TcpFlowRecord flow)
        {
            // Raised on capture threads — enqueue or drop, never block.
            if (!IsInteresting(flow)) return;
            if (!_queue.TryAdd(flow))
                Interlocked.Increment(ref _queueDropped); // queue full: capture outpaces decryption
        }
        private long _queueDropped;

        /// <summary>TLS-shaped flows only: a handshake record at the head of
        /// the client direction, or a classic TLS port when the head is
        /// missing (mid-stream capture still decrypts nothing, but the row
        /// documents an encrypted conversation).</summary>
        private static bool IsInteresting(TcpFlowRecord flow)
        {
            if (flow?.ClientData == null || flow.ClientData.Length < 5) return false;
            if (flow.ClientData[0] == 0x16 && (flow.ClientData[1] == 0x03)) return true; // TLS handshake
            return flow.RemotePortOrDefault() is 443 or 8443 or 853;
        }

        private void ProcessQueue()
        {
            try
            {
                foreach (var flow in _queue.GetConsumingEnumerable(_cts.Token))
                {
                    try { Process(flow); }
                    catch { /* one flow's failure never stops the pipeline */ }
                }
            }
            catch (OperationCanceledException) { }
            catch { /* shutdown race */ }
        }

        private void Process(TcpFlowRecord flow)
        {
            Interlocked.Increment(ref _processed);

            string remoteIp = RemoteIpOf(flow.ServerEndpoint);
            int remotePort = RemotePortOf(flow.ServerEndpoint);

            _keylog.Refresh();
            var result = TlsDecryptor.Decrypt(flow, _keylog);

            bool decrypted = result.Success;
            string status;
            if (decrypted) status = "decrypted";
            else if (result.Status != null && result.Status.Contains("No TLS handshake")) status = "no handshake";
            else if (result.Status != null && (result.Status.Contains("no TLS secrets") ||
                     result.Status.Contains("Not instrumented") ||
                     result.Status.Contains("keylogging is disabled"))) status = "encrypted (no keys)";
            else if (result.Status != null && result.Status.Contains("Unsupported cipher")) status = "unsupported cipher";
            else status = "undecryptable";
            if (result.Truncated && !status.Contains("truncated")) status += " · truncated";

            var record = new TransmissionRecord
            {
                TsUtc = flow.EndedUtc == default ? DateTime.UtcNow : flow.EndedUtc,
                Pid = flow.Pid,
                Image = flow.Image,
                RemoteIp = remoteIp,
                RemotePort = remotePort,
                LocalEndpoint = flow.ClientEndpoint,
                Sni = result.Sni,
                TlsVersion = result.TlsVersion,
                Alpn = result.Alpn,
                CipherSuite = result.CipherSuite,
                ClientBytes = flow.ClientBytes,
                ServerBytes = flow.ServerBytes,
                ClientAppBytes = result.ClientAppBytes,
                ServerAppBytes = result.ServerAppBytes,
                Status = status,
            };

            byte[] requestStream = null, responseStream = null;
            int messageCount = 0;
            var kinds = new HashSet<string>(StringComparer.Ordinal);

            if (decrypted)
            {
                Interlocked.Increment(ref _decrypted);
                requestStream = ConcatAppData(result, fromClient: true);
                responseStream = ConcatAppData(result, fromClient: false);

                foreach (var msg in HttpStreamDecoder.Decode(requestStream, true, result.Alpn)) { messageCount++; kinds.Add(msg.Kind); }
                foreach (var msg in HttpStreamDecoder.Decode(responseStream, false, result.Alpn)) { messageCount++; kinds.Add(msg.Kind); }
                record.MessageCount = messageCount;
                record.ContentKinds = string.Join(", ", kinds.Where(k => k != null));
            }
            else if (status == "encrypted (no keys)")
            {
                Interlocked.Increment(ref _noKeys);
            }

            // Archive rule: content, or the >10 KB upload this tab exists for.
            bool worthArchiving = (decrypted && (requestStream.Length > 0 || responseStream.Length > 0)) ||
                                  record.BigUpload ||
                                  (status == "encrypted (no keys)" && record.BigUpload);
            if (worthArchiving)
            {
                TransmissionsArchiveService.Append(record, requestStream, responseStream);
                if (record.HasContent)
                    CacheBodies(record.Id, requestStream, responseStream);
            }
            else
            {
                // Live-only row: viewers can still show it for this session.
                if (decrypted && (requestStream.Length > 0 || responseStream.Length > 0))
                    CacheBodies(record.Id, requestStream, responseStream);
            }

            ResolveProvider(record, remoteIp);
            TallyImage(record);
            OnRecord?.Invoke(record);

            if (record.BigUpload && status == "encrypted (no keys)")
                OnBigEncryptedUpload?.Invoke(record);
        }

        // ── per-image stats (drives "Apps without keys") ──────────────────

        private readonly object _statsLock = new();
        private readonly Dictionary<string, TransmissionsImageStats> _stats = new(StringComparer.OrdinalIgnoreCase);

        internal void TallyImage(TransmissionRecord record)
        {
            lock (_statsLock)
            {
                if (!_stats.TryGetValue(record.Image ?? "", out var stats))
                    _stats[record.Image ?? ""] = stats = new TransmissionsImageStats { Image = record.Image ?? "" };
                if (record.Decrypted) stats.DecryptedFlows++;
                else if (record.Status != null && record.Status.Contains("no keys"))
                {
                    stats.EncryptedFlows++;
                    stats.LastEncryptedUtc = record.TsUtc;
                    stats.LastEncryptedPid = record.Pid;
                    stats.LastEncryptedBiggestUpload = Math.Max(stats.LastEncryptedBiggestUpload, record.ClientBytes);
                }
            }
        }

        /// <summary>Snapshot of per-image counts, newest-encrypted first.</summary>
        public List<TransmissionsImageStats> GetImageStatsSnapshot()
        {
            lock (_statsLock)
                return _stats.Values
                    .OrderByDescending(s => s.LastEncryptedUtc)
                    .Select(s => s.Clone())
                    .ToList();
        }

        private long _processed;
        private long _decrypted;
        private long _noKeys;

        /// <summary>
        /// Entry point for layer-3 intercept records (InterceptProxyService):
        /// same treatment as captured flows — HTTP decode for message
        /// counts, archive + body cache, per-image tally, UI event. Works
        /// even when the watch is off; the archive makes rows visible
        /// whenever the tab loads.
        /// </summary>
        public void IngestIntercepted(TransmissionRecord record, byte[] requestStream, byte[] responseStream, string host)
        {
            if (record == null) return;
            try
            {
                int messageCount = 0;
                var kinds = new HashSet<string>(StringComparer.Ordinal);
                foreach (var msg in HttpStreamDecoder.Decode(requestStream, true, alpn: null)) { messageCount++; kinds.Add(msg.Kind); }
                foreach (var msg in HttpStreamDecoder.Decode(responseStream, false, alpn: null)) { messageCount++; kinds.Add(msg.Kind); }
                record.MessageCount = messageCount;
                record.ContentKinds = string.Join(", ", kinds.Where(k => k != null));

                if (!string.IsNullOrEmpty(host))
                {
                    if (System.Net.IPAddress.TryParse(host, out var ip))
                    {
                        record.RemoteIp = host;
                        ResolveProvider(record, host);
                    }
                    else
                    {
                        // Hostname: resolve in the background, then attribute.
                        Task.Run(() =>
                        {
                            try
                            {
                                var addresses = System.Net.Dns.GetHostAddresses(host);
                                if (addresses is { Length: > 0 })
                                {
                                    record.RemoteIp = addresses[0].ToString();
                                    ResolveProvider(record, record.RemoteIp);
                                }
                            }
                            catch { /* hostname unresolvable post-mortem — provider stays Unclassified */ }
                        });
                    }
                }

                TransmissionsArchiveService.Append(record, requestStream, responseStream);
                if (record.HasContent)
                    CacheBodies(record.Id, requestStream, responseStream);
                TallyImage(record);
                OnRecord?.Invoke(record);
            }
            catch (Exception)
            {
                // An intercept row must never break the session
            }
        }

        private static byte[] ConcatAppData(TlsDecryptResult result, bool fromClient)
        {
            var parts = result.Records
                .Where(r => r.Decrypted && r.ContentType == "application_data" && r.FromClient == fromClient)
                .Select(r => r.Data)
                .ToList();
            long total = parts.Sum(p => p?.Length ?? 0);
            if (total == 0 || total > 16 * 1024 * 1024) return Array.Empty<byte>();
            var buffer = new byte[total];
            int offset = 0;
            foreach (var part in parts)
            {
                Array.Copy(part, 0, buffer, offset, part.Length);
                offset += part.Length;
            }
            return buffer;
        }

        // ── provider attribution ──────────────────────────────────────────

        private void ResolveProvider(TransmissionRecord record, string ip)
        {
            if (string.IsNullOrEmpty(ip)) return;
            try
            {
                var cached = RdapService.Instance.Cached(ip);
                if (cached != null && !cached.IsNegative && (!string.IsNullOrEmpty(cached.Netname) || !string.IsNullOrEmpty(cached.Org)))
                {
                    record.Provider = cached.Netname ?? cached.Org;
                    record.ProviderCountry = cached.Country;
                    return;
                }

                string classified = IpClassifier.Classify(ip);
                if (classified != "Unclassified")
                    record.Provider = classified;

                // Fire the network lookup; the row's provider arrives late
                // and the grid updates in place via INotifyPropertyChanged.
                if (cached == null)
                {
                    RdapService.Instance.LookupAsync(ip).ContinueWith(t =>
                    {
                        try
                        {
                            var entry = t.Result;
                            if (entry != null && !entry.IsNegative &&
                                (!string.IsNullOrEmpty(entry.Netname) || !string.IsNullOrEmpty(entry.Org)))
                            {
                                record.Provider = entry.Netname ?? entry.Org;
                                record.ProviderCountry = entry.Country;
                            }
                        }
                        catch { /* negative/failed lookup keeps the static classification */ }
                    }, TaskScheduler.Default);
                }
            }
            catch { /* attribution is never fatal */ }
        }

        // ── body cache ────────────────────────────────────────────────────

        public bool TryGetBodies(string id, out byte[] request, out byte[] response)
        {
            lock (_bodiesLock)
            {
                if (_bodies.TryGetValue(id, out var pair))
                {
                    request = pair.Request;
                    response = pair.Response;
                    return true;
                }
            }
            request = null;
            response = null;
            return false;
        }

        /// <summary>Loads bodies for an archived row into the live cache
        /// (from disk) so the viewer's selection path is uniform.</summary>
        public (byte[] Request, byte[] Response) LoadFromArchive(TransmissionRecord record)
        {
            byte[] request = TransmissionsArchiveService.LoadBody(record.Id, record.ArchiveDay, "request");
            byte[] response = TransmissionsArchiveService.LoadBody(record.Id, record.ArchiveDay, "response");
            if (request != null || response != null)
                CacheBodies(record.Id, request, response);
            return (request, response);
        }

        private void CacheBodies(string id, byte[] request, byte[] response)
        {
            long bytes = (request?.Length ?? 0) + (response?.Length ?? 0);
            lock (_bodiesLock)
            {
                if (_bodies.ContainsKey(id))
                {
                    var existing = _bodyOrder.First(n => n.Id == id);
                    _bodyOrder.Remove(existing);
                    _bodyCacheUsed -= existing.Bytes;
                }
                _bodies[id] = (request ?? Array.Empty<byte>(), response ?? Array.Empty<byte>());
                _bodyOrder.AddLast((id, bytes));
                _bodyCacheUsed += bytes;

                while (_bodyCacheUsed > BodyCacheBytes && _bodyOrder.Count > 1)
                {
                    var oldest = _bodyOrder.First.Value;
                    _bodyOrder.RemoveFirst();
                    _bodies.Remove(oldest.Id);
                    _bodyCacheUsed -= oldest.Bytes;
                }
            }
        }

        private static string RemoteIpOf(string endpoint) =>
            endpoint != null && endpoint.LastIndexOf(':') > 0 ? endpoint[..endpoint.LastIndexOf(':')] : endpoint;

        private static int RemotePortOf(string endpoint) =>
            endpoint != null && endpoint.LastIndexOf(':') > 0 &&
            int.TryParse(endpoint[(endpoint.LastIndexOf(':') + 1)..], out int port) ? port : 0;
    }

    /// <summary>Per-image counters for the "Apps without keys" suggestions:
    /// how many of this image's TLS flows decrypted, how many arrived
    /// encrypted with no keys, and enough about the most recent encrypted
    /// one (pid + time) to recover its command line from the Sysmon archive
    /// for a faithful restart-under-watch.</summary>
    public sealed class TransmissionsImageStats
    {
        public string Image { get; set; }
        public long DecryptedFlows { get; set; }
        public long EncryptedFlows { get; set; }
        public DateTime LastEncryptedUtc { get; set; }
        public int LastEncryptedPid { get; set; }
        public long LastEncryptedBiggestUpload { get; set; }

        public TransmissionsImageStats Clone() => (TransmissionsImageStats)MemberwiseClone();
    }

    internal static class FlowPortHelper
    {
        public static int RemotePortOrDefault(this TcpFlowRecord flow)
        {
            string endpoint = flow?.ServerEndpoint;
            if (endpoint == null) return 0;
            int colon = endpoint.LastIndexOf(':');
            return colon > 0 && int.TryParse(endpoint[(colon + 1)..], out int port) ? port : 0;
        }
    }
}
