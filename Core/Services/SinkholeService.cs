using System;
using AutoCommand.Engines.Bridge;
using AutoCommand.Engines.Watch;
using System.Diagnostics;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace AutoScope.Services
{
    /// <summary>One denied telemetry attempt, as observed by the sinkhole.</summary>
    public class TelemetryDeniedAttempt
    {
        public DateTime TimeUtc { get; set; }
        public string Hostname { get; set; }        // TLS SNI; "(no SNI)" when the client sent none
        public string PeerEndpoint { get; set; }    // client's loopback endpoint
        public int Pid { get; set; }
        public string ProcessImage { get; set; }
        public string CommandLine { get; set; }
        public string DeniedBy { get; set; } = "sinkhole";
    }

    public enum SinkholeStatus { Inactive, Listening, PortBusy, Error }

    /// <summary>
    /// The telemetry sinkhole: a loopback listener on 127.0.0.1:443 that exists so
    /// hosts-pinned telemetry attempts become visible. Pinned names resolve to
    /// loopback, the client completes a TCP handshake and sends its ClientHello —
    /// from which the intended hostname (SNI) is read — and the connection is then
    /// closed without any TLS reply. The peer PID is captured from the OS
    /// connection table while the socket is live, and the process image and
    /// command line are resolved via WMI. Nothing is ever sent back.
    /// </summary>
    public sealed class SinkholeService
    {
        public static SinkholeService Instance { get; } = new();

        public event Action<TelemetryDeniedAttempt> OnAttempt;
        public event Action StatusChanged;

        public SinkholeStatus Status { get; private set; } = SinkholeStatus.Inactive;
        public string StatusDetail { get; private set; }

        private TcpListener _listener;
        private CancellationTokenSource _cts;

        private SinkholeService() { }

        /// <summary>
        /// Starts listening when any marked hosts pin currently points at
        /// 127.0.0.1. Safe to call repeatedly; no sinkhole pins means inactive.
        /// </summary>
        public void EnsureRunningForCurrentPins()
        {
            var pins = HostsTelemetryPins.ReadLive();
            if (!HostsTelemetryPins.AnySinkhole(pins))
            {
                Stop();
                StatusDetail = "No hosts pin currently points at the sinkhole.";
                StatusChanged?.Invoke();
                return;
            }
            Start();
        }

        public void Start()
        {
            if (_listener != null) return;   // already listening
            try
            {
                _cts = new CancellationTokenSource();
                _listener = new TcpListener(IPAddress.Loopback, 443);
                _listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, false);
                _listener.Start();
                Status = SinkholeStatus.Listening;
                StatusDetail = "Listening on 127.0.0.1:443 — attempts will be logged and dropped.";
                _ = Task.Run(() => AcceptLoopAsync(_cts.Token));
            }
            catch (SocketException ex)
            {
                // Port 443 on loopback is owned by something else (a local dev
                // server is the usual suspect) — stay silent rather than compete
                _listener = null;
                _cts?.Dispose();
                _cts = null;
                Status = SinkholeStatus.PortBusy;
                StatusDetail = $"127.0.0.1:443 is already in use ({ex.SocketErrorCode}) — the pin still blocks, " +
                               "but attempts reach that server instead of the sinkhole. Free the port or switch the pin back to 0.0.0.0.";
            }
            catch (Exception ex)
            {
                _listener = null;
                _cts?.Dispose();
                _cts = null;
                Status = SinkholeStatus.Error;
                StatusDetail = $"Sinkhole could not start: {ex.Message}";
            }
            StatusChanged?.Invoke();
        }

        public void Stop()
        {
            if (_listener == null)
            {
                if (Status != SinkholeStatus.Inactive)
                {
                    Status = SinkholeStatus.Inactive;
                    StatusDetail = null;
                    StatusChanged?.Invoke();
                }
                return;
            }
            try { _cts?.Cancel(); } catch { }
            try { _listener.Stop(); } catch { }
            _listener = null;
            _cts?.Dispose();
            _cts = null;
            Status = SinkholeStatus.Inactive;
            StatusDetail = null;
            StatusChanged?.Invoke();
        }

        private async Task AcceptLoopAsync(CancellationToken ct)
        {
            var listener = _listener;
            while (!ct.IsCancellationRequested)
            {
                Socket client;
                try { client = await listener.AcceptSocketAsync(); }
                catch (ObjectDisposedException) { break; }   // Stop() called
                catch (SocketException) { continue; }
                _ = Task.Run(() => Handle(client), ct);
            }
        }

        private void Handle(Socket client)
        {
            TelemetryDeniedAttempt attempt = null;
            try
            {
                // The peer PID only exists in the connection table while the
                // socket is live — attribute before anything else
                int pid = FindPeerPid((IPEndPoint)client.RemoteEndPoint);
                string sni = ReadClientHelloSni(client);
                attempt = new TelemetryDeniedAttempt
                {
                    TimeUtc = DateTime.UtcNow,
                    Hostname = string.IsNullOrEmpty(sni) ? "(no SNI)" : sni,
                    PeerEndpoint = client.RemoteEndPoint.ToString(),
                    Pid = pid,
                };
                if (pid > 0) EnrichFromWmi(pid, attempt);
            }
            catch { /* a half-open or hostile client is still a denied attempt at worst */ }
            finally
            {
                try { client.Close(); } catch { }   // no reply, ever
                if (attempt != null)
                {
                    Debug.WriteLine($"[sinkhole] denied {attempt.Hostname} from pid {attempt.Pid}");
                    OnAttempt?.Invoke(attempt);
                }
            }
        }

        /// <summary>Reads just enough of the stream for the ClientHello, then stops.</summary>
        private static string ReadClientHelloSni(Socket client)
        {
            client.ReceiveTimeout = 3000;
            var buffer = new byte[4096];
            int total = 0;
            try
            {
                while (total < buffer.Length)
                {
                    int n = client.Receive(buffer, total, buffer.Length - total, SocketFlags.None);
                    if (n <= 0) break;
                    total += n;
                    if (TlsSni.TryReadSni(buffer, total) != null) break;   // complete hello read
                }
            }
            catch (SocketException) { /* timeout or reset — parse whatever arrived */ }
            return TlsSni.TryReadSni(buffer, total);
        }

        private static void EnrichFromWmi(int pid, TelemetryDeniedAttempt attempt)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ProcessId, ExecutablePath, CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (var row in searcher.Get())
                {
                    attempt.ProcessImage = row["ExecutablePath"] as string;
                    attempt.CommandLine = row["CommandLine"] as string;
                    break;
                }
            }
            catch { /* process may have exited mid-query — pid alone is still useful */ }
            if (string.IsNullOrEmpty(attempt.ProcessImage))
            {
                try { attempt.ProcessImage = Process.GetProcessById(pid)?.MainModule?.FileName; }
                catch { /* gone or inaccessible */ }
            }
        }

        // ------------------------------------------------------------------
        // Peer PID attribution via the OS connection table (iphlpapi)
        // ------------------------------------------------------------------

        private const int AfInet = 2;
        private const int TcpTableOwnerPidAll = 5;
        private static readonly uint LoopbackBytes = BitConverter.ToUInt32(new byte[] { 127, 0, 0, 1 }, 0);

        [DllImport("iphlpapi.dll")]
        private static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int size, bool order, int af, int tableClass, int reserved);

        /// <summary>
        /// Finds the PID owning the client side of a loopback connection to
        /// 127.0.0.1:443 — a table row whose local endpoint is the peer and whose
        /// remote endpoint is the listener. Must run while that side is still open.
        /// </summary>
        private static int FindPeerPid(IPEndPoint peer)
        {
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
            if (size <= 0) return 0;

            var table = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(table, ref size, false, AfInet, TcpTableOwnerPidAll, 0) != 0)
                    return 0;

                int rows = Marshal.ReadInt32(table);
                long rowPtr = table + 4;   // DWORD dwNumEntries, then MIB_TCPROW_OWNER_PID rows:
                                           // state(4) localAddr(4) localPort(4) remoteAddr(4) remotePort(4) pid(4)
                for (int i = 0; i < rows; i++, rowPtr += 24)
                {
                    uint localAddr = (uint)Marshal.ReadInt32((IntPtr)(rowPtr + 4));
                    uint localPort = (uint)Marshal.ReadInt32((IntPtr)(rowPtr + 8)) & 0xFFFF;
                    uint remoteAddr = (uint)Marshal.ReadInt32((IntPtr)(rowPtr + 12));
                    uint remotePort = (uint)Marshal.ReadInt32((IntPtr)(rowPtr + 16)) & 0xFFFF;
                    uint pid = (uint)Marshal.ReadInt32((IntPtr)(rowPtr + 20));

                    if (remoteAddr == LoopbackBytes && Swap16((ushort)remotePort) == 443
                        && Swap16((ushort)localPort) == peer.Port && localAddr == LoopbackBytes)
                        return (int)pid;
                }
                return 0;
            }
            finally { Marshal.FreeHGlobal(table); }
        }

        private static ushort Swap16(ushort v) => (ushort)((v >> 8) | (v << 8));
    }
}
