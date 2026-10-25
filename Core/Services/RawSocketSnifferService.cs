using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using AutoScope.Models;

namespace AutoScope.Services
{
    public class RawSocketSnifferService
    {
        private readonly ConcurrentDictionary<string, SvchostMonitorItem> _trackedIps;
        private CancellationTokenSource _cts;
        private Socket _mainSocket;   // IPv4 capture — the primary path
        private Socket _v6Socket;     // IPv6 capture — best-effort companion

        public event Action<string> OnError;

        public RawSocketSnifferService(ConcurrentDictionary<string, SvchostMonitorItem> trackedIps)
        {
            _trackedIps = trackedIps;
        }

        public void Start()
        {
            _cts = new CancellationTokenSource();

            Task.Run(() =>
            {
                try
                {
                    IPAddress localIp = GetLocalIpAddress();
                    if (localIp == null)
                    {
                        OnError?.Invoke("Could not determine local IP address for raw socket binding.");
                        return;
                    }

                    _mainSocket = CreateReceiveAllSocket(AddressFamily.InterNetwork, localIp);
                    ReceiveLoop(_mainSocket, ParseIpv4Packet);
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
                {
                    OnError?.Invoke("Raw socket binding failed: Access Denied. Ensure the application is running as Administrator.");
                }
                catch (Exception ex)
                {
                    OnError?.Invoke($"Raw socket sniffer error: {ex.Message}");
                }
                finally
                {
                    _mainSocket?.Close();
                }
            }, _cts.Token);

            Task.Run(() =>
            {
                // IPv6 capture is best-effort: some environments refuse a v6
                // raw socket, and a failure here must not disable the working
                // v4 path (OnError stops the whole monitor), so it stays
                // silent — IPv6 rows then rely on their Sysmon-seeded
                // LastSeen for the "Last Update" column.
                try
                {
                    IPAddress localIp = GetLocalIpv6Address() ?? IPAddress.IPv6Any;
                    _v6Socket = CreateReceiveAllSocket(AddressFamily.InterNetworkV6, localIp);
                    ReceiveLoop(_v6Socket, ParseIpv6Packet);
                }
                catch { }
                finally
                {
                    _v6Socket?.Close();
                }
            }, _cts.Token);
        }

        public void Stop()
        {
            _cts?.Cancel();
            _mainSocket?.Close();
            _v6Socket?.Close();
        }

        /// <summary>Creates a raw socket bound to the given local address with SIO_RCVALL enabled.</summary>
        private static Socket CreateReceiveAllSocket(AddressFamily family, IPAddress localIp)
        {
            bool v4 = family == AddressFamily.InterNetwork;
            var socket = new Socket(family, SocketType.Raw, v4 ? ProtocolType.IP : ProtocolType.IPv6);
            socket.Bind(new IPEndPoint(localIp, 0));
            socket.SetSocketOption(
                v4 ? SocketOptionLevel.IP : SocketOptionLevel.IPv6,
                SocketOptionName.HeaderIncluded, true);

            // RCVALL_ON
            byte[] inValue = new byte[] { 1, 0, 0, 0 };
            byte[] outValue = new byte[] { 0, 0, 0, 0 };
            socket.IOControl(IOControlCode.ReceiveAll, inValue, outValue);
            return socket;
        }

        private void ReceiveLoop(Socket socket, Action<byte[], int> parsePacket)
        {
            byte[] buffer = new byte[65535];
            // Using a reasonable timeout so we can still check for cancellation periodically
            socket.ReceiveTimeout = 2000;

            while (!_cts.Token.IsCancellationRequested)
            {
                try
                {
                    // Blocking call to prevent CPU spinning.
                    // ReceiveTimeout ensures it unblocks occasionally to check _cts.
                    int bytesRead = socket.Receive(buffer);
                    if (bytesRead > 0)
                    {
                        parsePacket(buffer, bytesRead);
                    }
                }
                catch (SocketException ex)
                {
                    // SocketError.TimedOut is expected and normal due to ReceiveTimeout
                    if (ex.SocketErrorCode != SocketError.TimedOut &&
                        ex.SocketErrorCode != SocketError.Interrupted &&
                        ex.SocketErrorCode != SocketError.WouldBlock)
                    {
                        // Log unexpected socket errors if necessary, but keep the loop running
                        // unless it's a critical error (like socket closed)
                    }
                }
                catch (ObjectDisposedException)
                {
                    break; // Stop() closed the socket under us — normal shutdown, not an error
                }
            }
        }

        private void ParseIpv4Packet(byte[] buffer, int length)
        {
            try
            {
                if (length < 20) return; // minimum IPv4 header

                // IPv4 header addresses are at offset 12 (src) and 16 (dst)
                AttributePacket(
                    new IPAddress(new ReadOnlySpan<byte>(buffer, 12, 4)),
                    new IPAddress(new ReadOnlySpan<byte>(buffer, 16, 4)),
                    length);
            }
            catch { }
        }

        private void ParseIpv6Packet(byte[] buffer, int length)
        {
            try
            {
                if (length < 40) return; // fixed IPv6 header size

                // IPv6 header addresses sit at offset 8 (src) and 24 (dst);
                // they stay put even when extension headers follow
                AttributePacket(
                    new IPAddress(new ReadOnlySpan<byte>(buffer, 8, 16)),
                    new IPAddress(new ReadOnlySpan<byte>(buffer, 24, 16)),
                    length);
            }
            catch { }
        }

        /// <summary>Attributes one observed packet to any tracked row matching its endpoints.</summary>
        private void AttributePacket(IPAddress source, IPAddress destination, int length)
        {
            // Remote IP as source = reply traffic (receive)
            if (_trackedIps.TryGetValue(source.ToString(), out var srcItem))
            {
                srcItem.RxPackets++;
                srcItem.RxBytes += length;
                srcItem.LastSeen = DateTime.UtcNow;
            }

            // Remote IP as destination = traffic leaving (transmit)
            if (_trackedIps.TryGetValue(destination.ToString(), out var dstItem))
            {
                dstItem.TxPackets++;
                dstItem.TxBytes += length;
                dstItem.LastSeen = DateTime.UtcNow;
            }
        }

        private static IPAddress GetLocalIpAddress()
        {
            try
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0);
                socket.Connect("8.8.8.8", 65530); // Connects to a dummy external IP to resolve routing table local IP
                var endPoint = socket.LocalEndPoint as IPEndPoint;
                return endPoint?.Address;
            }
            catch
            {
                // Fallback to DNS
                var host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (var ip in host.AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                        return ip;
                }
                return null;
            }
        }

        /// <summary>
        /// Local IPv6 address the default route uses, or null when the
        /// machine has no IPv6 connectivity.
        /// </summary>
        private static IPAddress GetLocalIpv6Address()
        {
            try
            {
                using var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, 0);
                socket.Connect(IPAddress.Parse("2001:4860:4860::8888"), 65530);
                return (socket.LocalEndPoint as IPEndPoint)?.Address;
            }
            catch
            {
                return null;
            }
        }
    }
}
