using System;

namespace AutoScope.Models
{
    /// <summary>
    /// A finalized TCP conversation: both directions' reassembled byte
    /// streams (client = SYN sender), byte counts, and — when a Sysmon EID 3
    /// connect matched the flow's endpoints — the python pid/image that
    /// opened it. PID attribution is by-endpoint-at-connect-time: it is the
    /// process that connected with this exact 4-tuple, not a per-packet fact.
    /// </summary>
    public class TcpFlowRecord
    {
        public string Key { get; set; }
        public string ClientEndpoint { get; set; }   // ip:port of the SYN sender
        public string ServerEndpoint { get; set; }
        public DateTime StartedUtc { get; set; }
        public DateTime EndedUtc { get; set; }
        public long ClientBytes { get; set; }
        public long ServerBytes { get; set; }
        public bool FinBoth { get; set; }
        public bool Reset { get; set; }

        /// <summary>True when the per-flow byte cap dropped middle bytes (head+tail kept).</summary>
        public bool Truncated { get; set; }

        public int Pid { get; set; }
        public string Image { get; set; }

        /// <summary>Reassembled client→server bytes (handshake included).</summary>
        public byte[] ClientData { get; set; }

        /// <summary>Reassembled server→client bytes (handshake included).</summary>
        public byte[] ServerData { get; set; }

        public string Display =>
            $"{ClientEndpoint} → {ServerEndpoint}  {FormatBytes(ClientBytes)}↑ {FormatBytes(ServerBytes)}↓" +
            (Pid > 0 ? $"  pid {Pid}" : "  unattributed") +
            (Truncated ? "  (truncated)" : "");

        public string TimeDisplay => StartedUtc.ToLocalTime().ToString("HH:mm:ss");

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes}B";
            if (bytes < 1048576) return $"{bytes / 1024.0:F0}KB";
            return $"{bytes / 1048576.0:F1}MB";
        }
    }
}
