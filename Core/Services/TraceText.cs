using System.Net;
using AutoScope.Engines.Bridge;
using AutoScope.Engines.Watch;
using System.Net.Sockets;
using System.Text;
using AutoScope.Models;

namespace AutoScope.Services
{
    /// <summary>
    /// Plain-text rendering helpers ported from AutoCommand's SvchostTraceView
    /// and ProcessTraceWindow so the AI tool registry (AgentToolRegistry) can
    /// produce the same output without referencing any view code.
    /// </summary>
    public static class TraceText
    {
        private static readonly (string Name, string[] Cidrs)[] Ranges =
        {
            ("Microsoft/Azure", new[] { "20.0.0.0/8", "40.0.0.0/8", "13.64.0.0/11", "13.104.0.0/14",
                                        "52.96.0.0/12", "52.112.0.0/14", "65.52.0.0/14", "72.145.32.0/19", "172.176.0.0/12" }),
            ("Akamai (MS CDN)", new[] { "23.32.0.0/11", "23.192.0.0/11", "2.16.0.0/13", "95.100.0.0/15", "184.24.0.0/13", "104.64.0.0/10" }),
            ("Gcore (MS CDN)",  new[] { "92.223.0.0/16" }),
        };

        /// <summary>Classifies a remote IPv4 address against known Microsoft
        /// CDN/Azure ranges (ported verbatim from SvchostTraceView).</summary>
        public static string Classify(string ip)
        {
            if (!IPAddress.TryParse(ip, out var addr) || addr.AddressFamily != AddressFamily.InterNetwork)
                return "IPv6/other";
            var b = addr.GetAddressBytes();
            uint v = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
            foreach (var (name, cidrs) in Ranges)
                foreach (var cidr in cidrs)
                {
                    var parts = cidr.Split('/');
                    var nb = IPAddress.Parse(parts[0]).GetAddressBytes();
                    uint net = (uint)(nb[0] << 24 | nb[1] << 16 | nb[2] << 8 | nb[3]);
                    uint mask = uint.MaxValue << (32 - int.Parse(parts[1]));
                    if ((v & mask) == (net & mask)) return name;
                }
            return "UNCLASSIFIED";
        }

        /// <summary>Renders a PID-inquiry provenance report as plain text
        /// (ported verbatim from ProcessTraceWindow).</summary>
        public static string BuildReportText(ProvenanceReport r)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"PID INQUIRY — {r.Pid} · {r.Name}");
            sb.AppendLine($"Verdict: {r.Verdict} — {r.VerdictDetail}");
            sb.AppendLine($"Identity: image {r.ExePath ?? "?"} · started {r.Created:yyyy-MM-dd HH:mm:ss} · " +
                          $"owner {r.Owner ?? "?"} · {(r.Alive ? "running" : "not running")}");
            if (!string.IsNullOrEmpty(r.CommandLine))
                sb.AppendLine("Command line: " + r.CommandLine);
            if (r.Recycled && !string.IsNullOrEmpty(r.CurrentOwnerSummary))
            {
                sb.AppendLine();
                sb.AppendLine("⚠ PID RECYCLED — the subject above has EXITED. The PID now belongs to:");
                sb.AppendLine("      " + r.CurrentOwnerSummary);
                sb.AppendLine("      (unrelated process — everything below describes the exited subject)");
            }
            sb.AppendLine();
            sb.AppendLine("SPAWN CHAIN (child → root):");
            foreach (var link in r.Chain)
            {
                sb.AppendLine($"  PID {link.Pid} · {link.Name} · {link.Created:yyyy-MM-dd HH:mm:ss} · " +
                              $"{link.Owner ?? "?"}{(link.Verified ? "" : "   [UNVERIFIED]")}");
                if (!string.IsNullOrEmpty(link.CommandLine)) sb.AppendLine("      cmd: " + link.CommandLine);
                if (!string.IsNullOrEmpty(link.Note)) sb.AppendLine("      note: " + link.Note);
            }
            sb.AppendLine();
            sb.AppendLine("EVIDENCE:");
            foreach (var ev in r.Evidence)
                sb.AppendLine($"  [{ev.Source}] {ev.Detail.Replace("\r\n      ", "\r\n       ")}");
            if (r.Warnings.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("WARNINGS:");
                foreach (string w in r.Warnings) sb.AppendLine("  " + w);
            }
            sb.AppendLine();
            sb.AppendLine($"Generated {DateTime.Now:yyyy-MM-dd HH:mm:ss} by AutoScope Process Monitor (read-only inquiry)");
            return sb.ToString();
        }
    }
}
