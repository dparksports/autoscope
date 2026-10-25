using System;
using System.Collections.Generic;
using System.Linq;
using AutoScope.Models;

namespace AutoScope.Services
{
    /// <summary>
    /// Passive evidence engine behind the Site Doctor tab: groups the
    /// Transmissions archive by SNI hostname and reads the behavioral
    /// fingerprint out of what is already on disk — no packets sent, nothing
    /// guessed. Three signals, each one observed in the wild while diagnosing
    /// a real "this site refreshes slowly" report:
    ///
    ///   • Edge dispersion  — a browser that keeps landing on fresh server
    ///     addresses (4+ in an hour) is being steered around, usually by
    ///     short-TTL CDN DNS. Healthy sites sit on 1–2 addresses; the
    ///     baseline is computed from the machine's own other traffic.
    ///   • Connection bursts — 3+ conversations to one hostname opened
    ///     within the same five seconds is a browser racing retries after a
    ///     stall, not normal keep-alive usage.
    ///   • Single-edge churn — repeated new connections to the same address
    ///     within a minute, the shape of handshakes that complete and then
    ///     die before the browser will reuse them.
    ///
    /// Evidence, not verdict: the archive only records conversations worth
    /// keeping (&gt;10 KB uploads or decrypted bodies), so counts are a
    /// sample, never the whole story. The verdict engine weighs this
    /// fingerprint together with active probe results.
    /// </summary>
    public static class SiteFingerprintService
    {
        /// <summary>Burst window: 3+ conversation starts this close together.</summary>
        public static readonly TimeSpan BurstWindow = TimeSpan.FromSeconds(5);
        /// <summary>Dispersion floor: this many distinct edges flags steering
        /// even when the machine-wide baseline is unusually high.</summary>
        public const int EdgeDispersionFloor = 4;
        /// <summary>Minimum conversations before a host is worth judging.</summary>
        public const int MinConversations = 3;

        public sealed class EdgeStat
        {
            public string Ip { get; set; }
            public int Conversations { get; set; }
        }

        public sealed class SiteFingerprint
        {
            public string Host { get; set; }
            public DateTime FirstUtc { get; set; }
            public DateTime LastUtc { get; set; }
            public int Conversations { get; set; }
            public long ClientBytes { get; set; }
            public List<EdgeStat> Edges { get; set; } = new();
            public List<string> Processes { get; set; } = new();

            /// <summary>5-second windows containing 3+ conversation starts.</summary>
            public int BurstWindows { get; set; }
            public DateTime? FirstBurstUtc { get; set; }

            /// <summary>Most conversations opened to a single edge in any one minute.</summary>
            public int MaxSameEdgePerMinute { get; set; }

            /// <summary>Plain-English observations — one line per signal that fired.</summary>
            public List<string> Signals { get; set; } = new();

            /// <summary>True when at least one signal fired. Evidence for the
            /// verdict engine; never shown to the user as a conclusion.</summary>
            public bool LooksStruggling => Signals.Count > 0;

            public string SpanDisplay =>
                FirstUtc == default || LastUtc == default ? ""
                : $"{FirstUtc.ToLocalTime():MM-dd HH:mm} → {LastUtc.ToLocalTime():HH:mm}";
        }

        /// <summary>
        /// Browser process names recognized for the tab's "sites from" filter.
        /// Matched case-insensitively against the row's process filename with
        /// or without .exe — any other process is "apps", never a browser.
        /// </summary>
        private static readonly string[] KnownBrowsers =
        {
            "chrome", "brave", "firefox", "msedge", "edge", "opera", "vivaldi",
            "librewolf", "waterfox", "thorium", "chromium", "iron", "avastbrowser",
            "duckduckgo", "arc", "zen"
        };

        internal static bool IsBrowserProcess(string processDisplay)
        {
            if (string.IsNullOrEmpty(processDisplay)) return false;
            string name = processDisplay.Trim().ToLowerInvariant();
            if (name.EndsWith(".exe")) name = name[..^4];
            return KnownBrowsers.Contains(name);
        }

        /// <summary>
        /// Browsers with recorded conversations, busiest first — the tab's
        /// "sites from" filter list. Every user's list is their own: it comes
        /// from what they actually browse, never a hard-coded site roster.
        /// </summary>
        public static List<string> BrowsersSeen(List<TransmissionRecord> rows, int max = 8) =>
            rows?
                .Where(r => !string.IsNullOrEmpty(r.Sni) && IsBrowserProcess(r.ProcessDisplay))
                .GroupBy(r => r.ProcessDisplay.Trim().ToLowerInvariant().Replace(".exe", ""))
                .OrderByDescending(g => g.Count())
                .Take(max)
                .Select(g => g.Key)
                .ToList() ?? new List<string>();

        /// <summary>Hostnames worth offering in the tab's picker, busiest first.
        /// With <paramref name="browser"/> set, only that browser's recorded
        /// traffic counts — "the sites I actually visit in Chrome" instead of
        /// someone else's idea of popular.</summary>
        public static List<string> TopHosts(List<TransmissionRecord> rows, int maxHosts = 25,
            string browser = null)
        {
            IEnumerable<TransmissionRecord> source = rows?
                .Where(r => !string.IsNullOrEmpty(r.Sni)) ?? Array.Empty<TransmissionRecord>();
            if (!string.IsNullOrEmpty(browser))
            {
                string want = browser.Trim().ToLowerInvariant();
                source = source.Where(r =>
                {
                    string name = (r.ProcessDisplay ?? "").Trim().ToLowerInvariant();
                    return name == want || name == want + ".exe";
                });
            }
            return source
                .GroupBy(r => r.Sni, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .ThenByDescending(g => g.Max(r => r.TsUtc))
                .Take(maxHosts)
                .Select(g => g.Key)
                .ToList();
        }

        /// <summary>Every host's fingerprint; the input to the machine-wide baseline.</summary>
        public static Dictionary<string, SiteFingerprint> AllFingerprints(List<TransmissionRecord> rows)
        {
            var all = new Dictionary<string, SiteFingerprint>(StringComparer.OrdinalIgnoreCase);
            if (rows == null) return all;
            foreach (var group in rows.Where(r => !string.IsNullOrEmpty(r.Sni))
                                      .GroupBy(r => r.Sni, StringComparer.OrdinalIgnoreCase))
            {
                var fp = Fingerprint(group.ToList());
                if (fp.Conversations > 0) all[group.Key] = fp;
            }
            return all;
        }

        /// <summary>
        /// The machine-wide control: median distinct-edge count across every
        /// host with enough conversations to judge. A site using many times
        /// more edges than the machine's own norm is the dispersion signal.
        /// </summary>
        public static int BaselineEdgeCount(Dictionary<string, SiteFingerprint> all)
        {
            var counts = all.Values
                .Where(f => f.Conversations >= MinConversations)
                .Select(f => f.Edges.Count)
                .OrderBy(n => n)
                .ToList();
            if (counts.Count == 0) return 1;
            return counts.Count % 2 == 1
                ? counts[counts.Count / 2]
                : Math.Max(1, (counts[counts.Count / 2 - 1] + counts[counts.Count / 2]) / 2);
        }

        /// <summary>
        /// Fingerprint one host's rows (callers filter by SNI; the method is
        /// pure so the offline self-test can feed synthetic records).
        /// </summary>
        public static SiteFingerprint Fingerprint(List<TransmissionRecord> siteRows, int baselineEdges = 1)
        {
            var fp = new SiteFingerprint
            {
                Conversations = siteRows?.Count ?? 0,
                ClientBytes = siteRows?.Sum(r => r.ClientBytes) ?? 0,
                Processes = siteRows?
                    .Where(r => !string.IsNullOrEmpty(r.ProcessDisplay))
                    .Select(r => r.ProcessDisplay)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList() ?? new List<string>(),
            };
            if (siteRows == null || siteRows.Count == 0) return fp;

            var byTime = siteRows.OrderBy(r => r.TsUtc).ToList();
            fp.Host = byTime[0].Sni;
            fp.FirstUtc = byTime[0].TsUtc;
            fp.LastUtc = byTime[^1].TsUtc;

            fp.Edges = byTime
                .GroupBy(r => r.RemoteIp, StringComparer.OrdinalIgnoreCase)
                .Select(g => new EdgeStat { Ip = g.Key, Conversations = g.Count() })
                .OrderByDescending(e => e.Conversations)
                .ToList();

            // Bursts: sliding 5-second windows with 3+ starts (same host).
            int burst = 0;
            for (int i = 0; i < byTime.Count; i++)
            {
                int j = i;
                while (j < byTime.Count && byTime[j].TsUtc - byTime[i].TsUtc <= BurstWindow) j++;
                if (j - i >= 3)
                {
                    burst++;
                    fp.FirstBurstUtc ??= byTime[i].TsUtc;
                    i = j - 1; // skip past the burst; overlapping windows count once
                }
            }
            fp.BurstWindows = burst;

            // Single-edge churn: busiest rolling minute for any one edge.
            foreach (var edgeGroup in byTime.GroupBy(r => r.RemoteIp, StringComparer.OrdinalIgnoreCase))
            {
                var times = edgeGroup.Select(r => r.TsUtc).OrderBy(t => t).ToList();
                for (int i = 0; i < times.Count; i++)
                {
                    int j = i;
                    while (j < times.Count && times[j] - times[i] <= TimeSpan.FromMinutes(1)) j++;
                    fp.MaxSameEdgePerMinute = Math.Max(fp.MaxSameEdgePerMinute, j - i);
                }
            }

            fp.Signals = BuildSignals(fp, baselineEdges);
            return fp;
        }

        private static List<string> BuildSignals(SiteFingerprint fp, int baselineEdges)
        {
            var signals = new List<string>();
            if (fp.Conversations < MinConversations) return signals;

            TimeSpan span = fp.LastUtc - fp.FirstUtc;
            int dispersionBar = Math.Max(EdgeDispersionFloor, baselineEdges + 2);
            if (fp.Edges.Count >= dispersionBar)
                signals.Add(
                    $"Used {fp.Edges.Count} different server addresses in " +
                    $"{(int)span.TotalMinutes} minutes (this machine's other sites typically sit on {baselineEdges}).");

            if (fp.BurstWindows > 0 && fp.FirstBurstUtc.HasValue)
                signals.Add(
                    $"{fp.BurstWindows} burst{(fp.BurstWindows == 1 ? "" : "s")} of 3+ connections within five seconds " +
                    $"(first at {fp.FirstBurstUtc.Value.ToLocalTime():HH:mm:ss}) — the shape of a browser retrying after a stall.");

            if (fp.MaxSameEdgePerMinute >= 4)
                signals.Add(
                    $"Opened {fp.MaxSameEdgePerMinute} connections to one server address within a minute — " +
                    "healthy keep-alive reuses a connection instead of replacing it.");

            return signals;
        }
    }
}
