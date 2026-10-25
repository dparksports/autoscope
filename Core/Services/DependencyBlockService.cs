using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AutoScope.Models;

namespace AutoScope.Services
{
    /// <summary>
    /// The evidence pass behind the DependencyBlocked verdict: "the site's
    /// own servers are fine — something the PAGE depends on is on this
    /// machine's own block list."
    ///
    /// Why this exists: Windows Firewall blocks silently in the kernel, and
    /// a login page whose captcha or asset host is blocked shows a generic
    /// error while the site's own servers answer perfectly. The probe half
    /// of the Site Doctor can't see that — it measures the typed host, and
    /// the decisive evidence carries no hostname at all: a blocked connect
    /// dies before the TLS ClientHello, so it never enters the transmissions
    /// archive with an SNI. The only record is Sysmon EID 3 joined against
    /// the block inventory. This pass makes that join visible: it anchors on
    /// the archive's page loads ("browser X fetched host H at T"), pulls
    /// blocked connects from the same browser inside ±2 minutes of those
    /// loads, attributes each blocked address by what it has served on this
    /// machine (recorded SNI history), and the live half (DependencyBlock
    /// Service.Live.cs) quantifies the DNS rotation that makes the fault
    /// intermittent.
    ///
    /// Honesty rules, same as every engine: a blocked connect is called
    /// causal only when it falls inside a visit window; hits outside it are
    /// kept as context and never drive the verdict; attribution never
    /// guesses past recorded history.
    ///
    /// This file is the pure core — archive records + lite feed rows in,
    /// report out, no live-service dependencies — so the offline self-test
    /// compiles it byte-identical to what ships.
    /// </summary>
    public static partial class DependencyBlockService
    {
        /// <summary>How close to a recorded page load a blocked connect must
        /// fall to count as part of that visit.</summary>
        public const double VisitWindowSeconds = 120;

        /// <summary>How close in time (and same PID) another fetched host
        /// must be to count as a dependency of the page being loaded.</summary>
        public const double CoVisitSeconds = 5;

        /// <summary>Feed-row shape the core join accepts — decoupled from
        /// BlockHitFeedService's own types so this file compiles standalone
        /// in the self-test.</summary>
        public sealed class BlockHitLite
        {
            public DateTime TimeUtc { get; set; }
            public string Image { get; set; }
            public int Pid { get; set; }
            public string DestIp { get; set; }
            public string MatchKind { get; set; }   // "ip" | "app"
        }

        /// <summary>Block-inventory answer shape, same decoupling.</summary>
        public sealed class BlockInfoLite
        {
            public string Class;
            public DateTime? Created;
        }

        public sealed class Hit
        {
            public string Ip;
            public string Process;               // connecting process filename
            public int Attempts;
            public DateTime FirstUtc, LastUtc;
            public string BlockClass;            // inventory class, when known
            public DateTime? BlockedSince;       // rule provenance, when known
            /// <summary>Hostnames recorded traffic shows this address
            /// serving on THIS machine — attribution, never a guess.</summary>
            public List<string> ServedHosts = new();
        }

        public sealed class RotationFact
        {
            public string Host;
            public int BlockedAddresses, TotalAddresses;
        }

        public sealed class Report
        {
            public string Host;
            public List<DateTime> VisitTimesUtc = new();
            /// <summary>Blocked connects inside a visit window — the causal set.</summary>
            public List<Hit> InWindow = new();
            /// <summary>Same browsers, same lookback, outside every window — context only.</summary>
            public List<Hit> Nearby = new();
            /// <summary>Hosts the visiting browser fetched within seconds of a
            /// page load — the page's recorded dependencies.</summary>
            public List<string> CoVisitedHosts = new();
            /// <summary>Dependency hosts whose current DNS answers partly land
            /// on the block list — the intermittency explanation.</summary>
            public List<RotationFact> Rotations = new();
            public bool Any => InWindow.Count > 0;
        }

        /// <summary>
        /// Offline core: the whole join over caller-supplied inputs, so the
        /// self-test can prove it against synthetic fixtures. Anchors are
        /// page loads of <paramref name="host"/> inside the archive rows
        /// (optionally gated by <paramref name="anchorSinceUtc"/>); hits are
        /// block-feed rows for the same browsers.
        /// </summary>
        public static Report Analyze(
            string host,
            List<TransmissionRecord> rows,
            List<BlockHitLite> hits,
            Func<string, BlockInfoLite> blockedLookup,
            DateTime? anchorSinceUtc = null)
        {
            var report = new Report { Host = host };
            if (string.IsNullOrEmpty(host) || rows == null || rows.Count == 0) return report;

            var siteRows = rows
                .Where(r => string.Equals(r.Sni, host, StringComparison.OrdinalIgnoreCase) &&
                            (anchorSinceUtc == null || r.TsUtc >= anchorSinceUtc.Value))
                .ToList();
            if (siteRows.Count == 0) return report;   // no recorded visit → nothing to anchor on

            report.VisitTimesUtc = siteRows.Select(r => r.TsUtc).Distinct().OrderBy(t => t).ToList();

            // The browsers that made those page loads — matched by full image
            // path, with the filename as the portable fallback.
            var visitorImages = siteRows
                .Where(r => !string.IsNullOrEmpty(r.Image))
                .Select(r => r.Image)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var visitorStems = visitorImages
                .Select(Path.GetFileName)
                .Where(n => !string.IsNullOrEmpty(n))
                .Select(n => n.ToLowerInvariant())
                .ToHashSet();

            bool FromVisitor(BlockHitLite h) =>
                visitorImages.Contains(h.Image) ||
                visitorStems.Contains((Path.GetFileName(h.Image) ?? "").ToLowerInvariant());

            bool InWindow(DateTime t) => report.VisitTimesUtc.Any(v =>
                Math.Abs((t - v).TotalSeconds) <= VisitWindowSeconds);

            foreach (var g in (hits ?? new List<BlockHitLite>())
                     .Where(h => h.MatchKind == "ip" && !string.IsNullOrEmpty(h.DestIp) && FromVisitor(h))
                     .GroupBy(h => h.DestIp, StringComparer.OrdinalIgnoreCase))
            {
                var list = g.OrderByDescending(h => h.TimeUtc).ToList();
                var info = blockedLookup?.Invoke(g.Key);
                var hit = new Hit
                {
                    Ip = g.Key,
                    Process = Path.GetFileName(list[0].Image) ?? list[0].Image,
                    Attempts = list.Count,
                    FirstUtc = list.Min(h => h.TimeUtc),
                    LastUtc = list.Max(h => h.TimeUtc),
                    BlockClass = info?.Class,
                    BlockedSince = info?.Created,
                    ServedHosts = rows
                        .Where(r => string.Equals(r.RemoteIp, g.Key, StringComparison.OrdinalIgnoreCase) &&
                                    !string.IsNullOrEmpty(r.Sni))
                        .GroupBy(r => r.Sni, StringComparer.OrdinalIgnoreCase)
                        .OrderByDescending(gg => gg.Count())
                        .Take(3)
                        .Select(gg => gg.Key)
                        .ToList(),
                };
                if (list.Any(h => InWindow(h.TimeUtc))) report.InWindow.Add(hit);
                else report.Nearby.Add(hit);
            }
            report.InWindow = report.InWindow.OrderByDescending(h => h.Attempts).ToList();
            report.Nearby = report.Nearby.OrderByDescending(h => h.Attempts).ToList();

            // The page's recorded dependencies: hosts the same browser
            // fetched within seconds of a page load of the site under test.
            var visitorPids = siteRows.Where(r => r.Pid > 0).Select(r => r.Pid).ToHashSet();
            report.CoVisitedHosts = rows
                .Where(r => !string.IsNullOrEmpty(r.Sni) &&
                            !string.Equals(r.Sni, host, StringComparison.OrdinalIgnoreCase) &&
                            r.Pid > 0 && visitorPids.Contains(r.Pid) &&
                            siteRows.Any(s => s.Pid == r.Pid &&
                                              Math.Abs((s.TsUtc - r.TsUtc).TotalSeconds) <= CoVisitSeconds))
                .GroupBy(r => r.Sni, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .Take(6)
                .Select(g => g.Key)
                .ToList();

            return report;
        }

        /// <summary>
        /// Count how many of a dependency host's current addresses are on the
        /// block list — the "2 of 8 addresses blocked, so it works
        /// sometimes" fact. Pure, so the self-test covers it offline.
        /// </summary>
        public static RotationFact MeasureRotation(
            string depHost,
            IEnumerable<string> addresses,
            Func<string, BlockInfoLite> blockedLookup)
        {
            if (string.IsNullOrEmpty(depHost) || blockedLookup == null) return null;
            var distinct = (addresses ?? Array.Empty<string>()).Distinct().ToList();
            if (distinct.Count == 0) return null;
            int blocked = distinct.Count(ip => blockedLookup(ip) != null);
            return blocked > 0
                ? new RotationFact { Host = depHost, BlockedAddresses = blocked, TotalAddresses = distinct.Count }
                : null;
        }
    }
}
