using System;
using AutoCommand.Engines.Bridge;
using AutoCommand.Engines.Watch;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using AutoCommand.Engines.Core;
using AutoCommand.Engines.Diagnosis;

using Engines = AutoCommand.Engines;
namespace AutoScope.Services
{
    /// <summary>
    /// The live half of the dependency-block pass, now a thin adapter over
    /// the F# engine (Engines.Diagnosis / Dependency.fs): gathers the real
    /// archive, the persisted block-hit feed, the block-inventory cache,
    /// and live forward DNS for the rotation facts, and feeds the pure
    /// core. Kept in the app because it binds the (still C#) watch services.
    /// Every failure degrades to a thinner report, never an exception.
    /// </summary>
    public static class DependencyBlockService
    {
        /// <summary>
        /// Run off the UI thread. Attribution history goes 7 days deep — an
        /// address's served-hosts may be days old — while visit anchors and
        /// block hits honor <paramref name="minutesBack"/>.
        /// </summary>
        public static async Task<Report> AnalyzeLiveAsync(
            string host, int minutesBack, Action<string> progress, CancellationToken ct)
        {
            minutesBack = Math.Clamp(minutesBack, 5, 60 * 24 * 7);
            var report = new Report(host, new List<DateTime>(), new List<Hit>(),
                new List<Hit>(), new List<string>(), new List<RotationFact>());

            try
            {
                progress?.Invoke("Reading recorded page loads…");
                var rows = TransmissionsArchiveService.Read(8000, null, null,
                    DateTime.UtcNow - TimeSpan.FromDays(7))
                    .Select(r => new TrafficRow(r.TsUtc, r.Pid, r.Image, r.ProcessDisplay,
                        r.RemoteIp, r.RemotePort, r.Sni, r.ClientBytes, r.ServerBytes)).ToList();

                BlockHitFeedService.Instance.Start();   // idempotent; loads persisted hits
                var hits = BlockHitFeedService.Instance.Recent(minutesBack, 2000)
                    .Select(h => new BlockHitLite(h.TimeUtc, h.Image, h.Pid, h.DestIp, h.MatchKind))
                    .ToList();
                BlockInfoLite Lookup(string ip)
                {
                    var b = BlockHitFeedService.Instance.BlockedIp(ip);
                    return b == null ? null : new BlockInfoLite(b.Class, b.Created);
                }

                report = DependencyAnalysis.Analyze(host, rows, hits, Lookup,
                    DateTime.UtcNow.AddMinutes(-minutesBack));

                if (!report.Any) return report;

                progress?.Invoke("Checking whether the page's dependency hosts resolve to blocked addresses…");
                var candidates = report.CoVisitedHosts
                    .Concat(report.InWindow.SelectMany(h => h.ServedHosts))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(5)
                    .ToList();
                foreach (var depHost in candidates)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                        cts.CancelAfter(TimeSpan.FromSeconds(5));
                        // GetHostAddressesAsync, not a cached resolver: the
                        // rotation being measured is live DNS behavior.
                        var addrs = await Dns.GetHostAddressesAsync(depHost, cts.Token);
                        var fact = DependencyAnalysis.MeasureRotation(depHost,
                            addrs.Select(a => a.ToString()), Lookup);
                        if (fact != null) report.Rotations.Add(fact);
                    }
                    catch { /* one unresolvable host never stops the pass */ }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { /* a thinner report beats no report */ }

            return report;
        }
    }
}
