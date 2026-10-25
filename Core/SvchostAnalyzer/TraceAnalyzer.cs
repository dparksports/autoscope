using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;

namespace SvchostAnalyzer.Core;

/// <summary>The analysis result: the full report text and its flag count.</summary>
public sealed record AnalysisResult(string Report, int Flags, int EventCount);

/// <summary>
/// Pattern detection over JSONL traces: spawn genealogy (parent must be
/// services.exe), respawn loops, destination classification (Microsoft /
/// Akamai / Gcore / unclassified), beacon regularity (coefficient of
/// variation of connect intervals), upload-dominant byte flows. Returns the
/// report as text — the CLI prints it, the AutoCommand Svchost Trace tab
/// shows it in its analysis pane.
/// </summary>
public static class TraceAnalyzer
{
    /// <summary>Analyzes one or more trace files (identical JSONL schema).</summary>
    public static AnalysisResult Analyze(IEnumerable<string> files)
    {
        var events = new List<(DateTime T, string Type, JsonObject O)>();
        foreach (var path in files)
            foreach (var line in File.ReadLines(path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var node = JsonNode.Parse(line).AsObject();
                    events.Add((DateTime.Parse(node["t"]?.GetValue<string>() ?? "",
                        CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                        node["type"]?.GetValue<string>() ?? "?", node));
                }
                catch { /* malformed line — collector crash mid-write; skip */ }
            }
        if (events.Count == 0)
            return new AnalysisResult("no parseable events\r\n", 1, 0);
        events.Sort((a, b) => a.T.CompareTo(b.T));

        var span = events[^1].T - events[0].T;
        int flags = 0;
        var sb = new StringBuilder();
        sb.AppendLine($"=== SVCHOST TRACE ANALYSIS: {events.Count} events, {span.TotalMinutes:F1} min span ===");

        // ── 1. process creation ─────────────────────────────────────────
        var spawns = events.Where(e => e.Type is "spawn" or "baseline").ToList();
        sb.AppendLine($"\r\n--- PROCESS CREATION ({spawns.Count} svchost instances) ---");
        foreach (var g in spawns.GroupBy(e => e.O["parent"]?.GetValue<string>() is { } p ? p : "?")
                                .OrderByDescending(g => g.Count()))
            sb.AppendLine($"  parent {g.Key}: created {g.Count()} svchost instance(s)");
        foreach (var g in spawns.Where(e => e.Type == "spawn")
                                .GroupBy(e => e.O["services"]?.GetValue<string>() ?? "?")
                                .Where(g => g.Count() >= 4))
        {
            sb.AppendLine($"  [FLAG] service '{g.Key}' spawned {g.Count()}x in {span.TotalMinutes:F1} min - respawn/crash loop");
            flags++;
        }
        foreach (var s in spawns.Where(e => e.O["parent"]?.GetValue<string>() is null
                                                      or not ("services.exe" or "<exited>")))
        {
            sb.AppendLine($"  [FLAG] svchost PID {s.O["pid"]} ({s.O["services"]}) parent = '{s.O["parent"]}' (expect services.exe)");
            flags++;
        }
        int noSvc = spawns.Count(e => (e.O["services"]?.GetValue<string>() ?? "") is "" or "<no service>" or "<pending>");
        if (noSvc > 0) { sb.AppendLine($"  [FLAG] {noSvc} svchost instance(s) with NO resolvable service"); flags++; }

        // ── 1b. identity: -k group / -s declared service vs SCM ────────
        sb.AppendLine("\r\n--- IDENTITY (-k group · -s self-declared service vs SCM ground truth) ---");
        // parse cmd directly (not the stored k/s fields) so pre-identity
        // traces analyze identically
        var ident = spawns.Select(e => (
                Pid: e.O["pid"],
                e.O["cmd"]?.GetValue<string>(),
                Svc: e.O["services"]?.GetValue<string>() ?? ""))
            .Select(x => (x.Pid, Cmd: x.Item2, Id: SvchostIdentity.Parse(x.Item2), x.Svc))
            .ToList();
        var readable = ident.Where(x => !string.IsNullOrEmpty(x.Cmd)).ToList();
        if (readable.Count == 0)
        {
            sb.AppendLine("  command lines hidden or absent for every instance " +
                          "(non-elevated capture cannot read SYSTEM svchost lines — normal, nothing to corroborate)");
        }
        else
        {
            sb.AppendLine($"  {ident.Count} instances · {readable.Count} readable command line(s) · " +
                          $"{ident.Count - readable.Count} hidden/absent (non-elevated: SYSTEM lines are unreadable)");
            foreach (var g in readable.GroupBy(x => x.Id.Group ?? "<no -k>")
                                      .OrderByDescending(g => g.Count()))
                sb.AppendLine($"  group {g.Key}: {g.Count()} instance(s)");
        }
        bool Corroborable(string svc) => !string.IsNullOrEmpty(svc) && !svc.StartsWith('<');
        int mismatches = 0, noKs = 0;
        foreach (var x in ident)
        {
            if (Corroborable(x.Svc) && SvchostIdentity.Mismatches(x.Id.DeclaredService, x.Svc))
            {
                sb.AppendLine($"  [FLAG] PID {x.Pid}: -s '{x.Id.DeclaredService}' but SCM hosts '{x.Svc}' — " +
                              "self-declared identity contradicts the SCM (masquerade signal)");
                mismatches++; flags++;
            }
            else if (!string.IsNullOrEmpty(x.Cmd) && x.Id.Group == null)
            {
                sb.AppendLine($"  [FLAG] PID {x.Pid}: readable command line without -k service group — " +
                              "the SCM always passes -k; this is not a service host");
                noKs++; flags++;
            }
        }
        if (mismatches == 0 && noKs == 0)
            sb.AppendLine("  every readable command line corroborates its SCM services");

        // ── 2. destinations + classification ───────────────────────────
        var connects = events.Where(e => e.Type == "connect").ToList();
        var discos = events.Where(e => e.Type == "disconnect").ToList();
        sb.AppendLine($"\r\n--- CONNECTIONS ({connects.Count} opened, {discos.Count} closed) ---");
        if (discos.Count > 0)
            sb.AppendLine($"  average connection lifetime: {discos.Average(d => d.O["dur"]?.GetValue<double>() ?? 0):F1}s");
        foreach (var g in connects.GroupBy(c => (Svc: c.O["services"]?.GetValue<string>() ?? "?",
                                                 Ip: c.O["ip"]?.GetValue<string>() ?? "?"))
                                  .OrderByDescending(g => g.Count()))
        {
            var first = g.First().O;
            string pre = first["preexisting"]?.GetValue<bool>() == true ? " (preexisting)" : "";
            sb.AppendLine($"  {g.Key.Svc,-40} -> {g.Key.Ip,-16} x{g.Count(),-3} port {first["port"]} [{Classify(g.Key.Ip)}]{pre}");
        }
        var unknown = connects.Select(c => c.O["ip"]?.GetValue<string>() ?? "?")
                              .Where(ip => Classify(ip) == "UNCLASSIFIED").Distinct().ToList();
        if (unknown.Count > 0)
        {
            sb.AppendLine($"  [FLAG] {unknown.Count} UNCLASSIFIED destination(s): {string.Join(", ", unknown)} - verify via https://rdap.org/ip/<ip>");
            flags++;
        }

        // ── 3. beacon regularity ───────────────────────────────────────
        sb.AppendLine("\r\n--- BEACON ANALYSIS (connect intervals per service+IP) ---");
        int beacons = 0;
        foreach (var g in connects.GroupBy(c => (Svc: c.O["services"]?.GetValue<string>() ?? "?",
                                                 Ip: c.O["ip"]?.GetValue<string>() ?? "?")))
        {
            var times = g.Select(c => c.T).OrderBy(t => t).ToList();
            if (times.Count < 4) continue;
            var iv = times.Zip(times.Skip(1), (a, b) => (b - a).TotalSeconds).ToList();
            double mean = iv.Average();
            if (mean <= 0) continue;
            double std = Math.Sqrt(iv.Sum(v => (v - mean) * (v - mean)) / iv.Count);
            double cv = std / mean;
            bool regular = cv < 0.35;
            sb.AppendLine($"  {g.Key.Svc} -> {g.Key.Ip}: n={times.Count}, mean={mean:F1}s, CV={cv:F2} " +
                          (regular ? "[FLAG] REGULAR - beacon-like" : "(irregular - normal app behavior)"));
            if (regular) { beacons++; flags++; }
        }
        if (connects.Count == 0) sb.AppendLine("  (no svchost connections captured in this window)");
        else if (beacons == 0) sb.AppendLine("  no regular-interval pattern detected");

        // ── 4. byte flows ──────────────────────────────────────────────
        sb.AppendLine("\r\n--- BYTE FLOWS (cumulative-counter deltas per PID) ---");
        foreach (var g in events.Where(e => e.Type == "bytes").GroupBy(e => e.O["pid"]?.GetValue<int>() ?? 0))
        {
            var s = g.OrderBy(e => e.T).ToList();
            if (s.Count < 2) continue;
            long dr = (s[^1].O["r"]?.GetValue<long>() ?? 0) - (s[0].O["r"]?.GetValue<long>() ?? 0);
            long dw = (s[^1].O["w"]?.GetValue<long>() ?? 0) - (s[0].O["w"]?.GetValue<long>() ?? 0);
            sb.AppendLine($"  PID {g.Key} ({s[0].O["services"]}): received {dr:N0} B, sent {dw:N0} B");
            if (dw > 3_000_000 && dw > 3 * dr)
            {
                sb.AppendLine($"  [FLAG] PID {g.Key}: upload-dominant ({dw:N0} B sent vs {dr:N0} B received)");
                flags++;
            }
        }

        sb.AppendLine($"\r\n=== SUMMARY: {spawns.Count} instances, {connects.Count} connections, {beacons} beacon pattern(s), {flags} total flag(s) ===");
        return new AnalysisResult(sb.ToString(), flags, events.Count);
    }

    /// <summary>Session-verified ranges; unclassified destinations are flagged for RDAP, not auto-condemned.</summary>
    internal static string Classify(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr) || addr.AddressFamily != AddressFamily.InterNetwork)
            return "IPv6/other";
        uint v = IpToUint(addr);
        foreach (var (name, cidrs) in Tables.Ranges)
            foreach (var cidr in cidrs)
            {
                var parts = cidr.Split('/');
                uint net = IpToUint(IPAddress.Parse(parts[0]));
                uint mask = uint.MaxValue << (32 - int.Parse(parts[1]));
                if ((v & mask) == (net & mask)) return name;
            }
        return "UNCLASSIFIED";
    }

    private static uint IpToUint(IPAddress a)
    {
        var b = a.GetAddressBytes();
        return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
    }
}

internal static class Tables
{
    public static readonly (string Name, string[] Cidrs)[] Ranges =
    {
        ("Microsoft/Azure", new[] { "20.0.0.0/8", "40.0.0.0/8", "13.64.0.0/11", "13.104.0.0/14",
                                    "52.96.0.0/12", "52.112.0.0/14", "65.52.0.0/14", "72.145.32.0/19", "172.176.0.0/12" }),
        ("Akamai (MS CDN)", new[] { "23.32.0.0/11", "23.192.0.0/11", "2.16.0.0/13", "95.100.0.0/15", "184.24.0.0/13", "104.64.0.0/10" }),
        ("Gcore (MS CDN)",  new[] { "92.223.0.0/16" }),
    };
}
