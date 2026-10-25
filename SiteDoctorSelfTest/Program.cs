// Site doctor self-test — the Site Doctor pipeline ("why is this site slow
// / broken / can't sign in"), proven at the source. This build validates the
// F# ENGINES (Engines.Diagnosis): a C# test harness consuming the F#
// libraries directly is itself part of the validation — C#-consumes-F# is
// the interop contract. Offline: fingerprint signals over synthetic rows,
// every verdict rule over synthetic probe reports, the dependency-block
// join over the login-failure shape observed in the wild. Live (loopback
// only, no admin, no external network): a TLS server that answers
// handshakes and a "black hole" that accepts TCP then never replies.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using AutoScope.Engines.Core;
using AutoScope.Engines.Diagnosis;

int failures = 0;
void Check(string name, bool pass, string evidence = "")
{
    Console.WriteLine($"{(pass ? "PASS" : "FAIL")}  {name}{(pass || evidence.Length == 0 ? "" : "  — " + evidence)}");
    if (!pass) failures++;
}

// TrafficRow is an F# record: positional construction, declaration order.
static TrafficRow Rec(string sni, string ip, DateTime ts, long bytes = 12_000)
{
    const string image = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
    return new TrafficRow(ts, 1000, image, "chrome.exe", ip, 443, sni, bytes, 0);
}

static TrafficRow RecAt(string sni, string ip, DateTime ts, string image, int pid)
    => new TrafficRow(ts, pid, image, Path.GetFileName(image), ip, 443, sni, 12_000, 0);

DateTime T0 = DateTime.UtcNow;

// ─────────────────────────────────────────────────────────────────────
// 1. Fingerprint — edge dispersion (the steering signal)
// ─────────────────────────────────────────────────────────────────────
var dispersed = Enumerable.Range(0, 8)
    .Select(i => Rec("chat.z.ai", $"47.246.23.{140 + i}", T0.AddMinutes(i * 5)))
    .ToList();
var fpDispersed = SiteFingerprintService.Fingerprint(dispersed, baselineEdges: 1);
Check("dispersion: 8 edges flagged as struggling", fpDispersed.LooksStruggling);
Check("dispersion: edge count correct", fpDispersed.Edges.Count == 8, $"got {fpDispersed.Edges.Count}");
Check("dispersion: signal names the count",
    fpDispersed.Signals.Any(s => s.Contains("8 different server addresses")), string.Join(" | ", fpDispersed.Signals));

// ─────────────────────────────────────────────────────────────────────
// 2. Fingerprint — 5-second burst (the retry-race signal)
// ─────────────────────────────────────────────────────────────────────
var burst = new List<TrafficRow>
{
    Rec("chat.z.ai", "47.246.23.146", T0.AddSeconds(0)),
    Rec("chat.z.ai", "47.246.23.146", T0.AddSeconds(0.4)),
    Rec("chat.z.ai", "47.246.23.146", T0.AddSeconds(0.9)),
    Rec("chat.z.ai", "47.246.23.146", T0.AddMinutes(10)),
};
var fpBurst = SiteFingerprintService.Fingerprint(burst, baselineEdges: 1);
Check("burst: one 5s window detected", fpBurst.BurstWindows == 1, $"got {fpBurst.BurstWindows}");
Check("burst: FirstBurstUtc set", fpBurst.FirstBurstUtc.HasValue);

// ─────────────────────────────────────────────────────────────────────
// 3. Fingerprint — single-edge churn + calm-site negative
// ─────────────────────────────────────────────────────────────────────
var churn = Enumerable.Range(0, 5)
    .Select(i => Rec("api.github.com", "140.82.114.3", T0.AddSeconds(i * 8)))
    .ToList();
var fpChurn = SiteFingerprintService.Fingerprint(churn, baselineEdges: 1);
Check("churn: 5 same-edge connects within a minute", fpChurn.MaxSameEdgePerMinute == 5,
    $"got {fpChurn.MaxSameEdgePerMinute}");
Check("churn: churn signal fired", fpChurn.Signals.Any(s => s.Contains("within a minute")));

var calm = new List<TrafficRow>
{
    Rec("api.github.com", "140.82.114.3", T0),
    Rec("api.github.com", "140.82.114.3", T0.AddMinutes(55)),
};
var fpCalm = SiteFingerprintService.Fingerprint(calm, baselineEdges: 1);
Check("calm site: no signals", !fpCalm.LooksStruggling, string.Join(" | ", fpCalm.Signals));

// ─────────────────────────────────────────────────────────────────────
// 4. Fingerprint — TopHosts + machine-wide baseline
// ─────────────────────────────────────────────────────────────────────
var mixed = new List<TrafficRow>(burst);
mixed.AddRange(calm);
mixed.AddRange(Enumerable.Range(0, 9).Select(i => Rec("zcode.z.ai", "47.246.23.189", T0.AddMinutes(i))));
var top = SiteFingerprintService.TopHosts(mixed, 10);
Check("TopHosts: busiest host first", top[0] == "zcode.z.ai", $"got {top.FirstOrDefault()}");
var all = SiteFingerprintService.AllFingerprints(mixed);
Check("AllFingerprints: three hosts", all.Count == 3, $"got {all.Count}");
Check("BaselineEdgeCount: median across hosts", SiteFingerprintService.BaselineEdgeCount(all) == 1,
    $"got {SiteFingerprintService.BaselineEdgeCount(all)}");

// ─────────────────────────────────────────────────────────────────────
// 5. Verdict rules — synthetic probe reports
// ─────────────────────────────────────────────────────────────────────
SiteProbeReport Report(
    List<EdgeProbe> edges,
    List<DnsSample> dns = null,
    List<ControlProbe> controls = null) => new()
{
    Host = "test",
    Dns = new DnsResult
    {
        Host = "test",
        Samples = dns ?? new List<DnsSample>
            { new() { Ips = new List<string> { "1.2.3.4" } } },
    },
    Edges = edges,
    Controls = controls ?? new List<ControlProbe>(),
};

var vBlocked = SiteVerdict.Decide(null, Report(new List<EdgeProbe>
{
    new() { Ip = "1.2.3.4", TcpError = "connection refused" },
    new() { Ip = "5.6.7.8", TcpError = "no TCP answer in 4000ms" },
}));
Check("verdict: all-TCP-failed → Blocked", vBlocked.Kind == VerdictKind.Blocked, vBlocked.Kind.ToString());

var vDrop = SiteVerdict.Decide(null, Report(new List<EdgeProbe>
{
    new() { Ip = "47.246.23.220", TcpConnectMs = 30, TlsPlainMs = 54, TlsPlainVersion = "Tls12", TlsDefaultError = "timeout" },
}, controls: new List<ControlProbe> { new() { Host = "ctl", TcpConnectMs = 11, TlsMs = 15 } }));
Check("verdict: split hello shapes → HandshakeDropping", vDrop.Kind == VerdictKind.HandshakeDropping, vDrop.Kind.ToString());
Check("verdict: headline names the DROPPED shape",
    vDrop.Headline.Contains("Windows-default handshake"), vDrop.Headline);

var vSteer = SiteVerdict.Decide(null, Report(
    new List<EdgeProbe> { new() { Ip = "1.1.1.1", TcpConnectMs = 25, TlsDefaultMs = 50, TlsDefaultVersion = "Tls13", TlsPlainMs = 48, TlsPlainVersion = "Tls12" } },
    dns: new List<DnsSample>
    {
        new() { Ips = new List<string> { "1.1.1.1" } },
        new() { Ips = new List<string> { "2.2.2.2" } },
        new() { Ips = new List<string> { "3.3.3.3" } },
    }));
Check("verdict: rotating DNS → Steering", vSteer.Kind == VerdictKind.Steering, vSteer.Kind.ToString());

var vFar = SiteVerdict.Decide(null, Report(
    new List<EdgeProbe> { new() { Ip = "9.9.9.9", TcpConnectMs = 210, TlsDefaultMs = 320, TlsDefaultVersion = "Tls13", TlsPlainMs = 300, TlsPlainVersion = "Tls12" } },
    controls: new List<ControlProbe> { new() { Host = "ctl", TcpConnectMs = 10, TlsMs = 15 } }));
Check("verdict: 20x control latency → FarAway", vFar.Kind == VerdictKind.FarAway, vFar.Kind.ToString());

var vHealthy = SiteVerdict.Decide(fpCalm, Report(
    new List<EdgeProbe> { new() { Ip = "140.82.114.3", TcpConnectMs = 40, TlsDefaultMs = 60, TlsDefaultVersion = "Tls13", TlsPlainMs = 58, TlsPlainVersion = "Tls12" } },
    controls: new List<ControlProbe> { new() { Host = "ctl", TcpConnectMs = 30, TlsMs = 45 } }));
Check("verdict: fast + calm → Healthy", vHealthy.Kind == VerdictKind.Healthy, vHealthy.Kind.ToString());

var vNone = SiteVerdict.Decide(null, null);
Check("verdict: no evidence → Insufficient", vNone.Kind == VerdictKind.Insufficient, vNone.Kind.ToString());

// ─────────────────────────────────────────────────────────────────────
// 5b. Dependency-block join — "the site is fine, its dependency is
//     blocked here" (the login-failure shape observed in the wild)
// ─────────────────────────────────────────────────────────────────────
DateTime T1 = DateTime.UtcNow.AddMinutes(-30);
string braveExe = @"C:\Users\u\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe";
BlockInfoLite Info(DateTime since) => new BlockInfoLite("Unclassified", since);

var depRows = new List<TrafficRow>
{
    // The visit: browser 2000 loads the sign-in page and calls its API.
    RecAt("www.spectrum.net", "52.84.20.127", T1, braveExe, 2000),
    RecAt("apis.spectrum.net", "134.150.63.225", T1.AddSeconds(2), braveExe, 2000),
    // History: this machine has recorded the (soon blocked) Google frontend
    // serving other browsing — the attribution input.
    RecAt("mail.google.com", "142.251.34.67", T1.AddHours(-6), braveExe, 2000),
    RecAt("www.google.com", "142.251.34.69", T1.AddHours(-6).AddMinutes(1), braveExe, 2000),
    // A different browser's traffic — must not influence the join.
    RecAt("github.com", "140.82.116.3", T1.AddSeconds(1), @"C:\Program Files\Google\Chrome\Application\chrome.exe", 1000),
};
var depHits = new List<BlockHitLite>
{
    // In-window: 4s and 7s after the page load — the causal set.
    new BlockHitLite(T1.AddSeconds(4), braveExe, 2000, "142.251.34.67", "ip"),
    new BlockHitLite(T1.AddSeconds(7), braveExe, 2000, "142.251.34.67", "ip"),
    // Out of every visit window → context only, never the verdict.
    new BlockHitLite(T1.AddHours(-3), braveExe, 2000, "142.251.41.3", "ip"),
    // Another process hitting a block — irrelevant to this site's story.
    new BlockHitLite(T1.AddSeconds(5), @"C:\Windows\System32\svchost.exe", 999, "142.251.99.99", "ip"),
};

var dep = DependencyAnalysis.Analyze("www.spectrum.net", depRows, depHits,
    ip => ip == "142.251.34.67" ? Info(DateTime.UtcNow.AddDays(-3)) : null);
Check("dep: one in-window address, attempts aggregated",
    dep.InWindow.Count == 1 && dep.InWindow[0].Ip == "142.251.34.67" && dep.InWindow[0].Attempts == 2,
    $"{dep.InWindow.Count}/{dep.InWindow.FirstOrDefault()?.Ip}/{dep.InWindow.FirstOrDefault()?.Attempts}");
Check("dep: attribution names the served host",
    dep.InWindow[0].ServedHosts.Contains("mail.google.com"), string.Join(",", dep.InWindow[0].ServedHosts));
Check("dep: block provenance carried", dep.InWindow[0].BlockedSince.HasValue);
Check("dep: out-of-window hit kept as context only",
    dep.Nearby.Count == 1 && dep.Nearby[0].Ip == "142.251.41.3", $"{dep.Nearby.Count}");
Check("dep: other processes excluded from the join",
    !dep.InWindow.Concat(dep.Nearby).Any(h => h.Ip == "142.251.99.99"));
Check("dep: co-visited dependency host found (the page's API)",
    dep.CoVisitedHosts.Contains("apis.spectrum.net"), string.Join(",", dep.CoVisitedHosts));

var rot = DependencyAnalysis.MeasureRotation("www.google.com",
    Enumerable.Range(0, 8).Select(i => $"142.251.{150 + i}.119").Concat(new[] { "142.251.34.67" }),
    ip => ip == "142.251.34.67" ? Info(DateTime.UtcNow) : null);
Check("dep: rotation counts blocked fraction", rot != null && rot.BlockedAddresses == 1 && rot.TotalAddresses == 9,
    rot == null ? "null" : $"{rot.BlockedAddresses}/{rot.TotalAddresses}");
Check("dep: rotation null when nothing blocked",
    DependencyAnalysis.MeasureRotation("www.google.com", new[] { "1.1.1.1", "2.2.2.2" }, _ => null) == null);

// Healthy probe + in-window blocked dependency → DependencyBlocked, not Healthy.
SiteProbeReport HealthyReport() => Report(new List<EdgeProbe>
{
    new() { Ip = "52.84.20.127", TcpConnectMs = 40, TlsDefaultMs = 60, TlsDefaultVersion = "Tls13", TlsPlainMs = 58, TlsPlainVersion = "Tls12" },
}, controls: new List<ControlProbe> { new() { Host = "ctl", TcpConnectMs = 30, TlsMs = 45 } });

var vDep = SiteVerdict.Decide(null, HealthyReport(), dep);
Check("verdict: healthy site + blocked dependency → DependencyBlocked",
    vDep.Kind == VerdictKind.DependencyBlocked, vDep.Kind.ToString());
Check("verdict: headline names the blocked address and process",
    vDep.Headline.Contains("142.251.34.67") && vDep.Headline.Contains("brave.exe"), vDep.Headline);
Check("verdict: evidence lists the hit with its served host",
    vDep.Evidence.Any(l => l.Contains("142.251.34.67") && l.Contains("mail.google.com")),
    string.Join(" | ", vDep.Evidence));

// Honesty guard: nearby-only hits must NOT hijack a healthy verdict.
var depNearbyOnly = DependencyAnalysis.Analyze("www.spectrum.net", depRows,
    new List<BlockHitLite> { depHits[2] }, _ => null);
var vStillHealthy = SiteVerdict.Decide(null, HealthyReport(), depNearbyOnly);
Check("verdict: nearby-only hits keep Healthy honest",
    vStillHealthy.Kind == VerdictKind.Healthy, vStillHealthy.Kind.ToString());

// And with no probe at all, the join stands on its own recorded evidence.
var vDepNoProbe = SiteVerdict.Decide(null, null, dep);
Check("verdict: dependency evidence alone still fires",
    vDepNoProbe.Kind == VerdictKind.DependencyBlocked, vDepNoProbe.Kind.ToString());

// ─────────────────────────────────────────────────────────────────────
// 6. LIVE dual-shape probe — loopback TLS server vs loopback black hole
// ─────────────────────────────────────────────────────────────────────
using var rsa = RSA.Create(2048);
var certReq = new CertificateRequest("CN=sitedoctor-selftest", rsa,
    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
// schannel's server side refuses certs without the server-auth EKU —
// the handshake then dies with a client-side EOF, which is exactly what
// this test must NOT mistake for its own black-hole path.
certReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
    new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
using X509Certificate2 cert = certReq.CreateSelfSigned(
    DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

var healthyListener = new TcpListener(IPAddress.Loopback, 0);
healthyListener.Start();
int healthyPort = ((IPEndPoint)healthyListener.LocalEndpoint).Port;
int serverEphemeralErrors = 0;
var healthyServer = Task.Run(async () =>
{
    // Three connections arrive: the timing-only connect, then one per
    // hello shape — answer the TLS ones; the timing one EOFs harmlessly.
    // NOTE: a machine whose OS hardening leaves schannel unable to create
    // ephemeral keys can't host TLS at all ("platform does not support
    // ephemeral keys") — counted and reported as SKIP below, because the
    // thing under test is the PROBE, and its black-hole half still runs.
    for (int i = 0; i < 3; i++)
    {
        var client = await healthyListener.AcceptTcpClientAsync();
        _ = Task.Run(async () =>
        {
            try
            {
                using var ssl = new SslStream(client.GetStream(), false);
                await ssl.AuthenticateAsServerAsync(cert, false, SslProtocols.None, false);
                await Task.Delay(50); // hold it open briefly, like a real server
            }
            catch (AuthenticationException ex) when (ex.Message.Contains("ephemeral keys"))
            {
                Interlocked.Increment(ref serverEphemeralErrors);
            }
            catch { /* probe closed its side first — fine */ }
            finally { client.Dispose(); }
        });
    }
});

var blackHoleListener = new TcpListener(IPAddress.Loopback, 0);
blackHoleListener.Start();
int blackHolePort = ((IPEndPoint)blackHoleListener.LocalEndpoint).Port;
var blackHoleServer = Task.Run(async () =>
{
    for (int i = 0; i < 3; i++) // TCP connect + two hello attempts
    {
        var client = await blackHoleListener.AcceptTcpClientAsync();
        _ = Task.Run(async () =>
        {
            try { await Task.Delay(TimeSpan.FromSeconds(10)); } // accept, then say nothing
            catch { }
            finally { client.Dispose(); }
        });
    }
});

var probe = new SiteProbeService();
var ops = new List<string>();
void Log(string kind, string detail) { ops.Add($"[{kind}] {detail}"); }

var healthyEdge = await probe.ProbeEdgeAsync("127.0.0.1", "localhost", Log, CancellationToken.None, healthyPort);
Check("live: healthy server TCP ok", healthyEdge.TcpConnectMs.HasValue);

bool healthyTlsUnavailable = healthyEdge.TlsDefaultMs == null &&
                             serverEphemeralErrors > 0;
if (healthyTlsUnavailable)
{
    Console.WriteLine("SKIP  live: healthy-server hello checks — this machine's schannel cannot host TLS " +
                      "(\u201Cplatform does not support ephemeral keys\u201D, OS hardening). The probe's " +
                      "black-hole half below still proves the detection path; hello-acceptance is covered " +
                      "by the offline split-shape verdict checks.");
}
else
{
    Check("live: healthy server default hello ok",
        healthyEdge.TlsDefaultMs.HasValue && !string.IsNullOrEmpty(healthyEdge.TlsDefaultVersion),
        healthyEdge.TlsDefaultError ?? "(no error)");
    Check("live: healthy server plain hello ok",
        healthyEdge.TlsPlainMs.HasValue && !string.IsNullOrEmpty(healthyEdge.TlsPlainVersion),
        healthyEdge.TlsPlainError ?? "(no error)");
}

var blackHoleEdge = await probe.ProbeEdgeAsync("127.0.0.1", "localhost", Log, CancellationToken.None, blackHolePort);
Check("live: black hole TCP still accepts", blackHoleEdge.TcpConnectMs.HasValue, blackHoleEdge.TcpError ?? "");
Check("live: black hole drops default hello (timeout)",
    !blackHoleEdge.TlsDefaultMs.HasValue && !string.IsNullOrEmpty(blackHoleEdge.TlsDefaultError),
    blackHoleEdge.TlsDefaultError ?? "");
Check("live: black hole drops plain hello (timeout)",
    !blackHoleEdge.TlsPlainMs.HasValue && !string.IsNullOrEmpty(blackHoleEdge.TlsPlainError),
    blackHoleEdge.TlsPlainError ?? "");
Check("live: every operation was logged",
    ops.Count >= 6, $"got {ops.Count}: {string.Join(" | ", ops)}");

// And the split pair produces the HandshakeDropping verdict, end to end.
// Control numbers come from the live healthy server when this machine can
// host TLS; otherwise synthetic (the mapping is what's under test).
var vLive = SiteVerdict.Decide(null, new SiteProbeReport
{
    Host = "localhost",
    Dns = new DnsResult
    {
        Host = "localhost",
        Samples = new List<DnsSample> { new() { Ips = new List<string> { "127.0.0.1" } } },
    },
    Edges = new List<EdgeProbe> { blackHoleEdge },
    Controls = new List<ControlProbe>
    {
        healthyTlsUnavailable
            ? new() { Host = "synthetic-ctl", TcpConnectMs = 5, TlsMs = 10 }
            : new() { Host = "localhost", TcpConnectMs = healthyEdge.TcpConnectMs, TlsMs = healthyEdge.TlsDefaultMs },
    },
});
Check("live: black-hole edge + healthy control → HandshakeDropping",
    vLive.Kind == VerdictKind.HandshakeDropping, vLive.Kind.ToString());

// And when the control fails the same way, the finger turns around and
// points at the LOCAL stack — the LocalTlsBroken rule.
var vLocalBroken = SiteVerdict.Decide(null, new SiteProbeReport
{
    Host = "localhost",
    Dns = new DnsResult
    {
        Host = "localhost",
        Samples = new List<DnsSample> { new() { Ips = new List<string> { "127.0.0.1" } } },
    },
    Edges = new List<EdgeProbe> { blackHoleEdge },
    Controls = new List<ControlProbe>
    {
        new() { Host = "ctl", TcpConnectMs = 8, Error = "server never answered" },
    },
});
Check("live: all handshakes fail incl. control → LocalTlsBroken",
    vLocalBroken.Kind == VerdictKind.LocalTlsBroken, vLocalBroken.Kind.ToString());

healthyListener.Stop();
blackHoleListener.Stop();

// ─────────────────────────────────────────────────────────────────────
// 7. RunAsync caps — 10 extra edges must collapse to MaxEdgesPerRun
// ─────────────────────────────────────────────────────────────────────
var manyEdges = Enumerable.Range(1, 10).Select(i => $"10.0.0.{i}").ToList();
var capped = await probe.RunAsync("localhost", manyEdges, controlHosts: Array.Empty<string>(),
    dnsSampleInterval: TimeSpan.FromMilliseconds(10));
Check("caps: at most 4 edges probed", capped.Edges.Count <= SiteProbeService.MaxEdgesPerRun,
    $"got {capped.Edges.Count}");
Check("caps: 5 DNS samples taken", capped.Dns.Samples.Count == SiteProbeService.MaxDnsSamples,
    $"got {capped.Dns.Samples.Count}");
Check("caps: DNS ops logged", capped.Operations.Count(o => o.Kind == "dns") == SiteProbeService.MaxDnsSamples,
    $"got {capped.Operations.Count(o => o.Kind == "dns")}");
Check("caps: localhost resolved to loopback",
    capped.Dns.DistinctIps.All(ip => ip == "127.0.0.1"), string.Join(",", capped.Dns.DistinctIps));

// ─────────────────────────────────────────────────────────────────────
Console.WriteLine(failures == 0 ? "\nSiteDoctorSelfTest: ALL PASS" : $"\nSiteDoctorSelfTest: {failures} FAILURE(S)");
return failures == 0 ? 0 : 1;
