// NetWatch self-test — TcpConnectionTable (dual-family kernel enumeration,
// incl. a LIVE held [::1] connection) + SysmonArchiveService (watermark
// dedupe, day-file rotation, search, prune, corrupt-line tolerance).
// Archive persistence runs against a temp dir; nothing touches the real
// %LOCALAPPDATA% archive or the live Sysmon channel.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using AutoScope.Engines.Watch;

int failures = 0;
void Check(string name, bool pass, string evidence = "")
{
    Console.WriteLine($"{(pass ? "PASS" : "FAIL")}  {name}{(pass || evidence.Length == 0 ? "" : "  — " + evidence)}");
    if (!pass) failures++;
}

// ─────────────────────────────────────────────────────────────────────
// 1. TcpConnectionTable — destination classification, both families
// ─────────────────────────────────────────────────────────────────────
var localOrNonRoutable = new Dictionary<string, bool>
{
    ["127.0.0.1"] = true, ["127.5.5.5"] = true,
    ["192.168.1.5"] = true, ["10.0.0.1"] = true,
    ["172.16.0.1"] = true, ["172.31.9.9"] = true,
    ["172.32.0.1"] = false, ["8.8.8.8"] = false, ["1.1.1.1"] = false,
    ["224.0.0.1"] = true, ["239.255.255.255"] = true, ["255.255.255.255"] = true,
    ["::1"] = true, ["fe80::1"] = true, ["fd00::1"] = true, ["fc00::1"] = true,
    ["ff02::1"] = true, ["2600::1"] = false, ["2620:fe::fe"] = false,
    [""] = true,
};
foreach (var (ip, expected) in localOrNonRoutable)
    Check($"IsLocalOrNonRoutable({ip}) == {expected}",
        TcpConnectionTable.IsLocalOrNonRoutable(ip) == expected);
Check("IsLocalOrNonRoutable(null) == true", TcpConnectionTable.IsLocalOrNonRoutable(null));

// ─────────────────────────────────────────────────────────────────────
// 2. TcpConnectionTable — LIVE dual-family enumeration with a held
//    IPv6 loopback connection (the exact gap shipped in v2026.10.17.1:
//    AF_INET never returned it; the dual-family table must)
// ─────────────────────────────────────────────────────────────────────
using var v6Listener = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
v6Listener.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0));
v6Listener.Listen(1);
int listenPort = ((IPEndPoint)v6Listener.LocalEndPoint).Port;
using var accepted = new ManualResetEventSlim(false);
var v6Server = new Thread(() =>
{
    using var s = v6Listener.Accept();
    accepted.Set();
    Thread.Sleep(8000); // hold it open while the assertions run
});
v6Server.Start();

using var v6Client = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
v6Client.Connect(new IPEndPoint(IPAddress.IPv6Loopback, listenPort));

var rows = TcpConnectionTable.GetEstablished();
var v6rows = rows.Where(r => r.IsIpv6).ToList();
var v4rows = rows.Where(r => !r.IsIpv6).ToList();

Check("held [::1] connection is visible", v6rows.Any(r => r.RemoteIp == "::1"),
    $"{v6rows.Count} v6 rows: {string.Join(", ", v6rows.Select(r => r.RemoteEndPoint))}");
Check("v6 endpoints are bracketed", v6rows.All(r => r.RemoteEndPoint.StartsWith("[")),
    v6rows.FirstOrDefault()?.RemoteEndPoint ?? "(none)");
Check("v4 endpoints are not bracketed", v4rows.All(r => !r.RemoteEndPoint.StartsWith("[")),
    v4rows.FirstOrDefault()?.RemoteEndPoint ?? "(none)");
Check("every RemoteIp parses as an address", rows.All(r => IPAddress.TryParse(r.RemoteIp, out _)),
    rows.FirstOrDefault(r => !IPAddress.TryParse(r.RemoteIp, out _))?.RemoteIp ?? "");
Check("every port in range", rows.All(r => r.RemotePort > 0 && r.RemotePort <= 65535),
    rows.FirstOrDefault(r => r.RemotePort is <= 0 or > 65535)?.RemotePort.ToString() ?? "");
Check("pids are non-negative", rows.All(r => r.Pid >= 0));

v6Client.Close();

// ─────────────────────────────────────────────────────────────────────
// 3. SysmonArchiveService — offline, temp-dir persistence
// ─────────────────────────────────────────────────────────────────────
string tempRoot = Path.Combine(Path.GetTempPath(), "netwatch-selftest-" + Guid.NewGuid().ToString("N")[..8]);
SysmonArchiveService.ArchiveDirectory = tempRoot;

var day1 = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
var day2 = new DateTime(2026, 1, 2, 10, 0, 0, DateTimeKind.Utc);

var e1 = new ArchiveEvent { TsUtc = day1, Eid = 1, RecordId = 101, Data = new() { ["ProcessId"] = "111", ["Image"] = @"C:\temp\alpha.exe", ["CommandLine"] = "alpha --one" } };
var e2 = new ArchiveEvent { TsUtc = day1.AddHours(1), Eid = 3, RecordId = 102, Data = new() { ["ProcessId"] = "111", ["DestinationIp"] = "8.8.8.8", ["Image"] = @"C:\temp\alpha.exe" } };
var e3 = new ArchiveEvent { TsUtc = day1.AddHours(2), Eid = 1, RecordId = 103, Data = new() { ["ProcessId"] = "222", ["Image"] = @"C:\temp\beta.exe", ["CommandLine"] = "beta --two" } };
var e4 = new ArchiveEvent { TsUtc = day2, Eid = 1, RecordId = 104, Data = new() { ["ProcessId"] = "111", ["Image"] = @"C:\temp\alpha.exe", ["CommandLine"] = "alpha --again" } };
var e5 = new ArchiveEvent { TsUtc = day2.AddMinutes(5), Eid = 1, RecordId = 105, Data = new() { ["ProcessId"] = "333", ["Image"] = @"C:\temp\gamma.exe" } };

foreach (var e in new[] { e1, e2, e3, e4, e5 }) SysmonArchiveService.Append(e);

Check("day files rotate by date",
    File.Exists(Path.Combine(tempRoot, "sysmon-archive-2026-01-01.jsonl")) &&
    File.Exists(Path.Combine(tempRoot, "sysmon-archive-2026-01-02.jsonl")));
var (days, total) = SysmonArchiveService.StatusSummary();
Check("status summary counts", days == 2 && total == 5, $"days={days} events={total}");

// watermark dedupe: same event again, and an older one — neither appended
Check("duplicate append is dropped", !SysmonArchiveService.Append(e5));
Check("older-than-watermark append is dropped", !SysmonArchiveService.Append(e1));
var (_, totalAfterDupes) = SysmonArchiveService.StatusSummary();
Check("dedupe kept the count at 5", totalAfterDupes == 5, totalAfterDupes.ToString());

// exact-tie boundary: same ts as watermark, higher record id — appended
var e6 = new ArchiveEvent { TsUtc = day2.AddMinutes(5), Eid = 3, RecordId = 106, Data = new() { ["ProcessId"] = "333", ["DestinationIp"] = "1.1.1.1" } };
Check("same-ts-higher-rid append is accepted", SysmonArchiveService.Append(e6));

// search: newest-first, filters, cap
var all = SysmonArchiveService.Search(null, null, null, 100);
Check("search returns everything newest-first",
    all.Count == 6 && all[0].RecordId == 106 && all[^1].RecordId == 101,
    $"{all.Count} rows, first rid={all.FirstOrDefault()?.RecordId}");
Check("search eid filter", SysmonArchiveService.Search(3, null, null, 100).Count == 2);
Check("search contains matches data values",
    SysmonArchiveService.Search(null, "beta", null, 100).Count == 1 &&
    SysmonArchiveService.Search(null, "beta", null, 100)[0].Data["ProcessId"] == "222");
Check("search since cutoff",
    SysmonArchiveService.Search(null, null, day2, 100).Count == 3);
Check("search max cap", SysmonArchiveService.Search(null, null, null, 2).Count == 2);

// create-event lookup by pid — streamed, newest first, cap honored
var created111 = SysmonArchiveService.SearchCreateEvents(111, 5);
Check("SearchCreateEvents filters pid 111",
    created111.Count == 2 && created111.All(e => e.Data["ProcessId"] == "111"),
    $"count={created111.Count}");
Check("SearchCreateEvents newest first", created111[0].RecordId == 104);

// corrupt-line tolerance: garbage lines must not break the reader
File.AppendAllText(Path.Combine(tempRoot, "sysmon-archive-2026-01-02.jsonl"),
    "{not json at all" + Environment.NewLine);
Check("corrupt lines are skipped",
    SysmonArchiveService.Search(null, null, null, 100).Count == 6);

// prune: everything here predates today → all day files go
int pruned = SysmonArchiveService.Prune(30);
var (daysAfter, eventsAfter) = SysmonArchiveService.StatusSummary();
Check("prune removes expired day files", pruned == 2 && daysAfter == 0 && eventsAfter == 0,
    $"pruned={pruned} days={daysAfter} events={eventsAfter}");
Check("state.json survives prune as the only file",
    Directory.GetFiles(tempRoot).Length == 1 &&
    Directory.GetFiles(tempRoot)[0].EndsWith("state.json"));

try { Directory.Delete(tempRoot, true); } catch { }

Console.WriteLine(failures == 0 ? "\nALL CHECKS PASSED" : $"\n{failures} CHECK(S) FAILED");
return failures == 0 ? 0 : 1;
