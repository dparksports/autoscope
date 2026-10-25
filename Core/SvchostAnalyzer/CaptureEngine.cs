using System.Diagnostics;
using System.Management;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SvchostAnalyzer.Core;

/// <summary>Capture parameters — mirrors the CLI flags of the standalone exe.</summary>
public sealed class CaptureOptions
{
    public string OutFile { get; set; } = $"svchost-trace-{DateTime.Now:yyyyMMdd-HHmmss}.jsonl";
    public int PollMs { get; set; } = 1000;

    /// <summary>null = run until Stop() or the stop-file appears (service mode).</summary>
    public TimeSpan? Duration { get; set; } = TimeSpan.FromSeconds(90);

    /// <summary>Rotate the trace file when it exceeds this many megabytes (0 = never).</summary>
    public double MaxSizeMb { get; set; }

    /// <summary>Path whose appearance stops the capture (cross-process stop signal).</summary>
    public string StopFile { get; set; }
}

/// <summary>
/// The svchost capture engine: polls WMI (process/service events) and netstat
/// (TCP table) at a fixed interval and writes four synchronized event streams
/// as JSONL — baseline/spawn/exit, connect/disconnect, bytes. Deliberately
/// non-elevated-friendly: kernel ETW (Sysmon) needs admin, this degrades
/// gracefully instead. Batch queries keep the baseline fast (one WMI
/// roundtrip per table, not one per PID).
///
/// Runs on its own background thread; Start() returns immediately. The same
/// engine powers the SvchostAnalyzer CLI exe and the AutoCommand Svchost
/// Trace tab — linking it in-process removes the child-binary deployment
/// (and its SmartScreen friction) from the app.
/// </summary>
public sealed class CaptureEngine : IDisposable
{
    private static readonly Regex ConnRe = new(
        @"^\s*TCP\s+\S+\s+(?<ip>[^:]+):(?<port>\d+)\s+ESTABLISHED\s+(?<pid>\d+)\s*$",
        RegexOptions.Compiled);

    private readonly CaptureOptions _opt;
    private readonly Dictionary<int, string> _svc = new();
    private readonly Dictionary<string, DateTime> _open = new();
    private readonly HashSet<int> _bytePids = new();
    private string _cur;
    private int _part;
    private int _ticks;
    private Thread _thread;
    private volatile bool _stopRequested;

    /// <summary>Progress lines (baseline stats, periodic tick summaries).</summary>
    public event Action<string> Status;

    /// <summary>Fires when the capture finishes: "out file (+N rotated parts)".</summary>
    public event Action<string> Completed;

    /// <summary>True between Start() and capture completion.</summary>
    public bool IsRunning { get; private set; }

    /// <summary>
    /// Single-instance guard — true while a capture runs in this or any other
    /// process (the standalone exe shares the same Global mutex).
    /// </summary>
    public static bool IsCaptureRunning
    {
        get
        {
            try
            {
                if (Mutex.TryOpenExisting(@"Global\SvchostWatch.CaptureMutex", out Mutex existing))
                {
                    existing.Dispose();
                    return true;
                }
            }
            catch { /* abandoned mutex etc. — treat as not running */ }
            return false;
        }
    }

    public CaptureEngine(CaptureOptions options)
    {
        _opt = options;
        _cur = options.OutFile;
    }

    /// <summary>
    /// Starts the capture on a background thread. Throws
    /// <see cref="InvalidOperationException"/> when another capture is
    /// already running (this process or the standalone exe).
    /// </summary>
    public void Start()
    {
        if (IsRunning) return;

        if (IsCaptureRunning)
            throw new InvalidOperationException("another svchost capture is already running");

        IsRunning = true;
        _stopRequested = false;
        _thread = new Thread(RunCapture) { IsBackground = true, Name = "SvchostCapture" };
        _thread.Start();
    }

    /// <summary>Cooperative stop: sets the flag and waits for the capture thread to flush.</summary>
    public void Stop()
    {
        if (!IsRunning) return;
        _stopRequested = true;
        _thread?.Join(TimeSpan.FromSeconds(10));
    }

    public void Dispose() => Stop();

    // ── capture loop ─────────────────────────────────────────────────────

    private void RunCapture()
    {
        // owned for the whole capture: the scheduled-task autostart and an
        // interactive Start() must never double-capture
        Mutex mutex = null;
        bool owned = false;
        try
        {
            try { mutex = new Mutex(true, @"Global\SvchostWatch.CaptureMutex", out owned); }
            catch (Exception ex)
            {
                Status?.Invoke($"warning: single-instance mutex unavailable ({ex.Message})");
                owned = true;
            }
            if (!owned)
                throw new InvalidOperationException("another svchost capture is already running");

            TimeSpan dur = _opt.Duration ?? Timeout.InfiniteTimeSpan;
            var deadline = DateTime.Now + dur;
            Baseline();
            string reason = _opt.Duration is null ? "stopped" : "duration-elapsed";
            while ((_opt.Duration is null || DateTime.Now < deadline) && !_stopRequested)
            {
                if (_opt.StopFile != null && File.Exists(_opt.StopFile))
                {
                    try { File.Delete(_opt.StopFile); } catch { /* best effort */ }
                    reason = "stop-file";
                    break;
                }
                Tick();
                Thread.Sleep(_opt.PollMs);
            }
            Emit(new JsonObject
            {
                ["type"] = "stop", ["reason"] = reason, ["polls"] = _ticks,
                ["durationSec"] = _opt.Duration is null ? -1 : dur.TotalSeconds,
            });
            Completed?.Invoke(_opt.OutFile + (_part > 0 ? $" (+{_part} rotated file(s))" : ""));
        }
        finally
        {
            try { if (owned) mutex?.ReleaseMutex(); } catch { }
            mutex?.Dispose();
            IsRunning = false;
        }
    }

    private void Baseline()
    {
        var procs = QueryProcesses();
        var svcMap = QueryServiceMap();
        var nameMap = QueryNameMap();

        foreach (var p in procs)
        {
            _svc[p.Pid] = svcMap.TryGetValue(p.Pid, out var s) ? s : "<pending>";
            var baseline = new JsonObject
            {
                ["type"] = "baseline", ["pid"] = p.Pid, ["services"] = _svc[p.Pid],
                ["ppid"] = p.Ppid,
                ["parent"] = nameMap.TryGetValue(p.Ppid, out var pn) ? pn : "<exited>",
                ["created"] = p.Created, ["cmd"] = p.Cmd,
            };
            AddIdentity(baseline, p.Cmd, _svc[p.Pid]);
            Emit(baseline);
        }

        // Connections already established at start (e.g. the persistent WNS push
        // channel) would otherwise never be emitted — only transitions are tracked.
        foreach (var (pid, ip, port) in EstablishedSvchostConns())
        {
            _open[$"{pid}|{ip}:{port}"] = DateTime.Now;
            _bytePids.Add(pid);
            Emit(new JsonObject
            {
                ["type"] = "connect", ["preexisting"] = true, ["pid"] = pid,
                ["services"] = _svc[pid], ["ip"] = ip, ["port"] = port,
            });
        }
        Status?.Invoke($"baseline: {procs.Count} svchost instances, {_open.Count} preexisting connections");
    }

    private void Tick()
    {
        _ticks++;
        var now = DateTime.Now;
        var procs = QueryProcesses();
        var live = procs.Select(p => p.Pid).ToHashSet();

        foreach (var p in procs.Where(p => !_svc.ContainsKey(p.Pid)))
        {
            _svc[p.Pid] = ServiceFor(p.Pid) ?? "<no service>";
            var spawn = new JsonObject
            {
                ["type"] = "spawn", ["pid"] = p.Pid, ["services"] = _svc[p.Pid],
                ["ppid"] = p.Ppid, ["parent"] = NameFor(p.Ppid) ?? "<exited>",
                ["created"] = p.Created, ["cmd"] = p.Cmd,
            };
            AddIdentity(spawn, p.Cmd, _svc[p.Pid]);
            Emit(spawn);
        }

        foreach (var pid in _svc.Keys.Where(k => !live.Contains(k)).ToList())
        {
            Emit(new JsonObject { ["type"] = "exit", ["pid"] = pid, ["services"] = _svc[pid] });
            _svc.Remove(pid);
        }

        var cur = new HashSet<string>();
        foreach (var (pid, ip, port) in EstablishedSvchostConns())
        {
            string key = $"{pid}|{ip}:{port}";
            cur.Add(key);
            if (!_open.ContainsKey(key))
            {
                _open[key] = now;
                _bytePids.Add(pid);
                Emit(new JsonObject
                {
                    ["type"] = "connect", ["pid"] = pid,
                    ["services"] = _svc[pid], ["ip"] = ip, ["port"] = port,
                });
            }
        }
        foreach (var key in _open.Keys.Where(k => !cur.Contains(k)).ToList())
        {
            var parts = key.Split('|');
            double d = (now - _open[key]).TotalSeconds;
            Emit(new JsonObject
            {
                ["type"] = "disconnect", ["pid"] = int.Parse(parts[0]),
                ["ipport"] = parts[1], ["dur"] = Math.Round(d, 1),
            });
            _open.Remove(key);
        }

        if (_ticks % 5 == 0)
            foreach (var p in procs.Where(p => _bytePids.Contains(p.Pid)))
                Emit(new JsonObject { ["type"] = "bytes", ["pid"] = p.Pid, ["r"] = p.R, ["w"] = p.W });

        if (_ticks % 15 == 0)
            Status?.Invoke($"tick {_ticks}: {_svc.Count} instances, {_open.Count} connections");
    }

    /// <summary>
    /// Stamps a baseline/spawn event with the instance's command-line
    /// identity: "k" (-k group), "s" (-s self-declared service), and two
    /// masquerade markers — "mismatch" (the -s claim contradicts the
    /// SCM-resident services) and "noK" (a readable command line without a
    /// -k group: the SCM always passes -k, so a visible line lacking it is
    /// not a service host). Hidden command lines (non-elevated WMI cannot
    /// read SYSTEM processes) emit nothing here — that's the normal case,
    /// summarized by the analyzer instead of flagged.
    /// </summary>
    private static void AddIdentity(JsonObject o, string cmd, string servicesCsv)
    {
        var id = SvchostIdentity.Parse(cmd);
        if (id.Group != null) o["k"] = id.Group;
        if (id.DeclaredService != null) o["s"] = id.DeclaredService;
        if (!string.IsNullOrEmpty(cmd) && id.Group == null) o["noK"] = true;
        // "<pending>"/"<no service>" placeholders are not SCM data — nothing to corroborate against
        if (SvchostIdentity.Mismatches(id.DeclaredService,
                string.IsNullOrEmpty(servicesCsv) || servicesCsv.StartsWith('<') ? null : servicesCsv))
            o["mismatch"] = true;
    }

    private void Emit(JsonObject o)
    {
        o["t"] = DateTime.Now.ToString("o");
        try
        {
            // size-capped rotation so an indefinite (service-mode) capture can't
            // grow unbounded; parts are separate files the analyzer takes as args
            if (_opt.MaxSizeMb > 0 && File.Exists(_cur) &&
                new FileInfo(_cur).Length >= (long)(_opt.MaxSizeMb * 1024 * 1024))
            {
                _part++;
                _cur = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(_opt.OutFile))!,
                                    $"{Path.GetFileNameWithoutExtension(_opt.OutFile)}-{_part}.jsonl");
                var rot = new JsonObject { ["type"] = "rotate", ["part"] = _part };
                rot["t"] = DateTime.Now.ToString("o");
                File.AppendAllText(_cur, rot.ToJsonString() + "\n");
            }
        }
        catch { /* rotation is best-effort; keep appending to the current file */ }
        File.AppendAllText(_cur, o.ToJsonString() + "\n");
    }

    // ── WMI / netstat access ─────────────────────────────────────────────

    private static List<(int Pid, int Ppid, string Created, string Cmd, long R, long W)> QueryProcesses()
    {
        var list = new List<(int, int, string, string, long, long)>();
        using var s = new ManagementObjectSearcher(
            "SELECT ProcessId, ParentProcessId, CreationDate, CommandLine, ReadTransferCount, WriteTransferCount " +
            "FROM Win32_Process WHERE Name = 'svchost.exe'");
        foreach (ManagementObject o in s.Get())
            list.Add((Convert.ToInt32(o["ProcessId"]), Convert.ToInt32(o["ParentProcessId"]),
                o["CreationDate"]?.ToString() ?? "", o["CommandLine"]?.ToString() ?? "",
                Convert.ToInt64(o["ReadTransferCount"] ?? 0L), Convert.ToInt64(o["WriteTransferCount"] ?? 0L)));
        return list;
    }

    /// <summary>All services grouped by hosting PID — one roundtrip for the whole table.</summary>
    private static Dictionary<int, string> QueryServiceMap()
    {
        var map = new Dictionary<int, List<string>>();
        using var s = new ManagementObjectSearcher("SELECT Name, ProcessId FROM Win32_Service");
        foreach (ManagementObject o in s.Get())
        {
            int pid = Convert.ToInt32(o["ProcessId"]);
            if (pid == 0) continue;
            (map.TryGetValue(pid, out var l) ? l : map[pid] = new List<string>()).Add(o["Name"].ToString());
        }
        return map.ToDictionary(kv => kv.Key, kv => string.Join(",", kv.Value));
    }

    /// <summary>PID → process name for parent attribution — one roundtrip.</summary>
    private static Dictionary<int, string> QueryNameMap()
    {
        var map = new Dictionary<int, string>();
        using var s = new ManagementObjectSearcher("SELECT ProcessId, Name FROM Win32_Process");
        foreach (ManagementObject o in s.Get())
            map[Convert.ToInt32(o["ProcessId"])] = o["Name"].ToString();
        return map;
    }

    private static string ServiceFor(int pid)
    {
        using var s = new ManagementObjectSearcher($"SELECT Name FROM Win32_Service WHERE ProcessId = {pid}");
        foreach (ManagementObject o in s.Get()) return o["Name"].ToString();
        return null;
    }

    private static string NameFor(int pid)
    {
        using var s = new ManagementObjectSearcher($"SELECT Name FROM Win32_Process WHERE ProcessId = {pid}");
        foreach (ManagementObject o in s.Get()) return o["Name"].ToString();
        return null;
    }

    private List<(int Pid, string Ip, int Port)> EstablishedSvchostConns()
    {
        var list = new List<(int, string, int)>();
        var psi = new ProcessStartInfo("netstat", "-ano -p tcp")
        { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true };
        using var p = Process.Start(psi);
        string output = p.StandardOutput.ReadToEnd();
        p.WaitForExit(5000);
        foreach (var line in output.Split('\n'))
        {
            var m = ConnRe.Match(line);
            if (!m.Success) continue;
            string ip = m.Groups["ip"].Value;
            if (ip.StartsWith("127.") || ip.Contains("::1")) continue;
            int pid = int.Parse(m.Groups["pid"].Value);
            if (_svc.ContainsKey(pid))
                list.Add((pid, ip, int.Parse(m.Groups["port"].Value)));
        }
        return list;
    }
}
