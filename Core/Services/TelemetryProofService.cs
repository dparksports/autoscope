using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace AutoScope.Services
{
    /// <summary>
    /// Persists denied-telemetry attempts and keeps the aggregate counters the
    /// Black Hole tab shows. The store is plain JSONL next to the app
    /// (telemetry_proof.jsonl) — readable, greppable, deletable, in line with
    /// the app's no-hidden-state rule. The in-memory feed keeps the trailing
    /// window for the grid; totals always aggregate the whole file (small by
    /// nature — attempts are beacon-rate, not line-rate).
    /// </summary>
    public sealed class TelemetryProofService
    {
        public static TelemetryProofService Instance { get; } = new();

        private const int MaxRecentRows = 2000;
        private static readonly Encoding NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        private static string ProofFile =>
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "telemetry_proof.jsonl");

        private readonly object _lock = new();
        private readonly List<TelemetryDeniedAttempt> _recent = new();

        public event Action Changed;

        public int TotalDenied { get; private set; }
        public DateTime? FirstAttemptUtc { get; private set; }
        public DateTime? LastAttemptUtc { get; private set; }

        public IReadOnlyList<TelemetryDeniedAttempt> Recent
        {
            get { lock (_lock) return _recent.ToList(); }
        }

        private TelemetryProofService()
        {
            Load();
            SinkholeService.Instance.OnAttempt += Record;
        }

        /// <summary>Per-hostname totals over the whole persisted history.</summary>
        public List<(string Hostname, int Count)> TotalsByHostname() =>
            ScanFile()
                .GroupBy(a => a.Hostname, StringComparer.OrdinalIgnoreCase)
                .Select(g => (Hostname: g.Key, Count: g.Count()))
                .OrderByDescending(t => t.Count)
                .ToList();

        /// <summary>Per-process totals over the whole persisted history.</summary>
        public List<(string Process, int Count)> TotalsByProcess() =>
            ScanFile()
                .GroupBy(a => ProcessKey(a), StringComparer.OrdinalIgnoreCase)
                .Select(g => (Process: g.Key, Count: g.Count()))
                .OrderByDescending(t => t.Count)
                .ToList();

        public static string ProcessKey(TelemetryDeniedAttempt a) =>
            string.IsNullOrEmpty(a.ProcessImage) ? $"pid {a.Pid}" : Path.GetFileName(a.ProcessImage);

        private void Record(TelemetryDeniedAttempt attempt)
        {
            if (attempt == null) return;
            try
            {
                // UTF-8 without BOM — a preamble on the first line would make it
                // unparseable on reload (the same trap ultralytics' settings hit)
                File.AppendAllText(ProofFile,
                    JsonSerializer.Serialize(attempt) + Environment.NewLine, NoBom);
            }
            catch { /* disk full/locked — the in-memory feed still works */ }

            lock (_lock)
            {
                _recent.Add(attempt);
                if (_recent.Count > MaxRecentRows) _recent.RemoveAt(0);
                TotalDenied++;
                FirstAttemptUtc ??= attempt.TimeUtc;
                LastAttemptUtc = attempt.TimeUtc;
            }
            Changed?.Invoke();
        }

        /// <summary>Wipes the proof history (file and counters). Not the pins themselves.</summary>
        public void Clear()
        {
            lock (_lock)
            {
                _recent.Clear();
                TotalDenied = 0;
                FirstAttemptUtc = null;
                LastAttemptUtc = null;
            }
            try { File.Delete(ProofFile); } catch { }
            Changed?.Invoke();
        }

        private void Load()
        {
            try
            {
                var parsed = ScanFile();
                lock (_lock)
                {
                    _recent.AddRange(parsed.Skip(Math.Max(0, parsed.Count - MaxRecentRows)));
                    TotalDenied = parsed.Count;
                    FirstAttemptUtc = parsed.FirstOrDefault()?.TimeUtc;
                    LastAttemptUtc = parsed.LastOrDefault()?.TimeUtc;
                }
            }
            catch { /* unreadable store starts fresh */ }
        }

        private static List<TelemetryDeniedAttempt> ScanFile()
        {
            var parsed = new List<TelemetryDeniedAttempt>();
            if (!File.Exists(ProofFile)) return parsed;
            foreach (var line in File.ReadLines(ProofFile))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var attempt = JsonSerializer.Deserialize<TelemetryDeniedAttempt>(line);
                    if (attempt != null) parsed.Add(attempt);
                }
                catch { /* skip a torn line — never lose the rest */ }
            }
            return parsed;
        }
    }
}
