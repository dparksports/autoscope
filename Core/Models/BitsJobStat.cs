using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace AutoScope.Models
{
    /// <summary>
    /// "How often they connect": one rollup per (creating process, remote
    /// host) pair, fed every time a BITS transfer starts (EID 59). Keeps a
    /// bounded window of inter-arrival intervals to compute a coefficient
    /// of variation — the same beacon-regularity signal the svchost-watch
    /// analyzer uses, where a LOW CV means machine-like scheduling.
    /// Thread-safe: Add is called from event-log watcher threads.
    /// </summary>
    public class BitsJobStat
    {
        private readonly object _sync = new();
        private const int IntervalWindow = 50;   // intervals kept for the CV
        private const int DayWindow = 30;        // days kept in Daily

        public string CreatorImage { get; set; }
        public string Host { get; set; }
        public string Org { get; set; }

        public int JobCount { get; private set; }
        public int UploadCount { get; private set; }
        public DateTime FirstSeenUtc { get; private set; }
        public DateTime LastSeenUtc { get; private set; }
        public DateTime FirstTransferUtc { get; private set; }

        /// <summary>UTC date (yyyy-MM-dd) → transfer count. Serialized as-is.</summary>
        public Dictionary<string, int> Daily { get; set; } = new();

        /// <summary>Coefficient of variation of inter-arrival intervals, 0…∞ (null until ≥3 intervals).</summary>
        public double? IntervalCv { get; private set; }

        public void Add(DateTime transferUtc, bool isUpload)
        {
            lock (_sync)
            {
                JobCount++;
                if (isUpload) UploadCount++;
                if (FirstSeenUtc == default || transferUtc < FirstSeenUtc) FirstSeenUtc = transferUtc;

                if (_lastTransferUtc == default)
                {
                    FirstTransferUtc = transferUtc;
                }
                else
                {
                    double minutes = (transferUtc - _lastTransferUtc).TotalMinutes;
                    if (minutes >= 0) UpdateCv(minutes);
                }
                _lastTransferUtc = transferUtc;
                if (transferUtc > LastSeenUtc) LastSeenUtc = transferUtc;

                string day = transferUtc.ToString("yyyy-MM-dd");
                Daily[day] = Daily.TryGetValue(day, out int c) ? c + 1 : 1;
                while (Daily.Count > DayWindow)
                {
                    var oldest = Daily.Keys.OrderBy(k => k).First();
                    Daily.Remove(oldest);
                }
            }
        }

        private DateTime _lastTransferUtc;

        private readonly List<double> _intervals = new();
        private void UpdateCv(double minutes)
        {
            _intervals.Add(minutes);
            while (_intervals.Count > IntervalWindow) _intervals.RemoveAt(0);
            if (_intervals.Count >= 3) IntervalCv = ComputeCv(_intervals);
        }

        /// <summary>
        /// Bulk restore from persisted counts — bypasses Add() so replayed
        /// history cannot fabricate zero-length intervals (which would
        /// poison the CV). Fresh intervals rebuild the CV going forward.
        /// </summary>
        public void Restore(int jobCount, int uploadCount, DateTime firstSeenUtc, DateTime lastSeenUtc, Dictionary<string, int> daily)
        {
            lock (_sync)
            {
                JobCount = jobCount;
                UploadCount = uploadCount;
                FirstSeenUtc = firstSeenUtc;
                LastSeenUtc = lastSeenUtc;
                if (daily != null)
                    foreach (var kv in daily) Daily[kv.Key] = kv.Value;
            }
        }

        /// <summary>Pure CV computation (σ/μ) so the self-test can pin the math.</summary>
        public static double? ComputeCv(IReadOnlyList<double> values)
        {
            if (values == null || values.Count < 3) return null;
            double mean = values.Average();
            if (mean <= 0) return null;
            double variance = values.Select(v => (v - mean) * (v - mean)).Sum() / values.Count;
            return Math.Sqrt(variance) / mean;
        }

        // ----- display -----

        [JsonIgnore]
        public string CreatorDisplay => string.IsNullOrEmpty(CreatorImage) ? "—"
            : System.IO.Path.GetFileName(CreatorImage);

        [JsonIgnore]
        public string CountDisplay => JobCount.ToString();

        [JsonIgnore]
        public double PerDayAvg
        {
            get
            {
                var days = (LastSeenUtc.Date - FirstSeenUtc.Date).TotalDays + 1;
                if (days <= 0) return JobCount;
                return JobCount / days;
            }
        }

        [JsonIgnore]
        public string PerDayDisplay => PerDayAvg >= 10 ? $"{PerDayAvg:0}" : $"{PerDayAvg:0.#}";

        /// <summary>Regularity label from the CV: low = metronome-like scheduling.</summary>
        [JsonIgnore]
        public string RegularityDisplay => IntervalCv switch
        {
            null => "—",
            < 0.25 => $"regular (CV {IntervalCv:0.00})",
            < 0.75 => $"moderate (CV {IntervalCv:0.00})",
            _ => $"irregular (CV {IntervalCv:0.00})"
        };

        [JsonIgnore]
        public string UploadShareDisplay => JobCount == 0 ? "—" : $"{100.0 * UploadCount / JobCount:0}%";

        [JsonIgnore]
        public string FirstSeenDisplay => FirstSeenUtc == default ? "—" : FirstSeenUtc.ToLocalTime().ToString("MM-dd HH:mm");

        [JsonIgnore]
        public string LastSeenDisplay => LastSeenUtc == default ? "—" : LastSeenUtc.ToLocalTime().ToString("MM-dd HH:mm");

        [JsonIgnore]
        public string OrgDisplay => string.IsNullOrEmpty(Org) ? "…" : Org;
    }
}
