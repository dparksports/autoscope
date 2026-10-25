using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace AutoScope.Services
{
    /// <summary>One telemetry pin found in the hosts file.</summary>
    public class TelemetryPin
    {
        public string Address { get; set; }      // 0.0.0.0 (silent) or 127.0.0.1 (sinkhole)
        public string Hostname { get; set; }
        public string Marker { get; set; }       // full marker line, e.g. "# AutoScope telemetry-block ultralytics-sync"
        public bool IsSinkhole => Address == "127.0.0.1";
    }

    /// <summary>
    /// Reads and rewrites the telemetry-block pins that AutoScope and Shields Up
    /// write into the hosts file. Every pin lives under a marker line carrying the
    /// rule id; this class only ever touches lines under those markers, so user
    /// edits are never modified or removed. Pure text in/out — trivially testable.
    /// </summary>
    public static class HostsTelemetryPins
    {
        public const string SinkholeAddress = "127.0.0.1";
        public const string SilentAddress = "0.0.0.0";

        private static readonly string[] MarkerPrefixes =
        {
            "# AutoScope telemetry-block ",
            "# ShieldsUp telemetry-block ",
        };

        public static string HostsPath()
        {
            string system = Environment.GetFolderPath(Environment.SpecialFolder.System);
            if (string.IsNullOrEmpty(system))
                system = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows\System32";
            return Path.Combine(system, "drivers", "etc", "hosts");
        }

        /// <summary>Parses every marked pin from hosts-file text (or null for none).</summary>
        public static List<TelemetryPin> Parse(string hostsText)
        {
            var pins = new List<TelemetryPin>();
            if (string.IsNullOrEmpty(hostsText)) return pins;
            var prefixes = MarkerPrefixes.Select(p => p.TrimEnd()).ToArray();

            string marker = null;
            foreach (string raw in hostsText.Split('\n'))
            {
                string line = raw.TrimEnd('\r').Trim();
                string candidate = prefixes.FirstOrDefault(p => line.StartsWith(p, StringComparison.OrdinalIgnoreCase));
                if (candidate != null) { marker = line; continue; }
                if (marker == null) continue;

                // Pin lines are "<address> <hostname>"; anything else ends the block
                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2 && Uri.CheckHostName(parts[1]) != UriHostNameType.Unknown)
                    pins.Add(new TelemetryPin { Address = parts[0], Hostname = parts[1], Marker = marker });
                else
                    marker = null;   // blank line or unexpected content closes the block
            }
            return pins;
        }

        /// <summary>
        /// Rewrites every marked pin to the given address, returning the new hosts
        /// text. Untouched: everything outside marked blocks, and any line inside a
        /// block that is not a pin. Pins already at the address pass through as-is
        /// (normalizing their spacing to "<address> <hostname>").
        /// </summary>
        public static string SetPinAddress(string hostsText, string address)
        {
            if (address != SinkholeAddress && address != SilentAddress)
                throw new ArgumentException("Only 0.0.0.0 and 127.0.0.1 are permitted pin addresses.", nameof(address));

            var lines = hostsText.Replace("\r\n", "\n").Split('\n').ToList();
            var prefixes = MarkerPrefixes.Select(p => p.TrimEnd()).ToArray();
            bool inBlock = false;

            for (int i = 0; i < lines.Count; i++)
            {
                string line = lines[i].Trim();
                if (prefixes.Any(p => line.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
                {
                    inBlock = true;
                    continue;
                }
                if (!inBlock) continue;

                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2 && Uri.CheckHostName(parts[1]) != UriHostNameType.Unknown)
                    lines[i] = $"{address} {parts[1]}";
                else
                    inBlock = false;   // end of this block
            }
            return string.Join("\r\n", lines);
        }

        /// <summary>True when any marked pin currently points at the sinkhole.</summary>
        public static bool AnySinkhole(List<TelemetryPin> pins) =>
            pins.Any(p => p.IsSinkhole);

        /// <summary>Reads the live hosts file and returns its pins (empty list when unreadable).</summary>
        public static List<TelemetryPin> ReadLive()
        {
            try
            {
                string path = HostsPath();
                return File.Exists(path) ? Parse(File.ReadAllText(path)) : new List<TelemetryPin>();
            }
            catch { return new List<TelemetryPin>(); }
        }
    }
}
