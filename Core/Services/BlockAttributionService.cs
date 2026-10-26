using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;


using AutoScope.Engines.Watch;

namespace AutoScope.Services
{
    /// <summary>
    /// Recovers the service identity for block records whose attribution is
    /// still "none" — the 50-of-64 "svchost"/"&lt;unknown process&gt;" rows
    /// legacy files carry. The PID is long recycled by the time anyone opens
    /// the Blocks tab, but the 30-day Sysmon archive still holds the chain:
    ///   EID 3 (network, DestinationIp = the blocked key)
    ///     → ProcessId → EID 1 (process create) → Image + CommandLine
    ///     → svchost -s token / exe stem  →  serviceKey + display name.
    /// Batched into two archive passes (connections, then creates) instead
    /// of a scan per record. Best-effort per record: anything the archive
    /// cannot answer stays honestly unresolved instead of guessed.
    /// </summary>
    public static class BlockAttributionService
    {
        /// <summary>Runs the repair over every unresolved record.</summary>
        public static async Task<(int repaired, int unresolved)> RepairAllAsync(
            IProgress<string> progress = null)
        {
            return await Task.Run(() =>
            {
                var pending = BlocksStore.Default.Records.Where(NeedsRepair).ToList();
                int repaired = 0, unresolved = 0;
                if (pending.Count == 0) return (0, 0);

                // Pass 1 — newest archived connection per blocked IP / image.
                var conns = SysmonArchiveService.NewestConnectionPerIp(
                    pending.Where(r => r.Kind == "ip").Select(r => r.Key));
                foreach (var r in pending.Where(r => r.Kind != "ip"))
                {
                    // proc rows rarely need the archive (their path IS the
                    // identity) — only the create lookup below when present.
                    var imgHit = SysmonArchiveService.NewestConnectionPerImage(
                        new[] { r.Key });
                    foreach (var kv in imgHit) conns[r.Key] = kv.Value;
                }

                // Pass 2 — newest create-event per connecting PID.
                var pids = new HashSet<int>();
                foreach (var c in conns.Values)
                    if (c.Data.TryGetValue("ProcessId", out string pidS) && int.TryParse(pidS, out int pid))
                        pids.Add(pid);
                var creates = SysmonArchiveService.NewestCreateEventPerPid(pids);

                var updates = new List<(string kind, string key, string serviceKey, string displayName, string source)>();
                foreach (var r in pending)
                {
                    try
                    {
                        (string serviceKey, string displayName)? hit = null;
                        string source = "sysmon";

                        if (conns.TryGetValue(r.Key, out var net) &&
                            net.Data.TryGetValue("ProcessId", out string pidS) &&
                            int.TryParse(pidS, out int pid))
                        {
                            if (creates.TryGetValue(pid.ToString(), out var create) &&
                                create.TsUtc <= net.TsUtc) // pid-recycled since → wrong tenant, stay honest
                            {
                                hit = IdentityFromCreate(create.Data);
                            }
                            else
                            {
                                // No create in the archive window — but the PID
                                // may still be the live tenant (svchost hosts
                                // run for days). SCM ground truth, guarded
                                // against PID reuse by image + start time.
                                hit = LiveIdentityFor(pid,
                                    net.Data.TryGetValue("Image", out string img) ? img : null,
                                    net.TsUtc);
                                if (hit != null) source = "scm";
                            }
                        }

                        if (hit != null)
                        {
                            updates.Add((r.Kind, r.Key, hit.Value.serviceKey, hit.Value.displayName, source));
                            repaired++;
                            progress?.Report($"{r.Key} → {hit.Value.displayName}");
                            continue;
                        }

                        // No archive evidence: fall back to the exe stem for
                        // proc records (a path is its own identity), and leave
                        // IP records attributed-to-unknown.
                        if (r.Kind == "proc")
                        {
                            string stem = Path.GetFileNameWithoutExtension(r.Key).ToLowerInvariant();
                            if (stem.Length > 0)
                            {
                                updates.Add((r.Kind, r.Key, stem,
                                    ServiceCatalog.DisplayNameFor(stem, null), "catalog"));
                                repaired++;
                                continue;
                            }
                        }
                        unresolved++;
                    }
                    catch { unresolved++; /* one bad record never stops the pass */ }
                }
                BlocksStore.Default.SetAttributions(updates); // one save for the whole pass
                return (repaired, unresolved);
            });
        }

        private static bool NeedsRepair(BlockRecord r) =>
            string.IsNullOrEmpty(r.ServiceKey) || r.Attrib == "none";

        /// <summary>
        /// Identity for a connecting PID that is STILL RUNNING: the SCM's
        /// PID→service map, accepted only when the live process's image
        /// matches the archived event's image AND its start time predates
        /// the event (a recycled PID carrying a different tenant is not a
        /// match — honesty over coverage).
        /// </summary>
        private static (string serviceKey, string displayName)? LiveIdentityFor(
            int pid, string expectedImage, DateTime startedBeforeUtc)
        {
            if (string.IsNullOrEmpty(expectedImage)) return null;
            try
            {
                string path = null;
                DateTime? startedUtc = null;
                using (var s = new System.Management.ManagementObjectSearcher(
                           $"SELECT ExecutablePath, CreationDate FROM Win32_Process WHERE ProcessId = {pid}"))
                    foreach (System.Management.ManagementObject o in s.Get())
                    {
                        path = o["ExecutablePath"]?.ToString();
                        startedUtc = ParseDmtf(o["CreationDate"]?.ToString());
                        break;
                    }

                // Start time is the real PID-reuse guard: a recycled tenant
                // starts AFTER the archived connection. The live path is
                // corroboration only — WMI hides it for SYSTEM processes
                // when queried non-elevated.
                if (startedUtc == null || startedUtc.Value > startedBeforeUtc) return null;
                if (!string.IsNullOrEmpty(path) &&
                    !string.Equals(path, expectedImage, StringComparison.OrdinalIgnoreCase))
                    return null;

                string stem = Path.GetFileNameWithoutExtension(expectedImage).ToLowerInvariant();
                if (stem != "svchost")
                    return (stem, ServiceCatalog.DisplayNameFor(stem, null));

                var id = SvchostIdentityService.Resolve(pid);
                string key =
                    !string.IsNullOrEmpty(id.DeclaredService) ? id.DeclaredService.ToLowerInvariant()
                    : !string.IsNullOrEmpty(id.ServicesCsv) ? id.ServicesCsv.Split(',')[0].Trim().ToLowerInvariant()
                    : !string.IsNullOrEmpty(id.Group) ? "svchost:" + id.Group.ToLowerInvariant()
                    : null;
                if (key == null) return null;
                return (key, ServiceCatalog.DisplayNameFor(key, null));
            }
            catch { return null; }
        }

        /// <summary>DMTF "20261019152432.500000+420" → UTC; null when absent.</summary>
        private static DateTime? ParseDmtf(string dmtf)
        {
            if (string.IsNullOrEmpty(dmtf) || dmtf.Length < 14) return null;
            if (!DateTime.TryParseExact(dmtf.Substring(0, 14), "yyyyMMddHHmmss",
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out DateTime local)) return null;
            // trailing ±mmm is the UTC offset in minutes ("…924648-420")
            int off = 0;
            if (dmtf.Length >= 25)
            {
                string tail = dmtf.Substring(21);
                if ((tail.StartsWith("+") || tail.StartsWith("-")) && int.TryParse(tail.Substring(1), out int m))
                    off = tail.StartsWith("-") ? -m : m;
            }
            return local.AddMinutes(-off).ToUniversalTime();
        }

        /// <summary>Turns an EID 1 data dictionary into the grouping identity:
        /// svchost rows resolve via the -s service (else the -k group), any
        /// other image resolves to its exe stem.</summary>
        private static (string serviceKey, string displayName)? IdentityFromCreate(
            Dictionary<string, string> data)
        {
            if (!data.TryGetValue("Image", out string image) || string.IsNullOrEmpty(image))
                return null;
            string stem = Path.GetFileNameWithoutExtension(image).ToLowerInvariant();

            if (stem == "svchost")
            {
                string cmd = data.TryGetValue("CommandLine", out string c) ? c : null;
                var parsed = AutoScope.Engines.Watch.SvchostIdentity.Parse(cmd);
                if (!string.IsNullOrEmpty(parsed.DeclaredService))
                {
                    string svc = parsed.DeclaredService.ToLowerInvariant();
                    return (svc, ServiceCatalog.DisplayNameFor(svc, null));
                }
                if (!string.IsNullOrEmpty(parsed.Group))
                    return ($"svchost:{parsed.Group.ToLowerInvariant()}", $"svchost — {parsed.Group} service group");
                return ("svchost:unresolved", "svchost — service unknown");
            }

            return (stem, ServiceCatalog.DisplayNameFor(stem, null));
        }
    }
}
