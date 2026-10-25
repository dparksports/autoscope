using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;

namespace AutoScope.Models
{
    /// <summary>Firewall-block state of one blockable target (remote IP or executable).</summary>
    public enum BlockRuleState
    {
        None,
        Active,   // enabled block rules match — traffic is denied
        Paused    // rules exist but are all disabled (fleet pause) — traffic flows
    }

    public class SvchostMonitorItem : INotifyPropertyChanged, IResolvableHost
    {
        private long _rxPackets;
        private long _txPackets;
        private long _rxBytes;
        private long _txBytes;
        private DateTime _lastSeen;
        private string _processName;
        private string _hostname;
        private string _taskName;
        private string _taskUser;

        public int ProcessId { get; set; }
        public string RemoteIp { get; set; }
        public string Protocol { get; set; }

        /// <summary>
        /// Full executable path as logged by Sysmon (null when unknown). It
        /// identifies the row's process even after that process has exited,
        /// which is when the live name lookup would otherwise come up empty.
        /// </summary>
        public string ImagePath { get; set; }

        /// <summary>
        /// When the row's process started (UTC), captured once at row
        /// creation. PIDs are recycled aggressively; this timestamp — with
        /// the Sysmon image path — is the row's stable process identity.
        /// Later PID inquiries use it to tell the row's process from any
        /// unrelated process that has since inherited the number.
        /// </summary>
        public DateTime? ProcessStartedUtc { get; set; }

        public string Hostname
        {
            get => _hostname;
            set
            {
                if (_hostname == value) return;
                _hostname = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsResolved));
                OnPropertyChanged(nameof(HostnameDisplay));
            }
        }

        /// <summary>True when the hostname has been resolved to a real name (not raw IP / empty).</summary>
        public bool IsResolved =>
            !string.IsNullOrEmpty(_hostname) &&
            _hostname != "Unknown" &&
            _hostname != "-" &&
            !System.Net.IPAddress.TryParse(_hostname, out _);

        /// <summary>Friendly display — shows italic '(resolving…)' when not yet resolved.</summary>
        public string HostnameDisplay =>
            IsResolved ? _hostname : string.IsNullOrEmpty(_hostname) ? "resolving…" : _hostname;

        public string ProcessName
        {
            get => _processName;
            set { _processName = value; OnPropertyChanged(); OnPropertyChanged(nameof(ProcessDisplay)); }
        }

        /// <summary>
        /// Last time traffic was seen for this remote IP — seeded from the
        /// Sysmon event time at row creation (the triggering packets usually
        /// crossed the wire before the row existed), then refreshed by the
        /// sniffer on every matched packet, sent or received.
        /// </summary>
        public DateTime LastSeen
        {
            get => _lastSeen;
            set
            {
                _lastSeen = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(LastSeenDisplay));
                OnPropertyChanged(nameof(IsStale));
            }
        }

        /// <summary>True when no traffic has been seen for over five minutes (row dims).</summary>
        public bool IsStale => _lastSeen != default && DateTime.UtcNow - _lastSeen > TimeSpan.FromMinutes(5);

        private bool _hasExited;

        private string _parentImage;
        private string _nameRevealedFrom;
        private bool _nameProbeDone;

        /// <summary>
        /// Image of the process that spawned this row's process (from the
        /// Sysmon create-record), when known. The "spawned by git.exe"
        /// context is what makes unfamiliar helper names readable —
        /// "git-remote-https.exe" alone tells a user nothing.
        /// </summary>
        public string ParentImage
        {
            get => _parentImage;
            set { _parentImage = value; OnPropertyChanged(nameof(ProcessToolTip)); OnPropertyChanged(nameof(HasToolTip)); }
        }

        /// <summary>
        /// True for rows whose name never resolved — candidates for the
        /// archive-backed reveal pass (one attempt per row; the day-file
        /// scan is real disk work and the archive does not grow backwards).
        /// </summary>
        public bool NeedsNameReveal => string.IsNullOrEmpty(ProcessName) && !_nameProbeDone;

        /// <summary>Claims the row for the one-shot reveal pass; false when already attempted.</summary>
        public bool TryBeginNameProbe()
        {
            if (_nameProbeDone) return false;
            _nameProbeDone = true;
            return true;
        }

        /// <summary>
        /// Overwrites the row's identity with what a Sysmon record (trace
        /// or archive) proved the process really is — closing the loop for
        /// rows named by a recycled PID or never named at all. The previous
        /// display name is kept for the tooltip, so a correction is visible
        /// instead of silent.
        /// </summary>
        public void RevealIdentity(string name, string imagePath, string parentImage)
        {
            if (string.IsNullOrEmpty(ImagePath) && !string.IsNullOrEmpty(imagePath))
                ImagePath = imagePath;
            if (string.IsNullOrEmpty(_parentImage) && !string.IsNullOrEmpty(parentImage))
                ParentImage = parentImage;
            if (!string.IsNullOrEmpty(name) && !SameProcessName(name, ProcessName))
            {
                _nameRevealedFrom = ProcessName;
                ProcessName = System.IO.Path.GetFileName(name);
            }
            OnPropertyChanged(nameof(ProcessToolTip));
            OnPropertyChanged(nameof(HasToolTip));
        }

        /// <summary>
        /// Name equality that tolerates the app's two name shapes (Sysmon
        /// basenames carry ".exe", live ProcessName lookups do not).
        /// </summary>
        private static bool SameProcessName(string a, string b)
        {
            if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b))
                return string.IsNullOrEmpty(a) && string.IsNullOrEmpty(b);
            string fa = System.IO.Path.GetFileName(a);
            string fb = System.IO.Path.GetFileName(b);
            return string.Equals(fa, fb, StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(System.IO.Path.GetFileNameWithoutExtension(fa),
                                 System.IO.Path.GetFileNameWithoutExtension(fb),
                                 StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// True once the row's process has been observed to have exited. The
        /// row keeps its history (trace/block still work off the Sysmon image
        /// path) but is labeled so a dead connection stops looking live.
        /// </summary>
        public bool HasExited
        {
            get => _hasExited;
            private set { _hasExited = value; OnPropertyChanged(); }
        }

        /// <summary>Labels the row's process as exited (view's refresh timer, PID snapshot).</summary>
        public void MarkExited()
        {
            if (HasExited) return;
            HasExited = true;
            OnPropertyChanged(nameof(ProcessDisplay));
        }

        /// <summary>
        /// Hands the row to a new process after its original one exited and a
        /// different PID connected to the same remote IP, so counters keep
        /// accruing to a live process instead of a ghost PID.
        /// </summary>
        public void Reattribute(int processId, string processName, string imagePath,
                                DateTime? processStartedUtc = null)
        {
            ProcessId = processId;
            ProcessName = processName;
            if (!string.IsNullOrEmpty(imagePath)) ImagePath = imagePath;
            ProcessStartedUtc = processStartedUtc;

            TaskName = null;   // the old process's task attribution no longer applies
            TaskUser = null;

            // The old tenant's reveal state does not describe the new one
            // either — the newcomer gets its own name-probe pass.
            _nameRevealedFrom = null;
            _nameProbeDone = false;
            _parentImage = null;

            // The old tenant's service identity does not describe the new one
            // either — enrichment re-resolves it for the new process.
            _identityResolved = false;
            _hostedServices = null;
            _servicesDetail = null;
            _svchostGroup = null;
            _declaredService = null;
            _identitySuspicious = false;

            HasExited = false;
            OnPropertyChanged(nameof(ProcessDisplay));
            OnPropertyChanged(nameof(ProcessToolTip));
        }

        // -------------------------------------------------------------------
        // svchost identity — "which of the 74 instances is this?"
        //
        // svchost.exe is one generic binary; an instance's identity is the
        // SCM's PID→service map (ground truth) corroborated by its command
        // line (-k group · -s single tenant). Resolved asynchronously by
        // SvchostIdentityService once per row.
        // -------------------------------------------------------------------

        /// <summary>True when this row's process is a service host image.</summary>
        public bool IsSvchost =>
            string.Equals(ProcessName, "svchost.exe", StringComparison.OrdinalIgnoreCase);

        private string _hostedServices;    // SCM-resident service names, csv ("WpnService")
        private string _servicesDetail;    // names + display names + state, multi-line, for tooltips
        private string _svchostGroup;      // -k netsvcs
        private string _declaredService;   // -s WpnService
        private bool _identitySuspicious;  // -s/SCM mismatch, or visible cmdline without -k
        private bool _cmdLineHidden;       // svchost row whose command line was unreadable
        private bool _identityResolved;
        private bool _identityPending;

        /// <summary>True while the row is a svchost whose identity has not been resolved yet.</summary>
        public bool NeedsSvchostIdentity => IsSvchost && !_identityResolved && !_identityPending;

        /// <summary>
        /// Claims the row for identity resolution (one async attempt at a
        /// time); false when resolution is already done or in flight.
        /// </summary>
        public bool TryBeginIdentity()
        {
            if (!NeedsSvchostIdentity) return false;
            _identityPending = true;
            return true;
        }

        /// <summary>Releases a failed resolve attempt so the next tick can retry.</summary>
        public void AbandonIdentity() => _identityPending = false;

        /// <summary>Raw SCM-resident service names csv ("WpnService") — the
        /// block record's identity source; empty before resolution.</summary>
        public string HostedServicesCsv => _hostedServices ?? "";

        /// <summary>-k service group, when the command line was readable.</summary>
        public string SvchostGroup => _svchostGroup;

        /// <summary>-s self-declared service, when present.</summary>
        public string DeclaredService => _declaredService;

        /// <summary>Stamps the resolved svchost identity (SCM services + -k/-s tokens).</summary>
        public void SetSvchostIdentity(string hostedServicesCsv, string servicesDetail,
                                       string group, string declaredService,
                                       bool commandLineVisible, bool suspicious)
        {
            _hostedServices = hostedServicesCsv ?? "";
            _servicesDetail = servicesDetail;
            _svchostGroup = group;
            _declaredService = declaredService;
            _identitySuspicious = suspicious;
            _cmdLineHidden = !commandLineVisible;
            _identityResolved = true;
            _identityPending = false;
            OnPropertyChanged(nameof(ProcessDisplay));
            OnPropertyChanged(nameof(ProcessToolTip));
            OnPropertyChanged(nameof(IdentityLabel));
        }

        /// <summary>Compact service list for the Process cell: "WpnService", "A+B", "A+2 more".</summary>
        private string ServicesCompact
        {
            get
            {
                if (string.IsNullOrEmpty(_hostedServices)) return "no service";
                var names = _hostedServices.Split(',');
                return names.Length == 1 ? names[0]
                    : names.Length == 2 ? $"{names[0]}+{names[1]}"
                    : $"{names[0]}+{names.Length - 1} more";
            }
        }

        /// <summary>
        /// True once the row's hosted services are known (resolved identity
        /// with at least one SCM service).
        /// </summary>
        public bool HasServiceIdentity => IsSvchost && _identityResolved && !string.IsNullOrEmpty(_hostedServices);

        /// <summary>
        /// Short identity label for dropdowns and report text: the hosted
        /// service for svchost rows, the image name for everything else.
        /// </summary>
        public string IdentityLabel =>
            IsSvchost && _identityResolved ? ServicesCompact : (ProcessName ?? "?");

        /// <summary>
        /// True when the resolved identity carries a masquerade signal — the
        /// -s claim contradicts the SCM, or a readable command line has no -k.
        /// </summary>
        public bool IdentitySuspicious => _identitySuspicious;

        /// <summary>
        /// Friendly display: "PID (name)", "PID (svchost.exe [WpnService])"
        /// for resolved service hosts (the bracket is what tells the 74
        /// svchost instances apart), "— exited" once the process is gone.
        /// </summary>
        public string ProcessDisplay
        {
            get
            {
                string text;
                if (IsSvchost && _identityResolved)
                    text = $"{ProcessId} (svchost.exe [{ServicesCompact}]{(_identitySuspicious ? " ⚠" : "")})";
                else if (string.IsNullOrEmpty(ProcessName))
                    text = ProcessId.ToString();
                else
                    text = $"{ProcessId} ({ProcessName})";
                return HasExited ? $"{text} — exited" : text;
            }
        }

        /// <summary>Human-readable last-seen time.</summary>
        public string LastSeenDisplay
        {
            get
            {
                if (_lastSeen == default) return "—";
                var age = DateTime.UtcNow - _lastSeen;
                if (age.TotalSeconds < 5)  return "just now";
                if (age.TotalSeconds < 60) return $"{(int)age.TotalSeconds}s ago";
                if (age.TotalMinutes < 60) return $"{(int)age.TotalMinutes}m ago";
                return _lastSeen.ToLocalTime().ToString("HH:mm:ss");
            }
        }

        public long RxPackets
        {
            get => _rxPackets;
            set { _rxPackets = value; OnPropertyChanged(); }
        }

        public long TxPackets
        {
            get => _txPackets;
            set { _txPackets = value; OnPropertyChanged(); }
        }

        public long RxBytes
        {
            get => _rxBytes;
            set { _rxBytes = value; OnPropertyChanged(); OnPropertyChanged(nameof(RxBytesDisplay)); OnPropertyChanged(nameof(IsTxOnly)); }
        }

        public long TxBytes
        {
            get => _txBytes;
            set { _txBytes = value; OnPropertyChanged(); OnPropertyChanged(nameof(TxBytesDisplay)); OnPropertyChanged(nameof(IsHighTransmitter)); OnPropertyChanged(nameof(IsTxOnly)); }
        }

        /// <summary>
        /// Transmit threshold shared by every row: above it a row counts as a
        /// high transmitter (pinned to the top of the grid, tinted). User-
        /// changeable from the monitor toolbar; default 1 KB.
        /// </summary>
        public static long TxThresholdBytes = 1024;

        /// <summary>True while this row's transmit volume is at or above the high-transmitter threshold.</summary>
        public bool IsHighTransmitter => TxBytes >= TxThresholdBytes;

        /// <summary>
        /// Row creation time (UTC) — the clock the TX-only grace period runs
        /// on. Deliberately not the process start: counters belong to the
        /// remote-IP row, which can outlive and re-attribute processes.
        /// </summary>
        public DateTime FirstSeenUtc { get; } = DateTime.UtcNow;

        /// <summary>
        /// Grace period a row must age through before it can count as a
        /// one-way transmitter. Rows are seeded at 0/0 and Rx only arrives
        /// when a reply packet crosses the sniffer, so every new row is
        /// briefly "TX, no RX" mid-handshake; the gate keeps those from
        /// flashing in the TX-only view.
        /// </summary>
        public static int TxOnlyGraceSeconds = 30;

        /// <summary>
        /// True while the row has transmitted but never received anything
        /// back — the one-way-transmitter pattern (firewall-blocked
        /// outbound, dead-end beacons). Time-gated by the grace period, so
        /// it must be re-raised periodically (RefreshLastSeenDisplay), not
        /// only when a counter moves.
        /// </summary>
        public bool IsTxOnly =>
            TxBytes > 0 && RxBytes == 0 &&
            (DateTime.UtcNow - FirstSeenUtc).TotalSeconds >= TxOnlyGraceSeconds;

        public string RxBytesDisplay => FormatBytes(RxBytes);
        public string TxBytesDisplay => FormatBytes(TxBytes);

        // -------------------------------------------------------------------
        // Firewall-block state — stamped by the view from the firewall's live
        // inventory (the rules are the source of truth, so agent- and
        // wf.msc-created blocks mark rows just like monitor-created ones).
        // Two independent dimensions: the remote IP and the process exe.
        // -------------------------------------------------------------------

        private BlockRuleState _ipBlock = BlockRuleState.None;
        private BlockRuleState _appBlock = BlockRuleState.None;
        private string _ipBlockNote;     // rule Description (provenance), for tooltips
        private string _appBlockNote;

        public BlockRuleState IpBlockState => _ipBlock;
        public BlockRuleState ProcessBlockState => _appBlock;

        /// <summary>IP cell marker: red + strikethrough when an enabled block rule matches.</summary>
        public bool IsIpBlocked => _ipBlock == BlockRuleState.Active;

        /// <summary>Process cell marker: red + strikethrough when an enabled app rule matches.</summary>
        public bool IsProcessBlocked => _appBlock == BlockRuleState.Active;

        /// <summary>True when either dimension blocks this row's traffic.</summary>
        public bool IsTrafficBlocked => IsIpBlocked || IsProcessBlocked;

        /// <summary>True when block rules exist but are all disabled (fleet pause) — traffic flows.</summary>
        public bool HasPausedBlock => !IsTrafficBlocked &&
            (_ipBlock == BlockRuleState.Paused || _appBlock == BlockRuleState.Paused);

        /// <summary>Status-column glyph: ⛔ blocked · ⏸ paused · empty = allowed.</summary>
        public string StatusGlyph => IsTrafficBlocked ? "⛔" : HasPausedBlock ? "⏸" : "";

        /// <summary>Provenance of the IP block rule (null when the IP is not blocked).</summary>
        public string IpBlockToolTip =>
            _ipBlock == BlockRuleState.None ? null :
            (_ipBlock == BlockRuleState.Active
                ? "⛔ Remote IP is blocked — outbound TCP/UDP rules active"
                : "⏸ Block rules for this IP exist but are disabled (traffic flows) — re-enable from 'Blocked' → Manage all")
            + (string.IsNullOrEmpty(_ipBlockNote) ? "" : $"\n{_ipBlockNote}")
            + "\nUndo: right-click the row → Unblock, or 'Blocked' → Manage all.";

        /// <summary>Provenance of the app block rule (null when the process is not blocked).</summary>
        public string ProcessBlockToolTip =>
            _appBlock == BlockRuleState.None ? null :
            (_appBlock == BlockRuleState.Active
                ? "⛔ This executable is blocked — outbound rule active"
                : "⏸ A block rule for this executable exists but is disabled (traffic flows) — re-enable from 'Blocked' → Manage all")
            + (string.IsNullOrEmpty(_appBlockNote) ? "" : $"\n{_appBlockNote}")
            + "\nUndo: right-click the row → Unblock, or 'Blocked' → Manage all.";

        /// <summary>Status-column tooltip: whichever dimension is blocked, with provenance.</summary>
        public string StatusToolTip
        {
            get
            {
                if (!IsTrafficBlocked && !HasPausedBlock) return null;
                var sb = new StringBuilder();
                if (_ipBlock != BlockRuleState.None && IpBlockToolTip is string ip) sb.AppendLine(ip.TrimEnd());
                if (_appBlock != BlockRuleState.None && ProcessBlockToolTip is string app) sb.AppendLine(app.TrimEnd());
                return sb.Length == 0 ? null : sb.ToString();
            }
        }

        /// <summary>Stamped by the view's blocked-state sync (see RefreshBlockStateFromFirewallAsync).</summary>
        public void SetBlockState(BlockRuleState ip, string ipNote, BlockRuleState app, string appNote)
        {
            _ipBlock = ip;
            _appBlock = app;
            _ipBlockNote = ipNote;
            _appBlockNote = appNote;
            OnPropertyChanged(nameof(IpBlockState));
            OnPropertyChanged(nameof(ProcessBlockState));
            OnPropertyChanged(nameof(IsIpBlocked));
            OnPropertyChanged(nameof(IsProcessBlocked));
            OnPropertyChanged(nameof(IsTrafficBlocked));
            OnPropertyChanged(nameof(HasPausedBlock));
            OnPropertyChanged(nameof(StatusGlyph));
            OnPropertyChanged(nameof(IpBlockToolTip));
            OnPropertyChanged(nameof(ProcessBlockToolTip));
            OnPropertyChanged(nameof(StatusToolTip));
        }

        /// <summary>
        /// Scheduled task that launched this taskhostw instance (attribution from
        /// TaskSchedulerService), or null when the row is not a task host.
        /// </summary>
        public string TaskName
        {
            get => _taskName;
            private set { _taskName = value; OnPropertyChanged(); OnPropertyChanged(nameof(ProcessToolTip)); }
        }

        /// <summary>Account the scheduled task ran as, when known.</summary>
        public string TaskUser
        {
            get => _taskUser;
            private set { _taskUser = value; OnPropertyChanged(); OnPropertyChanged(nameof(ProcessToolTip)); }
        }

        /// <summary>Called by the view when TaskSchedulerService resolves the task behind a taskhostw row.</summary>
        public void SetTaskInfo(string taskName, string taskUser)
        {
            if (TaskName != null) return;
            TaskName = taskName;
            TaskUser = taskUser;
        }

        /// <summary>True when the Process tooltip has any content to show.</summary>
        public bool HasToolTip =>
            !string.IsNullOrEmpty(ImagePath) || TaskName != null || (IsSvchost && _identityResolved) ||
            !string.IsNullOrEmpty(_parentImage) || _nameRevealedFrom != null;

        /// <summary>
        /// Tooltip for the Process column: image path, spawn parent and
        /// plain-English gloss (the "it was Git all along" context),
        /// scheduled-task attribution, and — for resolved svchost rows —
        /// the full service identity (SCM ground truth, -k group, -s claim,
        /// corroboration).
        /// </summary>
        public string ProcessToolTip
        {
            get
            {
                var sb = new StringBuilder();
                if (!string.IsNullOrEmpty(ImagePath)) sb.AppendLine(ImagePath);
                if (!string.IsNullOrEmpty(_parentImage) && !SameProcessName(_parentImage, ProcessName))
                    sb.AppendLine("spawned by " + System.IO.Path.GetFileName(_parentImage));
                if (AutoScope.Services.ProcessGlossary.TryDescribe(
                        !string.IsNullOrEmpty(ImagePath) ? ImagePath : ProcessName, out string gloss))
                    sb.AppendLine("ℹ " + gloss);
                if (_nameRevealedFrom != null)
                    sb.AppendLine($"🏷 real name revealed from the Sysmon record (row previously showed '{_nameRevealedFrom}')");
                if (TaskName != null)
                {
                    sb.Append("Task: ").Append(TaskName);
                    if (!string.IsNullOrEmpty(TaskUser)) sb.Append("   (as ").Append(TaskUser).Append(')');
                    sb.AppendLine();
                }
                if (IsSvchost && _identityResolved)
                {
                    sb.AppendLine("svchost identity:");
                    if (!string.IsNullOrEmpty(_servicesDetail)) sb.AppendLine(_servicesDetail);
                    sb.Append("group (-k): ").Append(string.IsNullOrEmpty(_svchostGroup) ? "—" : _svchostGroup)
                      .Append(" · self-declared (-s): ").Append(string.IsNullOrEmpty(_declaredService) ? "—" : _declaredService);
                    if (_identitySuspicious)
                        sb.AppendLine("   ⚠ identity signal — see below");
                    else
                        sb.AppendLine();
                    if (string.IsNullOrEmpty(_hostedServices))
                        sb.Append("⚠ no service resolves to this PID — the strongest single masquerade red flag");
                    else if (_identitySuspicious)
                        sb.Append("⚠ command line contradicts the SCM-resident services — masquerade signal (audit-svchost.ps1)");
                    else if (_cmdLineHidden)
                        sb.Append("command line hidden (standard user cannot read SYSTEM svchost lines) — rerun elevated to corroborate -k/-s");
                    else
                        sb.Append("command line corroborates the SCM ✓");
                }
                var text = sb.ToString();
                return text.Length == 0 ? null : text;
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;

        /// <summary>
        /// Called by the UI refresh timer to re-evaluate the relative "Xs ago"
        /// text, the staleness flag, and the time-gated TX-only flag without
        /// needing to mutate LastSeen itself.
        /// </summary>
        public void RefreshLastSeenDisplay()
        {
            OnPropertyChanged(nameof(LastSeenDisplay));
            OnPropertyChanged(nameof(IsStale));
            OnPropertyChanged(nameof(IsTxOnly));
        }

        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1048576) return $"{(bytes / 1024.0):F1} KB";
            return $"{(bytes / 1048576.0):F1} MB";
        }
    }
}
