using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;

namespace AutoScope.Models
{
    /// <summary>
    /// One python process creation, as recorded by Sysmon EID 1 (with full
    /// parentage) and closed out by EID 5 (Exited). Pairs of spawns coming
    /// from a venv launcher collapse into a single row: the real interpreter
    /// carries the record and the launcher is shown in the detail pane.
    /// Display-only properties are excluded from JSONL export/copy.
    /// </summary>
    public class SpawnItem : INotifyPropertyChanged
    {
        private bool _exited;
        private int _flowCount;
        private bool _hasTrace;
        private string _outcome;
        private string _verdict;

        public DateTime TimeUtc { get; set; }
        public int Pid { get; set; }
        /// <summary>
        /// Sysmon's ProcessGuid (braces stripped) — kernel-assigned and unique
        /// for the whole boot. Unlike the PID, it can never be recycled onto
        /// another process, so it is the safest key for later attribution.
        /// </summary>
        public string ProcessGuid { get; set; }
        public string Image { get; set; }
        public string CommandLine { get; set; }
        public int ParentPid { get; set; }
        public string ParentImage { get; set; }
        public string ParentCommandLine { get; set; }
        public string User { get; set; }
        public string IntegrityLevel { get; set; }
        public string Hashes { get; set; }
        public string Source { get; set; }

        /// <summary>
        /// The venv launcher row this spawn was paired with (python child of a
        /// python parent with a different image and a \Scripts\ launcher path).
        /// Null when the spawn has no launcher in front of it.
        /// </summary>
        [JsonIgnore]
        public SpawnItem VenvLauncher { get; private set; }

        /// <summary>True when this row was absorbed into a child row as the venv launcher.</summary>
        public bool IsAbsorbedLauncher { get; private set; }

        /// <summary>True when the parent is itself a tracked python spawn (but not a venv launcher).</summary>
        public bool HasPythonParent { get; private set; }

        /// <summary>Set by the watcher when another python launch absorbed this row as its launcher.</summary>
        public void MarkAbsorbedLauncher() { IsAbsorbedLauncher = true; OnPropertyChanged(nameof(Badge)); }

        public void SetVenvLauncher(SpawnItem launcher)
        {
            VenvLauncher = launcher;
            OnPropertyChanged(nameof(Badge));
        }

        public void SetPythonParent()
        {
            HasPythonParent = true;
            OnPropertyChanged(nameof(Badge));
        }

        /// <summary>Grid badge: "venv" for a paired interpreter, "py→py" for python-spawned-python.</summary>
        private string _detailBadge;

        /// <summary>
        /// View-set badge (e.g. the scheduled-task name on a taskhostw row);
        /// the python-specific badges take precedence when present.
        /// </summary>
        public void SetDetailBadge(string badge)
        {
            _detailBadge = badge;
            OnPropertyChanged(nameof(Badge));
        }

        public string Badge
        {
            get
            {
                if (VenvLauncher != null) return "venv";
                if (HasPythonParent) return "py→py";
                return _detailBadge ?? string.Empty;
            }
        }

        /// <summary>View-set outcome ("rc 0 · 0.4 s") once the scheduler reported the action's result.</summary>
        public void SetOutcome(string outcome) { _outcome = outcome; OnPropertyChanged(nameof(OutcomeDisplay)); }

        /// <summary>View-set verdict from TaskLaunchInfo — Inbox / Third-party / Orphaned.</summary>
        public void SetVerdict(string verdict)
        {
            _verdict = verdict;
            OnPropertyChanged(nameof(Verdict));
            OnPropertyChanged(nameof(VerdictVisibility));
            OnPropertyChanged(nameof(VerdictBackground));
            OnPropertyChanged(nameof(VerdictForeground));
        }

        /// <summary>Lifecycle flag — flipped by the EID 5 (process terminate) watcher.</summary>
        public bool Exited
        {
            get => _exited;
            set { _exited = value; OnPropertyChanged(); OnPropertyChanged(nameof(LifeDisplay)); }
        }

        /// <summary>Number of TCP flows correlated to this pid at connect time.</summary>
        public int FlowCount
        {
            get => _flowCount;
            set { _flowCount = value; OnPropertyChanged(); }
        }

        /// <summary>True once a trace record from the audit hook matched this pid.</summary>
        public bool HasTrace
        {
            get => _hasTrace;
            set { _hasTrace = value; OnPropertyChanged(); }
        }

        [JsonIgnore]
        public string TimeDisplay => TimeUtc == default ? "—" : TimeUtc.ToLocalTime().ToString("HH:mm:ss");

        [JsonIgnore]
        public string ImageDisplay => string.IsNullOrEmpty(Image) ? "—" : System.IO.Path.GetFileName(Image);

        [JsonIgnore]
        public string LifeDisplay => Exited ? "exited" : "running";

        /// <summary>Outcome column: return code + duration once the scheduler reported a result, else lifecycle.</summary>
        [JsonIgnore]
        public string OutcomeDisplay => _outcome ?? (Exited ? "exited" : "running");

        [JsonIgnore]
        public string Verdict => _verdict;

        [JsonIgnore]
        public Microsoft.UI.Xaml.Visibility VerdictVisibility =>
            string.IsNullOrEmpty(_verdict) ? Microsoft.UI.Xaml.Visibility.Collapsed : Microsoft.UI.Xaml.Visibility.Visible;

        /// <summary>Chip background per verdict (color string; the XAML converter turns it into a brush).</summary>
        [JsonIgnore]
        public string VerdictBackground => _verdict switch
        {
            "Inbox" => "#2E5E3E",
            "Third-party" => "#6B4E1A",
            "Orphaned" => "#6E2A2A",
            _ => "#2A2A33"
        };

        /// <summary>Chip text per verdict, matched to its background so the
        /// three states read apart at a glance: Inbox calm green, Third-party
        /// amber, Orphaned alert red.</summary>
        [JsonIgnore]
        public string VerdictForeground => _verdict switch
        {
            "Inbox" => "#7ED8A0",
            "Orphaned" => "#F2A0B4",
            _ => "#E5C77B"
        };

        /// <summary>"PID (name)" for the parent column; "—" when Sysmon gave no parent image.</summary>
        [JsonIgnore]
        public string ParentDisplay
        {
            get
            {
                if (string.IsNullOrEmpty(ParentImage)) return ParentPid > 0 ? ParentPid.ToString() : "—";
                return $"{ParentPid} ({System.IO.Path.GetFileName(ParentImage)})";
            }
        }

        /// <summary>Full parent image + command line for the column tooltip.</summary>
        [JsonIgnore]
        public string ParentToolTip
        {
            get
            {
                if (string.IsNullOrEmpty(ParentImage) && string.IsNullOrEmpty(ParentCommandLine)) return null;
                return $"{ParentImage ?? "?"}{Environment.NewLine}{ParentCommandLine ?? ""}";
            }
        }

        /// <summary>Chip background for the badge column (venv pairs get the accent blue).</summary>
        [JsonIgnore]
        public string BadgeBackground => VenvLauncher != null ? "#1A4A8A" : "#2A2A33";

        /// <summary>Collapses the badge cell when there is nothing to badge.</summary>
        [JsonIgnore]
        public Microsoft.UI.Xaml.Visibility BadgeVisibility =>
            string.IsNullOrEmpty(Badge) ? Microsoft.UI.Xaml.Visibility.Collapsed : Microsoft.UI.Xaml.Visibility.Visible;

        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }
}
