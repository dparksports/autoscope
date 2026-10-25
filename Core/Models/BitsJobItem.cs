using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;

namespace AutoScope.Models
{
    /// <summary>One file inside a BITS job, merged from the COM file
    /// enumeration (remote + local names) and the completion-time
    /// inspection (size + SHA-256). Content is never read here —
    /// previewing is the explicit user action in BitsView.</summary>
    public class BitsFileRef
    {
        public string RemoteName { get; set; }
        public string LocalName { get; set; }
        public long? LocalSize { get; set; }
        public string Sha256 { get; set; }
        /// <summary>hashed / gone / access-denied / pending</summary>
        public string HashStatus { get; set; } = "pending";

        [JsonIgnore]
        public string RemoteDisplay => RemoteName ?? "—";
        [JsonIgnore]
        public string LocalDisplay => string.IsNullOrEmpty(LocalName) ? "(local path unknown — job predates tracing)" : LocalName;
        [JsonIgnore]
        public string SizeDisplay => LocalSize is long n ? BitsJobItem.FormatBytes(n) : "—";
        [JsonIgnore]
        public string HashDisplay => string.IsNullOrEmpty(Sha256) ? (HashStatus ?? "—") : Sha256;
    }

    /// <summary>One raw BITS event-log record attached to a job's timeline.</summary>
    public class BitsEventRecord
    {
        public DateTime TimeUtc { get; set; }
        public int EventId { get; set; }
        public string Text { get; set; }

        [JsonIgnore]
        public string Display => $"{TimeUtc.ToLocalTime():HH:mm:ss}  #{EventId}  {Text}";
    }

    /// <summary>
    /// One Background Intelligent Transfer Service job, stitched from the
    /// Bits-Client operational event log (EID 3 created / 59 transfer
    /// started / 60 transfer stopped / 4 complete) and enriched live from
    /// the BITS COM queue (direction, state, progress, per-file names).
    /// Display-only properties are excluded from JSONL export/copy;
    /// exports carry metadata only — never file content.
    /// </summary>
    public class BitsJobItem : INotifyPropertyChanged
    {
        private string _url;
        private string _host;
        private int _port;
        private string _resolvedIps;
        private string _org;
        private string _state;
        private string _direction;
        private ulong _bytesTotal;
        private ulong _bytesTransferred;
        private string _statusText;
        private string _reasonText;
        private string _verdict;
        private string _creatorSigner;
        private DateTime _lastSeenUtc;

        /// <summary>Job GUID as lowercase braceless string — the stitch key across event log and COM.</summary>
        public string JobId { get; set; }
        public string Name { get; set; }
        public string OwnerAccount { get; set; }
        public string CreatorImage { get; set; }
        public int CreatorPid { get; set; }
        public DateTime FirstSeenUtc { get; set; }
        public List<BitsFileRef> Files { get; } = new();
        public List<BitsEventRecord> Timeline { get; } = new();

        // ----- enrichment-set fields (raise change notifications) -----

        public string Url { get => _url; set { _url = value; OnPropertyChanged(); OnPropertyChanged(nameof(UrlPathDisplay)); } }
        public string Host { get => _host; set { _host = value; OnPropertyChanged(); } }
        public int Port { get => _port; set { _port = value; OnPropertyChanged(); } }
        public string ResolvedIps { get => _resolvedIps; set { _resolvedIps = value; OnPropertyChanged(); } }
        public string Org { get => _org; set { _org = value; OnPropertyChanged(); } }
        public string State { get => _state; set { _state = value; OnPropertyChanged(); } }
        public string Direction { get => _direction; set { _direction = value; OnPropertyChanged(); OnPropertyChanged(nameof(DirectionBackground)); OnPropertyChanged(nameof(IsUpload)); } }
        public ulong BytesTotal { get => _bytesTotal; set { _bytesTotal = value; OnPropertyChanged(); OnPropertyChanged(nameof(BytesDisplay)); } }
        public ulong BytesTransferred { get => _bytesTransferred; set { _bytesTransferred = value; OnPropertyChanged(); OnPropertyChanged(nameof(BytesDisplay)); } }
        public string StatusText { get => _statusText; set { _statusText = value; OnPropertyChanged(); } }
        public string ReasonText { get => _reasonText; set { _reasonText = value; OnPropertyChanged(); } }
        public string Verdict { get => _verdict; set { _verdict = value; OnPropertyChanged(); OnPropertyChanged(nameof(VerdictBackground)); } }
        public string CreatorSigner { get => _creatorSigner; set { _creatorSigner = value; OnPropertyChanged(); OnPropertyChanged(nameof(CreatorDisplay)); } }
        public DateTime LastSeenUtc { get => _lastSeenUtc; set { _lastSeenUtc = value; OnPropertyChanged(); OnPropertyChanged(nameof(LastSeenDisplay)); } }

        /// <summary>Raised whenever a file is added or its hash lands, so bound lists refresh.</summary>
        public void NotifyFilesChanged()
        {
            OnPropertyChanged(nameof(Files));
            OnPropertyChanged(nameof(FileCountDisplay));
        }

        // ----- computed display properties -----

        [JsonIgnore]
        public string TimeDisplay => FirstSeenUtc == default ? "—" : FirstSeenUtc.ToLocalTime().ToString("MM-dd HH:mm:ss");

        [JsonIgnore]
        public string LastSeenDisplay => LastSeenUtc == default ? "—" : LastSeenUtc.ToLocalTime().ToString("MM-dd HH:mm:ss");

        [JsonIgnore]
        public string CreatorDisplay
        {
            get
            {
                if (string.IsNullOrEmpty(CreatorImage)) return CreatorPid > 0 ? $"PID {CreatorPid}" : "—";
                string exe = Path.GetFileName(CreatorImage);
                return CreatorPid > 0 ? $"{exe} ({CreatorPid})" : exe;
            }
        }

        [JsonIgnore]
        public string UrlPathDisplay
        {
            get
            {
                if (string.IsNullOrEmpty(Url)) return "—";
                if (Uri.TryCreate(Url, UriKind.Absolute, out var u))
                {
                    string path = u.AbsolutePath == "/" ? "" : u.AbsolutePath;
                    return path.Length > 60 ? path[..60] + "…" : (path.Length == 0 ? u.Host : path);
                }
                return Url.Length > 60 ? Url[..60] + "…" : Url;
            }
        }

        [JsonIgnore]
        public string BytesDisplay
        {
            get
            {
                if (BytesTotal == 0 && BytesTransferred == 0) return "—";
                return BytesTotal > 0
                    ? $"{FormatBytes(BytesTransferred)} / {FormatBytes(BytesTotal)}"
                    : FormatBytes(BytesTransferred);
            }
        }

        [JsonIgnore]
        public string FileCountDisplay => Files.Count == 0 ? "—" : Files.Count.ToString();

        [JsonIgnore]
        public bool IsUpload => Direction == "Upload" || Direction == "Upload-reply";

        /// <summary>Chip background per direction; uploads get the danger red.</summary>
        [JsonIgnore]
        public string DirectionBackground => Direction switch
        {
            "Download" => "#1A4A8A",
            "Upload" => "#6E2A2A",
            "Upload-reply" => "#6E2A2A",
            _ => "#2A2A33"
        };

        [JsonIgnore]
        public string VerdictBackground => Verdict switch
        {
            "Normal" => "#2E5E3E",
            "Review" => "#6E2A2A",
            _ => "#2A2A33"
        };

        [JsonIgnore]
        public string HostDisplay => string.IsNullOrEmpty(Host) ? "—" : Host;

        [JsonIgnore]
        public string OrgDisplay => string.IsNullOrEmpty(Org) ? "…" : Org;

        /// <summary>Human byte formatting (same shape as SvchostMonitorItem.FormatBytes).</summary>
        public static string FormatBytes(double bytes)
        {
            string[] units = { "B", "KB", "MB", "GB", "TB" };
            int u = 0;
            while (bytes >= 1024 && u < units.Length - 1) { bytes /= 1024; u++; }
            return $"{bytes:0.#} {units[u]}";
        }

        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }
}
