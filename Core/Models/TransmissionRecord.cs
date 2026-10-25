using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace AutoScope.Models
{
    /// <summary>
    /// One finalized outbound TLS conversation as the Transmissions tab sees
    /// it: the decrypted view when session keys existed, the honest status
    /// ("encrypted — no keys", "not TLS") when they did not. The wire facts
    /// (endpoints, sizes, pid via Sysmon EID 3) are always present; the
    /// content lives in the archive's body files, referenced by Id.
    /// </summary>
    public class TransmissionRecord : INotifyPropertyChanged
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public DateTime TsUtc { get; set; }

        public int Pid { get; set; }
        public string Image { get; set; }
        public string ProcessDisplay => string.IsNullOrEmpty(Image)
            ? (Pid > 0 ? $"pid {Pid}" : "unattributed")
            : System.IO.Path.GetFileName(Image);

        public string RemoteIp { get; set; }
        public int RemotePort { get; set; }
        public string ServerEndpoint => $"{RemoteIp}:{RemotePort}";
        public string LocalEndpoint { get; set; }

        public string Sni { get; set; }
        public string HostDisplay => string.IsNullOrEmpty(Sni) ? "(no SNI)" : Sni;

        public string TlsVersion { get; set; }
        public string Alpn { get; set; }
        public string CipherSuite { get; set; }

        /// <summary>RDAP netname/org when known, else the static range
        /// classification, else "Unclassified". Late-bound: RDAP answers
        /// asynchronously and the grid row updates in place.</summary>
        public string Provider
        {
            get => _provider;
            set { if (SetField(ref _provider, value)) OnPropertyChanged(nameof(ProviderAndCountry)); }
        }
        private string _provider = "Unclassified";
        public string ProviderCountry { get; set; }
        public string ProviderAndCountry => string.IsNullOrEmpty(ProviderCountry)
            ? Provider
            : $"{Provider} ({ProviderCountry})";

        public long ClientBytes { get; set; }       // wire, reassembled
        public long ServerBytes { get; set; }
        public long ClientAppBytes { get; set; }    // decrypted plaintext
        public long ServerAppBytes { get; set; }

        /// <summary>"decrypted" · "encrypted (no keys)" · "not TLS" ·
        /// "no handshake" · "unsupported cipher" · "undecryptable", with an
        /// optional " · truncated" suffix when the capture dropped bytes.
        /// Intercept-sourced rows use "decrypted · intercept …" variants.</summary>
        public string Status { get; set; }
        public bool Decrypted => Status != null &&
                                 (Status == "decrypted" || Status.StartsWith("decrypted", StringComparison.Ordinal));

        /// <summary>The user-facing threshold this tab exists for: an upload
        /// larger than 10 KB deserves a row even when no keys existed.</summary>
        public bool BigUpload => ClientBytes > 10 * 1024;
        public string BigUploadVisibility => BigUpload ? "Visible" : "Collapsed";

        public bool HasContent { get; set; }
        public string Sha256 { get; set; }
        public int MessageCount { get; set; }
        public string ContentKinds { get; set; }

        public string ArchiveDay { get; set; }

        // ── display helpers ──────────────────────────────────────────────

        public string TimeDisplay => TsUtc == default ? "" : TsUtc.ToLocalTime().ToString("MM-dd HH:mm:ss");
        public string UpDisplay => FormatBytes(ClientBytes);
        public string DownDisplay => FormatBytes(ServerBytes);
        public string AppBytesDisplay => Decrypted
            ? $"{FormatBytes(ClientAppBytes)} / {FormatBytes(ServerAppBytes)}"
            : "—";

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes}B";
            if (bytes < 1048576) return $"{bytes / 1024.0:F1}KB";
            return $"{bytes / 1048576.0:F1}MB";
        }

        public event PropertyChangedEventHandler PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        private bool SetField<T>(ref T field, T value, [CallerMemberName] string name = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value)) return false;
            field = value;
            OnPropertyChanged(name);
            return true;
        }
    }
}
