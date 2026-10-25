using System.Collections.Generic;

namespace AutoScope.Models
{
    /// <summary>Outcome of decrypting one captured TLS flow.</summary>
    public class TlsDecryptResult
    {
        /// <summary>True when at least one application-data record decrypted.</summary>
        public bool Success { get; set; }

        /// <summary>Human-readable status: the reason when not successful.</summary>
        public string Status { get; set; }

        public string TlsVersion { get; set; }
        public string Sni { get; set; }
        public string Alpn { get; set; }
        public string CipherSuite { get; set; }
        public bool Truncated { get; set; }

        public long ClientAppBytes { get; set; }
        public long ServerAppBytes { get; set; }

        public List<TlsPlainRecord> Records { get; } = new();

        /// <summary>First HTTP/1.x messages parsed from the plaintext, when parseable.</summary>
        public string HttpSummary { get; set; }

        public string HeaderLine =>
            $"{TlsVersion ?? "?"} · {Sni ?? "(no SNI)"}" +
            (!string.IsNullOrEmpty(Alpn) ? $" · ALPN {Alpn}" : "") +
            (CipherSuite != null ? $" · {CipherSuite}" : "");
    }

    /// <summary>One TLS record after decryption, with plaintext when it decrypted.</summary>
    public class TlsPlainRecord
    {
        public bool FromClient { get; set; }
        public string ContentType { get; set; }
        public bool Decrypted { get; set; }
        public string Note { get; set; }
        public byte[] Data { get; set; }
        public long Length => Data?.Length ?? 0;
    }
}
