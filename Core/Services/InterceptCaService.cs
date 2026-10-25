using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AutoScope.Services
{
    /// <summary>
    /// The intercept CA and its leaf minting. Layer 3's dangerous part,
    /// caged: one RSA-2048 CA per install ("CN=AutoScope Intercept CA"),
    /// persisted under %LOCALAPPDATA%\AutoScope\intercept so sessions
    /// reuse it, installed into the MACHINE Root store only while an
    /// intercept session runs and removed when it ends. Leaf certificates
    /// are minted per hostname, cached briefly — a session never generates
    /// hundreds of keys.
    ///
    /// Nothing here ever touches LSASS or Schannel internals: the CA is the
    /// standard, user-visible mechanism, auditable in certmgr as "AutoScope
    /// Intercept CA" whenever it is trusted.
    /// </summary>
    internal static class InterceptCaService
    {
        private const string CaSubject = "CN=AutoScope Intercept CA,O=AutoScope";

        internal static string Dir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoScope", "intercept");

        private static string CaPath => Path.Combine(Dir, "ca.pfx");

        private static readonly object Gate = new();
        private static X509Certificate2 _ca;
        private static readonly Dictionary<string, (X509Certificate2 Cert, DateTime MintedUtc)> _leafCache =
            new(StringComparer.OrdinalIgnoreCase);

        /// <summary>The CA, creating and persisting it on first use.</summary>
        internal static X509Certificate2 GetOrCreateCa()
        {
            lock (Gate)
            {
                if (_ca != null) return _ca;
                try
                {
                    if (File.Exists(CaPath))
                        _ca = new X509Certificate2(CaPath);
                }
                catch { /* unreadable pfx — regenerate below */ }

                if (_ca == null || !_ca.HasPrivateKey || DateTime.UtcNow > _ca.NotAfter.AddDays(-30))
                {
                    using var rsa = RSA.Create(2048);
                    var request = new CertificateRequest(CaSubject, rsa,
                        HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
                        certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));
                    request.CertificateExtensions.Add(new X509KeyUsageExtension(
                        X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
                    request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(
                        request.PublicKey, false));
                    _ca = request.CreateSelfSigned(DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(2));

                    Directory.CreateDirectory(Dir);
                    File.WriteAllBytes(CaPath, _ca.Export(X509ContentType.Pfx));
                }
                return _ca;
            }
        }

        // ── Root store lifecycle ──────────────────────────────────────────

        /// <summary>Trusts the CA machine-wide for the session's duration.
        /// Requires elevation (the app's manifest guarantees it).</summary>
        internal static void InstallToRoot()
        {
            var ca = GetOrCreateCa();
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            var existing = store.Certificates.Find(X509FindType.FindByThumbprint, ca.Thumbprint, validOnly: false);
            if (existing.Count == 0) store.Add(ca);
        }

        /// <summary>Removes exactly our CA (by thumbprint) — never a blanket
        /// store cleanup.</summary>
        internal static void RemoveFromRoot(string thumbprint = null)
        {
            string tp = thumbprint ?? GetOrCreateCa().Thumbprint;
            try
            {
                using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                foreach (var cert in store.Certificates.Find(
                             X509FindType.FindByThumbprint, tp, validOnly: false))
                    store.Remove(cert);
            }
            catch { /* best-effort removal; RecoverAfterCrash retries at next app start */ }
        }

        // ── leaf minting ──────────────────────────────────────────────────

        /// <summary>
        /// A server certificate for one hostname (or IP), signed by the CA.
        /// Cached per hostname per 10 minutes — reused connections and
        /// reconnects do not re-mint.
        /// </summary>
        internal static X509Certificate2 GetOrMintLeaf(string host)
        {
            lock (Gate)
            {
                if (_leafCache.TryGetValue(host, out var cached) &&
                    DateTime.UtcNow - cached.MintedUtc < TimeSpan.FromMinutes(10))
                    return cached.Cert;

                var ca = GetOrCreateCa();
                using var rsa = RSA.Create(2048);
                var request = new CertificateRequest($"CN={host}", rsa,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, critical: false)); // serverAuth
                request.CertificateExtensions.Add(new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: false));

                bool isIp = IPAddress.TryParse(host, out var ip);
                var sanBuilder = new SubjectAlternativeNameBuilder();
                if (isIp) sanBuilder.AddIpAddress(ip);
                else sanBuilder.AddDnsName(host);
                request.CertificateExtensions.Add(sanBuilder.Build());

                var leaf = request.Create(ca, DateTime.UtcNow.AddMinutes(-5),
                    DateTime.UtcNow.AddDays(7), ca.GetSerialNumber());
                // CopyWithPrivateKey returns the cert WITH its private key —
                // the chain to the CA is built by clients via the Root store.
                var leafWithKey = leaf.CopyWithPrivateKey(rsa);

                _leafCache[host] = (leafWithKey, DateTime.UtcNow);
                return leafWithKey;
            }
        }
    }
}
