using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using AutoScope.Models;

namespace AutoScope.Services
{
    /// <summary>
    /// Decrypts a captured TLS flow in-tab, using the SSLKEYLOGFILE secrets
    /// that instrumented python processes wrote (via TlsKeylogService) plus
    /// the full reassembled TCP streams from TcpStreamCaptureService.
    ///
    /// Everything uses in-box .NET crypto (AesGcm, ChaCha20Poly1305, HMAC);
    /// no BouncyCastle dependency. Integrity is enforced by the AEAD tags:
    /// a wrong or missing secret fails the tag and the record is reported
    /// undecryptable — never a partial guess. Finished-message verification
    /// (transcript hash) is intentionally not attempted: it needs a global
    /// wire-order merge of both directions that SIO_RCVALL timestamps cannot
    /// provide, and the AEAD tag is an equivalent integrity oracle.
    ///
    /// Best-effort with explicit flags: TLS 1.3 KeyUpdate re-derives the next
    /// traffic secret per RFC 8446; if later records still fail they are
    /// flagged, not guessed.
    /// </summary>
    public static class TlsDecryptor
    {
        // -----------------------------------------------------------------------
        // Cipher suites
        // -----------------------------------------------------------------------

        private sealed class SuiteInfo
        {
            public ushort Id;
            public string Name;
            public int KeyLen;       // per-direction write key
            public int FixedIvLen;   // TLS 1.2 key-block fixed IV; TLS 1.3 static IV
            public int MacLen;       // TLS 1.2 CBC MAC length (0 for AEAD)
            public string Aead;      // "gcm" | "chacha" | "cbc" | "t13gcm" | "t13chacha"
            public HashAlgorithmName Hash;
        }

        private static readonly Dictionary<ushort, SuiteInfo> Suites = CreateSuites();

        private static Dictionary<ushort, SuiteInfo> CreateSuites()
        {
            var list = new List<SuiteInfo>
            {
                // TLS 1.3
                new() { Id = 0x1301, Name = "TLS_AES_128_GCM_SHA256",        KeyLen = 16, FixedIvLen = 12, MacLen = 0, Aead = "t13gcm",    Hash = HashAlgorithmName.SHA256 },
                new() { Id = 0x1302, Name = "TLS_AES_256_GCM_SHA384",        KeyLen = 32, FixedIvLen = 12, MacLen = 0, Aead = "t13gcm",    Hash = HashAlgorithmName.SHA384 },
                new() { Id = 0x1303, Name = "TLS_CHACHA20_POLY1305_SHA256",  KeyLen = 32, FixedIvLen = 12, MacLen = 0, Aead = "t13chacha", Hash = HashAlgorithmName.SHA256 },
                // TLS 1.2 AEAD
                new() { Id = 0xC02F, Name = "ECDHE_RSA_AES_128_GCM_SHA256",   KeyLen = 16, FixedIvLen = 4,  MacLen = 0, Aead = "gcm",     Hash = HashAlgorithmName.SHA256 },
                new() { Id = 0xC030, Name = "ECDHE_RSA_AES_256_GCM_SHA384",   KeyLen = 32, FixedIvLen = 4,  MacLen = 0, Aead = "gcm",     Hash = HashAlgorithmName.SHA384 },
                new() { Id = 0xC02B, Name = "ECDHE_ECDSA_AES_128_GCM_SHA256", KeyLen = 16, FixedIvLen = 4,  MacLen = 0, Aead = "gcm",     Hash = HashAlgorithmName.SHA256 },
                new() { Id = 0xC02C, Name = "ECDHE_ECDSA_AES_256_GCM_SHA384", KeyLen = 32, FixedIvLen = 4,  MacLen = 0, Aead = "gcm",     Hash = HashAlgorithmName.SHA384 },
                new() { Id = 0x9C,   Name = "RSA_AES_128_GCM_SHA256",         KeyLen = 16, FixedIvLen = 4,  MacLen = 0, Aead = "gcm",     Hash = HashAlgorithmName.SHA256 },
                new() { Id = 0x9D,   Name = "RSA_AES_256_GCM_SHA384",         KeyLen = 32, FixedIvLen = 4,  MacLen = 0, Aead = "gcm",     Hash = HashAlgorithmName.SHA384 },
                new() { Id = 0xCCA8, Name = "ECDHE_RSA_CHACHA20_POLY1305",    KeyLen = 32, FixedIvLen = 12, MacLen = 0, Aead = "chacha",  Hash = HashAlgorithmName.SHA256 },
                new() { Id = 0xCCA9, Name = "ECDHE_ECDSA_CHACHA20_POLY1305",  KeyLen = 32, FixedIvLen = 12, MacLen = 0, Aead = "chacha",  Hash = HashAlgorithmName.SHA256 },
                // TLS 1.2 CBC (MAC stripped but not verified — flagged per record)
                new() { Id = 0xC027, Name = "ECDHE_RSA_AES_128_CBC_SHA",      KeyLen = 16, FixedIvLen = 16, MacLen = 20, Aead = "cbc",    Hash = HashAlgorithmName.SHA256 },
                new() { Id = 0xC014, Name = "ECDHE_RSA_AES_256_CBC_SHA",      KeyLen = 32, FixedIvLen = 16, MacLen = 20, Aead = "cbc",    Hash = HashAlgorithmName.SHA256 },
                new() { Id = 0x3C,   Name = "RSA_AES_128_CBC_SHA256",         KeyLen = 16, FixedIvLen = 16, MacLen = 32, Aead = "cbc",    Hash = HashAlgorithmName.SHA256 },
                new() { Id = 0x3D,   Name = "RSA_AES_256_CBC_SHA256",         KeyLen = 32, FixedIvLen = 16, MacLen = 32, Aead = "cbc",    Hash = HashAlgorithmName.SHA256 },
            };
            return list.ToDictionary(s => s.Id);
        }

        // -----------------------------------------------------------------------
        // Public entry point
        // -----------------------------------------------------------------------

        public static TlsDecryptResult Decrypt(TcpFlowRecord flow, TlsKeylogService keylog)
        {
            var result = new TlsDecryptResult
            {
                Truncated = flow.Truncated
            };

            var clientRecords = ParseRecords(flow.ClientData);
            var serverRecords = ParseRecords(flow.ServerData);
            if (flow.Truncated) result.Status = "Capture truncated mid-stream — some records may be missing.";

            var hello = ParseClientHello(clientRecords);
            if (hello == null)
            {
                result.Status = "No TLS handshake found in this flow.";
                return result;
            }

            var serverHello = ParseServerHello(serverRecords);
            ushort suiteId = serverHello?.SuiteId ?? hello.OfferedSuites.FirstOrDefault(s => Suites.ContainsKey(s));
            if (suiteId == 0 || !Suites.TryGetValue(suiteId, out var suite))
            {
                result.Status = $"Unsupported cipher suite 0x{suiteId:X4}.";
                return result;
            }

            result.Sni = hello.Sni;
            result.Alpn = hello.Alpn;
            result.CipherSuite = suite.Name;

            var secrets = keylog.GetSecrets(hello.ClientRandom);
            if (secrets == null || secrets.Count == 0)
            {
                result.Status = TlsKeylogService.KeylogEnabled
                    ? "Not instrumented — no TLS secrets logged for this session (install the hook in this python's environment)."
                    : "TLS keylogging is disabled in settings.";
                return result;
            }

            bool tls13 = serverHello?.IsTls13 ?? secrets.ContainsKey("CLIENT_HANDSHAKE_TRAFFIC_SECRET");
            result.TlsVersion = tls13 ? "TLS 1.3" : "TLS 1.2";

            if (tls13)
                DecryptTls13(result, clientRecords, serverRecords, secrets, suite);
            else
                DecryptTls12(result, clientRecords, serverRecords, secrets, suite);

            result.Success = result.Records.Any(r => r.Decrypted && r.ContentType == "application_data");
            if (result.Success)
                result.Status = $"{result.Records.Count(r => r.Decrypted)} record(s) decrypted";
            else if (string.IsNullOrEmpty(result.Status) || result.Status.StartsWith("Capture truncated"))
                result.Status = "Undecryptable (incomplete capture or missing secret).";

            result.HttpSummary = SummarizeHttp(result);
            return result;
        }

        // -----------------------------------------------------------------------
        // TLS record parsing
        // -----------------------------------------------------------------------

        private sealed class TlsRecord
        {
            public byte Type;
            public ushort Version;
            public byte[] Payload;
        }

        /// <summary>
        /// Splits a byte stream into TLS records. With head+tail retention the
        /// stream can contain a gap; parsing resynchronizes on the next
        /// plausible header instead of losing the tail.
        /// </summary>
        private static List<TlsRecord> ParseRecords(byte[] stream)
        {
            var records = new List<TlsRecord>();
            if (stream == null || stream.Length < 5) return records;

            int pos = 0;
            while (pos + 5 <= stream.Length)
            {
                byte type = stream[pos];
                ushort version = (ushort)((stream[pos + 1] << 8) | stream[pos + 2]);
                int length = (stream[pos + 3] << 8) | stream[pos + 4];

                bool plausible = type >= 20 && type <= 24 &&
                                 (version >> 8) == 0x03 && (version & 0xFF) <= 0x04 &&
                                 length is > 0 and <= 0x4200;
                if (!plausible || pos + 5 + length > stream.Length)
                {
                    pos++; // resync scan
                    continue;
                }

                var payload = new byte[length];
                Array.Copy(stream, pos + 5, payload, 0, length);
                records.Add(new TlsRecord { Type = type, Version = version, Payload = payload });
                pos += 5 + length;
            }
            return records;
        }

        // -----------------------------------------------------------------------
        // Handshake message parsing
        // -----------------------------------------------------------------------

        private sealed class ClientHelloInfo
        {
            public byte[] ClientRandom;
            public string Sni;
            public string Alpn;
            public ushort[] OfferedSuites;
            public bool OfferedTls13;
        }

        private static ClientHelloInfo ParseClientHello(List<TlsRecord> records)
        {
            foreach (var record in records.Where(r => r.Type == 22))
            {
                byte[] body = HandshakeBody(record.Payload, 1); // handshake type 1 = ClientHello
                if (body == null) continue;

                var info = new ClientHelloInfo();
                var reader = new ByteReader(body);
                reader.Skip(2);                       // client_version
                info.ClientRandom = reader.Take(32);  // always at a fixed offset
                int sessionIdLen = reader.Take8();
                reader.Skip(sessionIdLen);
                int suitesLen = reader.Take16();
                var suites = new List<ushort>();
                for (int i = 0; i + 1 < suitesLen; i += 2) suites.Add(reader.Take16());
                info.OfferedSuites = suites.ToArray();
                int compLen = reader.Take8();
                reader.Skip(compLen);
                info.OfferedTls13 = ParseExtensions(reader, extType =>
                {
                    if (extType == 43)
                    {
                        int listLen = reader.Take8();
                        for (int i = 0; i + 1 < listLen; i += 2)
                            if (reader.Take16() == 0x0304) return true;
                        return false;
                    }
                    if (extType == 0)
                    {
                        int listLen = reader.Take16();
                        int entryType = reader.Take8();
                        int nameLen = reader.Take16();
                        info.Sni = Encoding.ASCII.GetString(reader.Take(nameLen));
                    }
                    else if (extType == 16)
                    {
                        int listLen = reader.Take16();
                        var protocols = new List<string>();
                        int consumed = 0;
                        while (consumed < listLen)
                        {
                            int protoLen = reader.Take8();
                            protocols.Add(Encoding.ASCII.GetString(reader.Take(protoLen)));
                            consumed += 1 + protoLen;
                        }
                        info.Alpn = string.Join(", ", protocols);
                    }
                    return false;
                });
                return info;
            }
            return null;
        }

        private sealed class ServerHelloInfo
        {
            public ushort SuiteId;
            public bool IsTls13;
        }

        private static ServerHelloInfo ParseServerHello(List<TlsRecord> records)
        {
            foreach (var record in records.Where(r => r.Type == 22))
            {
                byte[] body = HandshakeBody(record.Payload, 2); // handshake type 2 = ServerHello
                if (body == null) continue;

                var info = new ServerHelloInfo();
                var reader = new ByteReader(body);
                ushort version = reader.Take16();
                reader.Skip(32);                        // random
                int sessionIdLen = reader.Take8();
                reader.Skip(sessionIdLen);
                info.SuiteId = reader.Take16();
                reader.Skip(1);                         // compression
                ParseExtensions(reader, extType =>
                {
                    if (extType == 43)                  // supported_versions: the real one
                        info.IsTls13 = reader.Take16() == 0x0304;
                    return false;
                });
                if (version == 0x0304) info.IsTls13 = true;
                return info;
            }
            return null;
        }

        /// <summary>Returns the handshake body when the record starts with the wanted type.</summary>
        private static byte[] HandshakeBody(byte[] payload, byte wantedType)
        {
            if (payload.Length < 4 || payload[0] != wantedType) return null;
            int length = (payload[1] << 16) | (payload[2] << 8) | payload[3];
            if (4 + length > payload.Length) return null;
            var body = new byte[length];
            Array.Copy(payload, 4, body, 0, length);
            return body;
        }

        /// <summary>
        /// Walks an extension block; the callback may consume the extension
        /// body from the reader (it is given the type first) and returns true
        /// to abort the walk. The walker realigns to each extension's declared
        /// extent afterwards, so a callback that reads too much or too little
        /// cannot desync the following extensions.
        /// </summary>
        private static bool ParseExtensions(ByteReader reader, Func<ushort, bool> consume)
        {
            if (!reader.HasMore(2)) return false;
            int extBlockLen = reader.Take16();
            int consumed = 0;
            while (consumed + 4 <= extBlockLen && reader.HasMore(4))
            {
                ushort extType = reader.Take16();
                int extLen = reader.Take16();
                int bodyStart = reader.Position;
                if (consume(extType)) return true;
                reader.SeekTo(bodyStart + extLen);
                consumed += 4 + extLen;
            }
            return false;
        }

        // -----------------------------------------------------------------------
        // TLS 1.2
        // -----------------------------------------------------------------------

        private static void DecryptTls12(TlsDecryptResult result,
            List<TlsRecord> clientRecords, List<TlsRecord> serverRecords,
            IReadOnlyDictionary<string, byte[]> secrets, SuiteInfo suite)
        {
            if (!secrets.TryGetValue("CLIENT_RANDOM", out var masterSecret))
            {
                result.Status = "CLIENT_RANDOM secret missing for this session.";
                return;
            }

            // The key block needs both randoms: client's from the hello we
            // parsed, server's from the ServerHello's fixed offset.
            byte[] clientRandom = null, serverRandom = null;
            foreach (var r in clientRecords.Where(r => r.Type == 22))
                if (HandshakeBody(r.Payload, 1) != null) { clientRandom = ExtractRandom(r.Payload); break; }
            foreach (var r in serverRecords.Where(r => r.Type == 22))
                if (HandshakeBody(r.Payload, 2) != null) { serverRandom = ExtractRandom(r.Payload); break; }
            if (clientRandom == null || serverRandom == null)
            {
                result.Status = "Incomplete handshake capture (a hello is missing).";
                return;
            }

            int blockLen = suite.MacLen * 2 + suite.KeyLen * 2 + suite.FixedIvLen * 2;
            byte[] keyBlock = Prf12(masterSecret, "key expansion",
                serverRandom.Concat(clientRandom).ToArray(), blockLen, suite.Hash);

            var halves = SplitKeyBlock(keyBlock, suite);
            DecryptDirection12(result, clientRecords, halves.Client, suite, fromClient: true);
            DecryptDirection12(result, serverRecords, halves.Server, suite, fromClient: false);
        }

        private static byte[] ExtractRandom(byte[] handshakePayload)
        {
            // handshake header(4) + version(2) then the 32-byte random
            var random = new byte[32];
            Array.Copy(handshakePayload, 6, random, 0, 32);
            return random;
        }

        private sealed class KeyHalf
        {
            public byte[] MacKey;
            public byte[] EncKey;
            public byte[] FixedIv;
            public int MacLen;
        }

        private static (KeyHalf Client, KeyHalf Server) SplitKeyBlock(byte[] block, SuiteInfo suite)
        {
            // RFC 5246 §6.3 key_block layout — grouped by kind, not per side:
            // [client MAC][server MAC][client key][server key][client IV][server IV]
            int pos = 0;
            byte[] Take(int len)
            {
                var part = new byte[len];
                Array.Copy(block, pos, part, 0, len);
                pos += len;
                return part;
            }
            byte[] clientMac = Take(suite.MacLen), serverMac = Take(suite.MacLen);
            byte[] clientKey = Take(suite.KeyLen), serverKey = Take(suite.KeyLen);
            byte[] clientIv = Take(suite.FixedIvLen), serverIv = Take(suite.FixedIvLen);
            return (new KeyHalf { MacKey = clientMac, EncKey = clientKey, FixedIv = clientIv, MacLen = suite.MacLen },
                    new KeyHalf { MacKey = serverMac, EncKey = serverKey, FixedIv = serverIv, MacLen = suite.MacLen });
        }

        private static void DecryptDirection12(TlsDecryptResult result, List<TlsRecord> records, KeyHalf keys,
            SuiteInfo suite, bool fromClient)
        {
            // Per-direction record sequence for the AEAD AAD. RFC 5246 §6.1:
            // the counter resets when a new connection state becomes active
            // (ChangeCipherSpec). The CCS record itself is not counted — the
            // first encrypted record (the Finished) is sequence 0.
            long seq = 0;
            bool ccsSeen = false;  // app data only becomes encrypted after ChangeCipherSpec

            foreach (var record in records)
            {
                long recordSeq = seq;
                switch (record.Type)
                {
                    case 20:
                        ccsSeen = true;
                        seq = -1; // the following record restarts at zero
                        AddPlaintext(result, fromClient, "change_cipher_spec", record.Payload);
                        break;

                    case 22 when !ccsSeen:
                        AddPlaintext(result, fromClient, "handshake", record.Payload);
                        break;

                    case 23 when ccsSeen:
                        DecryptAppRecord12(result, record, keys, suite, fromClient, recordSeq);
                        break;

                    case 21:
                        AddPlaintext(result, fromClient, "alert", record.Payload);
                        break;
                }
                seq++;
            }
        }

        /// <summary>Decrypts one TLS 1.2 application_data record with the direction's key half.</summary>
        private static void DecryptAppRecord12(TlsDecryptResult result, TlsRecord record, KeyHalf keys,
            SuiteInfo suite, bool fromClient, long seq)
        {
            byte[] plaintext = suite.Aead switch
            {
                "gcm" => DecryptGcm12(keys, record, seq),
                "chacha" => DecryptChaCha12(keys, record, seq),
                "cbc" => DecryptCbc12(keys, record),
                _ => null
            };

            if (plaintext != null)
            {
                AddPlaintext(result, fromClient, "application_data", plaintext);
                if (suite.Aead == "cbc")
                    result.Records[^1].Note = "CBC record — padding valid, MAC not verified";
                return;
            }

            result.Records.Add(new TlsPlainRecord
            {
                FromClient = fromClient,
                ContentType = "application_data",
                Decrypted = false,
                Note = "undecryptable (incomplete capture or missing secret)"
            });
        }

        /// <summary>TLS 1.2 GCM: explicit nonce (8) ‖ ciphertext ‖ tag; implicit IV from the key block.</summary>
        private static byte[] DecryptGcm12(KeyHalf keys, TlsRecord record, long seq)
        {
            if (record.Payload.Length < 8 + 16) return null;

            var nonce = new byte[4 + 8];
            Array.Copy(keys.FixedIv, 0, nonce, 0, 4);
            Array.Copy(record.Payload, 0, nonce, 4, 8);

            // AAD length is the plaintext fragment length (RFC 5288 §3):
            // total minus explicit nonce minus AEAD tag.
            int plainLen = record.Payload.Length - 8 - 16;
            var aad = new byte[13];
            for (int i = 0; i < 8; i++) aad[i] = (byte)(seq >> (8 * (7 - i)));
            aad[8] = record.Type;
            aad[9] = (byte)(record.Version >> 8);
            aad[10] = (byte)(record.Version & 0xFF);
            aad[11] = (byte)(plainLen >> 8);
            aad[12] = (byte)(plainLen & 0xFF);

            return AeadDecrypt("gcm", keys.EncKey, nonce,
                record.Payload.AsSpan(8).ToArray(), aad);
        }

        /// <summary>
        /// TLS 1.2 ChaCha20-Poly1305 (RFC 7905): nonce = 4 zero bytes ‖ seq.
        /// The static-IV-XOR-seq variant is tried as a fallback — the AEAD tag
        /// makes a wrong construction fail safely rather than mis-decrypt.
        /// </summary>
        private static byte[] DecryptChaCha12(KeyHalf keys, TlsRecord record, long seq)
        {
            var nonce = new byte[12];
            for (int i = 0; i < 8; i++) nonce[11 - i] = (byte)(seq >> (8 * i));

            int plainLen = record.Payload.Length - 16; // AAD wants the plaintext length (tag excluded)
            var aad = new byte[13];
            for (int i = 0; i < 8; i++) aad[i] = (byte)(seq >> (8 * (7 - i)));
            aad[8] = record.Type;
            aad[9] = (byte)(record.Version >> 8);
            aad[10] = (byte)(record.Version & 0xFF);
            aad[11] = (byte)(plainLen >> 8);
            aad[12] = (byte)(plainLen & 0xFF);

            byte[] plain = AeadDecrypt("chacha", keys.EncKey, nonce, record.Payload, aad);
            if (plain != null) return plain;

            var xorNonce = Nonce13(keys.FixedIv, seq);
            return AeadDecrypt("chacha", keys.EncKey, xorNonce, record.Payload, aad);
        }

        /// <summary>
        /// TLS 1.2 CBC: payload = IV ‖ encrypted; padding stripped per RFC
        /// 5246. The trailing MAC is removed but NOT verified (record-level
        /// sequence tracking across a possibly-resynchronized stream makes the
        /// MAC input unreliable) — records carry a note saying so.
        /// </summary>
        private static byte[] DecryptCbc12(KeyHalf keys, TlsRecord record)
        {
            byte[] payload = record.Payload;
            if (payload.Length < 32 + keys.MacLen) return null;

            using var aes = Aes.Create();
            aes.Key = keys.EncKey;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;

            byte[] iv = payload[..16];
            byte[] encrypted = payload[16..];
            byte[] decrypted;
            try
            {
                using var decryptor = aes.CreateDecryptor();
                decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
            }
            catch
            {
                return null;
            }

            int padLen = decrypted[^1];
            if (padLen >= decrypted.Length) return null;
            // Sanity per RFC 5246: every padding byte equals the length
            for (int i = decrypted.Length - padLen - 1; i < decrypted.Length - 1; i++)
                if (decrypted[i] != padLen) return null;

            int contentLen = decrypted.Length - padLen - 1 - keys.MacLen;
            return contentLen > 0 ? decrypted[..contentLen] : null;
        }

        // -----------------------------------------------------------------------
        // TLS 1.3
        // -----------------------------------------------------------------------

        private sealed class Direction13
        {
            public byte[] HandshakeSecret, HandshakeKey, HandshakeIv;
            public byte[] AppSecret, AppKey, AppIv;
            public long HandshakeSeq, AppSeq;
            public bool AfterKeyUpdate;

            /// <summary>RFC 8446 §7.2 KeyUpdate: next secret, fresh key/iv, sequence resets.</summary>
            public void RollKeyUpdate(HashAlgorithmName hash, int keyLen)
            {
                AppSecret = ExpandLabel(AppSecret, "traffic upd", HashLength(hash), hash);
                AppKey = ExpandLabel(AppSecret, "key", keyLen, hash);
                AppIv = ExpandLabel(AppSecret, "iv", 12, hash);
                AppSeq = 0;
                AfterKeyUpdate = true;
            }
        }

        private static int HashLength(HashAlgorithmName hash) =>
            hash == HashAlgorithmName.SHA384 ? 48 : 32;

        private static void DecryptTls13(TlsDecryptResult result,
            List<TlsRecord> clientRecords, List<TlsRecord> serverRecords,
            IReadOnlyDictionary<string, byte[]> secrets, SuiteInfo suite)
        {
            var client = BuildDirection13(secrets, "CLIENT", suite);
            var server = BuildDirection13(secrets, "SERVER", suite);
            if (client == null || server == null)
            {
                result.Status = "TLS 1.3 traffic secrets missing for this session.";
                return;
            }

            // Records interleave across directions; process both in stream
            // order per direction — sequence numbers are per-direction anyway.
            DecryptDirection13(result, clientRecords, client, suite, fromClient: true);
            DecryptDirection13(result, serverRecords, server, suite, fromClient: false);
        }

        private static Direction13 BuildDirection13(IReadOnlyDictionary<string, byte[]> secrets, string side, SuiteInfo suite)
        {
            byte[] handshakeSecret = secrets.GetValueOrDefault($"{side}_HANDSHAKE_TRAFFIC_SECRET");
            byte[] appSecret = secrets.GetValueOrDefault($"{side}_TRAFFIC_SECRET_0");
            if (handshakeSecret == null && appSecret == null) return null;

            var dir = new Direction13
            {
                HandshakeSecret = handshakeSecret,
                AppSecret = appSecret
            };
            if (handshakeSecret != null)
            {
                dir.HandshakeKey = ExpandLabel(handshakeSecret, "key", suite.KeyLen, suite.Hash);
                dir.HandshakeIv = ExpandLabel(handshakeSecret, "iv", 12, suite.Hash);
            }
            if (appSecret != null)
            {
                dir.AppKey = ExpandLabel(appSecret, "key", suite.KeyLen, suite.Hash);
                dir.AppIv = ExpandLabel(appSecret, "iv", 12, suite.Hash);
            }
            return dir;
        }

        private static void DecryptDirection13(TlsDecryptResult result, List<TlsRecord> records, Direction13 dir,
            SuiteInfo suite, bool fromClient)
        {
            // Early handshake records (the hello itself) are plaintext; from the
            // first encrypted record on, try app key first, then handshake key.
            bool seenEncrypted = false;

            foreach (var record in records)
            {
                if (record.Type == 22 && !seenEncrypted)
                {
                    AddPlaintext(result, fromClient, "handshake", record.Payload);
                    continue;
                }
                if (record.Type != 23 && record.Type != 22) continue;

                seenEncrypted = true;
                byte[] plaintext = TryDecrypt13(record, dir, suite);

                if (plaintext == null)
                {
                    result.Records.Add(new TlsPlainRecord
                    {
                        FromClient = fromClient,
                        ContentType = ContentType13(record.Type),
                        Decrypted = false,
                        Note = dir.AfterKeyUpdate
                            ? "undecrypted after key update"
                            : "undecryptable (missing secret or incomplete capture)"
                    });
                    continue;
                }

                byte innerType = plaintext.Length > 0 ? plaintext[^1] : (byte)0;
                var content = plaintext[..^1];
                while (content.Length > 0 && content[^1] == 0) content = content[..^1]; // zero padding

                if (innerType == 24)
                {
                    AddPlaintext(result, fromClient, "key_update", content);
                    if (dir.AppSecret != null)
                        dir.RollKeyUpdate(suite.Hash, suite.KeyLen);
                    continue;
                }

                switch (innerType)
                {
                    case 23:
                        AddPlaintext(result, fromClient, "application_data", content);
                        break;
                    case 22:
                        foreach (var msg in SplitHandshakeMessages(content))
                            AddPlaintext(result, fromClient, HandshakeName(msg[0]), msg);
                        break;
                    case 21:
                        AddPlaintext(result, fromClient, "alert", content);
                        break;
                    default:
                        AddPlaintext(result, fromClient, $"content {innerType}", content);
                        break;
                }
            }
        }

        /// <summary>Attempts app then handshake keys; advances the winning key's sequence.</summary>
        private static byte[] TryDecrypt13(TlsRecord record, Direction13 dir, SuiteInfo suite)
        {
            if (dir.AppKey != null)
            {
                byte[] nonce = Nonce13(dir.AppIv, dir.AppSeq);
                byte[] plain = AeadDecrypt(suite.Aead, dir.AppKey, nonce, record.Payload, AeadHeader13(record));
                if (plain != null)
                {
                    dir.AppSeq++;
                    return plain;
                }
            }
            if (dir.HandshakeKey != null)
            {
                byte[] nonce = Nonce13(dir.HandshakeIv, dir.HandshakeSeq);
                byte[] plain = AeadDecrypt(suite.Aead, dir.HandshakeKey, nonce, record.Payload, AeadHeader13(record));
                if (plain != null)
                {
                    dir.HandshakeSeq++;
                    return plain;
                }
            }
            return null;
        }

        private static byte[] Nonce13(byte[] staticIv, long seq)
        {
            var nonce = (byte[])staticIv.Clone();
            for (int i = 0; i < 8; i++)
                nonce[nonce.Length - 1 - i] ^= (byte)(seq >> (8 * i));
            return nonce;
        }

        private static byte[] AeadHeader13(TlsRecord record)
        {
            // opaque_type(1)=record.Type, legacy_version(2)=0x0303, length(2)
            return new byte[] { record.Type, 0x03, 0x03,
                (byte)(record.Payload.Length >> 8), (byte)(record.Payload.Length & 0xFF) };
        }

        // -----------------------------------------------------------------------
        // AEAD primitives — in-box crypto, tag failure = null (never a guess).
        // TLS 1.2 and 1.3 share the constructions; only the nonce/AAD wiring
        // (done by the callers) differs.
        // -----------------------------------------------------------------------

        private static byte[] AeadDecrypt(string kind, byte[] key, byte[] nonce, byte[] payload, byte[] aad)
        {
            if (payload.Length < 16) return null;

            byte[] ciphertext = payload[..^16];
            byte[] tag = payload[^16..];
            var plaintext = new byte[ciphertext.Length];

            try
            {
                switch (kind)
                {
                    case "gcm":
                    case "t13gcm":
                        using (var aes = new AesGcm(key, 16))
                        {
                            aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                        }
                        return plaintext;

                    case "chacha":
                    case "t13chacha":
                        using (var chacha = new ChaCha20Poly1305(key))
                        {
                            chacha.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                        }
                        return plaintext;
                }
            }
            catch (CryptographicException)
            {
                return null; // AEAD tag mismatch — wrong key/nonce/secret
            }
            catch
            {
                return null;
            }
            return null;
        }

        private static IEnumerable<byte[]> SplitHandshakeMessages(byte[] content)
        {
            int pos = 0;
            while (pos + 4 <= content.Length)
            {
                int length = (content[pos + 1] << 16) | (content[pos + 2] << 8) | content[pos + 3];
                if (pos + 4 + length > content.Length) yield break;
                yield return content[pos..(pos + 4 + length)];
                pos += 4 + length;
            }
        }

        private static string HandshakeName(byte type) => type switch
        {
            1 => "client_hello",
            2 => "server_hello",
            4 => "new_session_ticket",
            8 => "encrypted_extensions",
            11 => "certificate",
            13 => "certificate_request",
            14 => "finished",
            15 => "certificate_url",
            20 => "finished", // (never 20; kept exhaustive)
            _ => $"handshake {type}"
        };

        private static string ContentType13(byte type) => type switch
        {
            20 => "change_cipher_spec",
            21 => "alert",
            22 => "handshake",
            23 => "application_data",
            _ => $"content {type}"
        };

        private static void AddPlaintext(TlsDecryptResult result, bool fromClient, string type, byte[] data)
        {
            result.Records.Add(new TlsPlainRecord
            {
                FromClient = fromClient,
                ContentType = type,
                Decrypted = true,
                Data = data
            });
            if (type == "application_data")
            {
                if (fromClient) result.ClientAppBytes += data.Length;
                else result.ServerAppBytes += data.Length;
            }
        }

        // -----------------------------------------------------------------------
        // HTTP/1.x summary
        // -----------------------------------------------------------------------

        private static string SummarizeHttp(TlsDecryptResult result)
        {
            var clientBytes = ConcatRecords(result, fromClient: true);
            var serverBytes = ConcatRecords(result, fromClient: false);
            if (clientBytes.Length == 0 && serverBytes.Length == 0) return null;

            var sb = new StringBuilder();
            AppendHttpMessages(sb, "→ request", clientBytes);
            AppendHttpMessages(sb, "← response", serverBytes);
            return sb.Length > 0 ? sb.ToString() : null;
        }

        private static byte[] ConcatRecords(TlsDecryptResult result, bool fromClient)
        {
            var parts = result.Records
                .Where(r => r.Decrypted && r.ContentType == "application_data" && r.FromClient == fromClient)
                .Select(r => r.Data)
                .ToList();
            long total = parts.Sum(p => p.Length);
            if (total == 0 || total > 4 * 1024 * 1024) return Array.Empty<byte>();
            var buffer = new byte[total];
            int offset = 0;
            foreach (var part in parts)
            {
                Array.Copy(part, 0, buffer, offset, part.Length);
                offset += part.Length;
            }
            return buffer;
        }

        private static void AppendHttpMessages(StringBuilder sb, string label, byte[] stream)
        {
            int shown = 0;
            int pos = 0;
            while (shown < 3 && pos < stream.Length)
            {
                int headerEnd = IndexOf(stream, "\r\n\r\n"u8, pos);
                if (headerEnd < 0) break;

                string head = Encoding.ASCII.GetString(stream[pos..headerEnd]);
                var lines = head.Split("\r\n");
                if (lines.Length == 0 || !LooksLikeHttpStart(lines[0]))
                {
                    // binary or chunked continuation — stop summarizing
                    break;
                }

                sb.Append(label).Append(": ").Append(lines[0]).AppendLine();
                foreach (var line in lines.Skip(1))
                {
                    if (HeaderOfInterest(line)) sb.Append("    ").Append(line.TrimEnd()).AppendLine();
                }
                shown++;

                int headerLen = headerEnd + 4 - pos;
                int contentLength = FindContentLength(lines);
                pos = contentLength >= 0 ? headerEnd + 4 + contentLength : stream.Length;
            }
        }

        private static bool LooksLikeHttpStart(string line) =>
            line.Contains("HTTP/") &&
            (line.Split(' ').Length >= 2);

        private static bool HeaderOfInterest(string line)
        {
            foreach (var name in new[] { "Host:", "User-Agent:", "Content-Type:", "Content-Length:", "Server:", "Location:" })
                if (line.StartsWith(name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static int FindContentLength(string[] lines)
        {
            foreach (var line in lines)
                if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase) &&
                    int.TryParse(line.AsSpan(line.IndexOf(':') + 1).Trim(), out int len))
                    return len;
            return -1;
        }

        private static int IndexOf(byte[] haystack, ReadOnlySpan<byte> needle, int start)
        {
            for (int i = start; i <= haystack.Length - needle.Length; i++)
            {
                int j = 0;
                while (j < needle.Length && haystack[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }

        // -----------------------------------------------------------------------
        // Crypto helpers (TLS PRF + HKDF-Expand-Label, in-box primitives)
        // -----------------------------------------------------------------------

        /// <summary>TLS 1.2 PRF (RFC 5246 §5): P_hash expansion of the master secret.</summary>
        private static byte[] Prf12(byte[] secret, string label, byte[] seed, int length, HashAlgorithmName hash)
        {
            var labelBytes = Encoding.ASCII.GetBytes(label);
            byte[] input = labelBytes.Concat(seed).ToArray();

            using var hmac = CreateHmac(hash, secret);
            byte[] a = hmac.ComputeHash(input);

            var output = new byte[length];
            int filled = 0;
            while (filled < length)
            {
                byte[] block = hmac.ComputeHash(a.Concat(input).ToArray());
                int take = Math.Min(block.Length, length - filled);
                Array.Copy(block, 0, output, filled, take);
                filled += take;
                a = hmac.ComputeHash(a);
            }
            return output;
        }

        /// <summary>HKDF-Expand (RFC 5869) — secrets from the keylog are already pseudorandom, so Extract is skipped.</summary>
        private static byte[] HkdfExpand(byte[] secret, byte[] info, int length, HashAlgorithmName hash)
        {
            var output = new byte[length];
            byte[] t = Array.Empty<byte>();
            int filled = 0;
            int counter = 1;
            using var hmac = CreateHmac(hash, secret);
            while (filled < length)
            {
                var input = t.Concat(info).Append((byte)counter).ToArray();
                t = hmac.ComputeHash(input);
                int take = Math.Min(t.Length, length - filled);
                Array.Copy(t, 0, output, filled, take);
                filled += take;
                counter++;
            }
            return output;
        }

        /// <summary>TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).</summary>
        private static byte[] ExpandLabel(byte[] secret, string label, int length, HashAlgorithmName hash)
        {
            var info = new List<byte>(label.Length + 8);
            info.Add((byte)(length >> 8));
            info.Add((byte)(length & 0xFF));
            byte[] prefixed = Encoding.ASCII.GetBytes("tls13 " + label);
            info.Add((byte)prefixed.Length);
            info.AddRange(prefixed);
            info.Add(0); // empty context
            return HkdfExpand(secret, info.ToArray(), length, hash);
        }

        private static HMAC CreateHmac(HashAlgorithmName hash, byte[] key) =>
            hash == HashAlgorithmName.SHA384 ? new HMACSHA384(key) : new HMACSHA256(key);

        // -----------------------------------------------------------------------
        // Byte reader for handshake parsing
        // -----------------------------------------------------------------------

        private sealed class ByteReader
        {
            private readonly byte[] _buffer;
            private int _pos;

            public ByteReader(byte[] buffer) => _buffer = buffer;

            public bool HasMore(int count) => _pos + count <= _buffer.Length;
            public void Skip(int count) => _pos = Math.Min(_pos + count, _buffer.Length);
            public int Position => _pos;
            public void SeekTo(int position) => _pos = Math.Clamp(position, 0, _buffer.Length);

            // All reads are bounds-guarded: a malformed or truncated
            // handshake yields zeros/empties, never an out-of-range throw.
            public byte Take8() => HasMore(1) ? _buffer[_pos++] : (byte)0;

            public ushort Take16()
            {
                if (!HasMore(2))
                {
                    _pos = _buffer.Length;
                    return 0;
                }
                ushort value = (ushort)((_buffer[_pos] << 8) | _buffer[_pos + 1]);
                _pos += 2;
                return value;
            }

            public byte[] Take(int count)
            {
                count = Math.Min(count, _buffer.Length - _pos);
                if (count <= 0) return Array.Empty<byte>();
                var part = _buffer[_pos..(_pos + count)];
                _pos += count;
                return part;
            }
        }
    }
}
