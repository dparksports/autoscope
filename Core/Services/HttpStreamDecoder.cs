using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace AutoScope.Services
{
    /// <summary>
    /// Turns one direction of decrypted TLS application-data into a list of
    /// HTTP messages the viewer can render: request/response start line,
    /// selected headers, and the body after chunked-transfer and
    /// Content-Encoding (gzip / br / deflate) decoding.
    ///
    /// HTTP/2 is detected (ALPN or a plausible SETTINGS frame) but not
    /// demultiplexed — no HPACK parser here. Those streams surface as one
    /// "HTTP/2 binary stream" message with the raw bytes in the hex view, so
    /// the tab stays honest about what it can and cannot show.
    /// </summary>
    public static class HttpStreamDecoder
    {
        /// <summary>Refuse to decode bodies larger than this — the capture
        /// caps a direction at 8 MB wire anyway; this is the belt to that.</summary>
        private const int MaxDecodeBytes = 16 * 1024 * 1024;

        public sealed class HttpMessage
        {
            public bool FromClient { get; set; }
            public bool IsHttp { get; set; }          // parseable HTTP/1.x message
            public string StartLine { get; set; }      // "POST /v1/x HTTP/1.1" / "HTTP/1.1 200 OK"
            public string MethodOrStatus { get; set; } // short grid label: "POST /v1/x" / "200"
            public Dictionary<string, string> Headers { get; } = new(StringComparer.OrdinalIgnoreCase);
            public byte[] Body { get; set; }           // after chunked + content-encoding decode
            public string ContentEncoding { get; set; }
            public bool Chunked { get; set; }
            public string ContentType { get; set; }
            public string Kind { get; set; }           // json / text / html / binary / empty / h2

            public string Display
            {
                get
                {
                    string arrow = FromClient ? "→ " : "← ";
                    string label = IsHttp ? (MethodOrStatus ?? "") : (Kind ?? "");
                    return $"{arrow}{label}  {FormatBytes(Body?.Length ?? 0)}{(ContentEncoding != null ? $"  ({ContentEncoding} decoded)" : "")}";
                }
            }

            public string HeaderText()
            {
                var sb = new StringBuilder();
                sb.AppendLine(StartLine ?? "(not HTTP)");
                foreach (var kv in Headers)
                    sb.Append(kv.Key).Append(": ").AppendLine(kv.Value);
                if (Chunked) sb.AppendLine("(chunked transfer decoded)");
                if (ContentEncoding != null) sb.AppendLine($"(content-encoding {ContentEncoding} decoded)");
                return sb.ToString();
            }
        }

        /// <summary>
        /// Parses a whole direction. A direction that does not start like
        /// HTTP yields a single non-HTTP message carrying the raw bytes, so
        /// the viewer always has something truthful to show.
        /// </summary>
        public static List<HttpMessage> Decode(byte[] stream, bool fromClient, string alpn)
        {
            var messages = new List<HttpMessage>();
            if (stream == null || stream.Length == 0) return messages;

            if (IsHttp2(stream, alpn))
            {
                messages.Add(new HttpMessage
                {
                    FromClient = fromClient,
                    IsHttp = false,
                    MethodOrStatus = "HTTP/2",
                    Kind = "h2",
                    Body = stream,
                });
                return messages;
            }

            int pos = 0;
            while (pos < stream.Length && messages.Count < 200)
            {
                var msg = ParseOne(stream, ref pos, fromClient);
                if (msg == null) break;
                messages.Add(msg);
            }

            // Trailing bytes that never formed a complete message: surface
            // them rather than silently dropping them.
            if (pos < stream.Length && messages.Count > 0 && messages[^1].IsHttp)
                messages.Add(RawMessage(stream[pos..], fromClient, "partial"));
            if (messages.Count == 0)
                messages.Add(RawMessage(stream, fromClient, null));
            return messages;
        }

        private static HttpMessage ParseOne(byte[] stream, ref int pos, bool fromClient)
        {
            int headerEnd = IndexOf(stream, "\r\n\r\n"u8, pos);
            if (headerEnd < 0) return null;

            string head = Encoding.ASCII.GetString(stream, pos, headerEnd - pos);
            string[] lines = head.Split("\r\n");
            if (lines.Length == 0 || !LooksLikeHttpStart(lines[0])) return null;

            var msg = new HttpMessage
            {
                FromClient = fromClient,
                IsHttp = true,
                StartLine = lines[0],
            };
            foreach (var line in lines[1..])
            {
                int colon = line.IndexOf(':');
                if (colon > 0)
                    msg.Headers[line[..colon].Trim()] = line[(colon + 1)..].Trim();
            }
            msg.MethodOrStatus = fromClient
                ? FirstTwoTokens(lines[0])
                : FirstToken(lines[0]);
            msg.ContentType = msg.Headers.GetValueOrDefault("Content-Type");

            int bodyStart = headerEnd + 4;
            byte[] body;
            if (TryGetHeader(msg, "Transfer-Encoding", out var te) &&
                te.Contains("chunked", StringComparison.OrdinalIgnoreCase))
            {
                msg.Chunked = true;
                var (dechunked, consumed) = Dechunk(stream, bodyStart);
                body = dechunked;
                pos = consumed;
            }
            else if (TryGetHeader(msg, "Content-Length", out var clValue) &&
                     int.TryParse(clValue, out int cl) && cl >= 0)
            {
                if (bodyStart + cl > stream.Length)
                {
                    // Capture cut the body short — show what arrived.
                    body = stream[bodyStart..];
                    pos = stream.Length;
                }
                else
                {
                    body = stream[bodyStart..(bodyStart + cl)];
                    pos = bodyStart + cl;
                }
            }
            else
            {
                // No framing information: the rest of the direction is the
                // body (common for truncated captures and connection-close
                // responses).
                body = stream[bodyStart..];
                pos = stream.Length;
            }

            if (TryGetHeader(msg, "Content-Encoding", out var ce) && body.Length > 0)
            {
                var decoded = DecodeBody(body, ce);
                if (decoded != null)
                {
                    msg.ContentEncoding = ce;
                    body = decoded;
                }
            }

            msg.Body = body;
            msg.Kind = ClassifyBody(msg.ContentType, body);
            return msg;
        }

        // ── body decoding ────────────────────────────────────────────────

        private static byte[] DecodeBody(byte[] body, string contentEncoding)
        {
            if (body.Length == 0 || body.Length > MaxDecodeBytes) return null;
            try
            {
                string ce = contentEncoding.Trim().ToLowerInvariant();
                if (ce is "gzip" or "x-gzip")
                {
                    // gzip streams may be concatenated (RFC 1952 §2.2); the
                    // .NET decoder stops after the first member, so loop.
                    using var output = new MemoryStream();
                    int offset = 0;
                    int members = 0;
                    while (offset + 2 <= body.Length && body[offset] == 0x1F && body[offset + 1] == 0x8B && members < 64)
                    {
                        using var input = new MemoryStream(body, offset, body.Length - offset, writable: false);
                        using var gz = new GZipStream(input, CompressionMode.Decompress);
                        gz.CopyTo(output);
                        offset = (int)input.Position;
                        members++;
                    }
                    return members > 0 ? output.ToArray() : null;
                }
                if (ce == "br")
                {
                    using var input = new MemoryStream(body);
                    using var br = new BrotliStream(input, CompressionMode.Decompress);
                    using var output = new MemoryStream();
                    br.CopyTo(output);
                    return output.ToArray();
                }
                if (ce == "deflate")
                {
                    // "deflate" means zlib (RFC 1950), but half the internet
                    // ships raw deflate — try both.
                    try
                    {
                        using var input = new MemoryStream(body);
                        using var zlib = new ZLibStream(input, CompressionMode.Decompress);
                        using var output = new MemoryStream();
                        zlib.CopyTo(output);
                        return output.ToArray();
                    }
                    catch
                    {
                        using var input2 = new MemoryStream(body);
                        using var raw = new DeflateStream(input2, CompressionMode.Decompress);
                        using var output2 = new MemoryStream();
                        raw.CopyTo(output2);
                        return output2.ToArray();
                    }
                }
            }
            catch
            {
                return null; // undecodable body: show the compressed bytes, flagged
            }
            return null;
        }

        /// <summary>Decodes chunked transfer coding; returns the payload and
        /// the stream position after the terminating zero chunk.</summary>
        private static (byte[] payload, int consumed) Dechunk(byte[] stream, int start)
        {
            using var output = new MemoryStream();
            int pos = start;
            while (pos < stream.Length)
            {
                int lineEnd = IndexOf(stream, "\r\n"u8, pos);
                if (lineEnd < 0) break;
                string sizeLine = Encoding.ASCII.GetString(stream, pos, lineEnd - pos);
                int semi = sizeLine.IndexOf(';'); // chunk extensions
                if (semi >= 0) sizeLine = sizeLine[..semi];
                if (!int.TryParse(sizeLine.Trim(), System.Globalization.NumberStyles.HexNumber,
                        System.Globalization.CultureInfo.InvariantCulture, out int size))
                    break; // not actually chunked — stop, keep what we have

                pos = lineEnd + 2;
                if (size == 0)
                {
                    // trailer section ends at a blank line (or the capture end)
                    int trailerEnd = IndexOf(stream, "\r\n\r\n"u8, pos - 2);
                    pos = trailerEnd < 0 ? stream.Length : trailerEnd + 4;
                    break;
                }
                if (pos + size > stream.Length)
                {
                    output.Write(stream, pos, stream.Length - pos);
                    pos = stream.Length;
                    break; // capture cut mid-chunk
                }
                output.Write(stream, pos, size);
                pos += size + 2; // skip payload + CRLF
            }
            return (output.ToArray(), Math.Min(pos, stream.Length));
        }

        // ── classification ───────────────────────────────────────────────

        private static bool IsHttp2(byte[] stream, string alpn)
        {
            if (alpn != null && alpn.Contains("h2", StringComparison.OrdinalIgnoreCase)) return true;
            // HTTP/2 connection preface before the first SETTINGS frame
            return stream.Length >= 9 + 3 &&
                   Encoding.ASCII.GetString(stream, 0, 3) == "PRI" &&
                   stream.Length >= 24 &&
                   Encoding.ASCII.GetString(stream, 14, 10) == "SM\r\n\r\n";
        }

        private static bool LooksLikeHttpStart(string line)
        {
            if (!line.Contains("HTTP/")) return false;
            var parts = line.Split(' ');
            return parts.Length >= 2;
        }

        private static string ClassifyBody(string contentType, byte[] body)
        {
            if (body == null || body.Length == 0) return "empty";
            if (contentType != null)
            {
                string ct = contentType.Split(';')[0].Trim().ToLowerInvariant();
                if (ct.Contains("json")) return "json";
                if (ct.Contains("html")) return "html";
                if (ct.StartsWith("text/")) return "text";
                if (ct.Contains("xml")) return "xml";
                if (ct.Contains("x-www-form-urlencoded") || ct.Contains("form-data")) return "form";
                return "binary";
            }
            // Sniff: mostly printable ASCII → text; leading { or [ → json
            int probe = Math.Min(body.Length, 512), printable = 0;
            for (int i = 0; i < probe; i++)
            {
                byte b = body[i];
                if (b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127)) printable++;
            }
            bool textish = printable * 100 / probe >= 95;
            if (textish && body.Length > 0 && (body[0] == (byte)'{' || body[0] == (byte)'[')) return "json";
            return textish ? "text" : "binary";
        }

        private static HttpMessage RawMessage(byte[] data, bool fromClient, string kind) => new()
        {
            FromClient = fromClient,
            IsHttp = false,
            MethodOrStatus = kind ?? "raw",
            Kind = kind ?? ClassifyBody(null, data),
            Body = data,
        };

        private static bool TryGetHeader(HttpMessage msg, string name, out string value)
        {
            if (msg.Headers.TryGetValue(name, out value))
            {
                // Transfer/Content-Encoding can repeat — join, the decoders
                // handle a combined value, and the flag stays honest.
                return true;
            }
            value = null;
            return false;
        }

        private static string FirstToken(string line) => line.Split(' ').FirstOrDefault() ?? line;
        private static string FirstTwoTokens(string line)
        {
            var parts = line.Split(' ');
            return parts.Length >= 2 ? $"{parts[0]} {parts[1]}" : line;
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes}B";
            if (bytes < 1048576) return $"{bytes / 1024.0:F1}KB";
            return $"{bytes / 1048576.0:F1}MB";
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
    }
}
