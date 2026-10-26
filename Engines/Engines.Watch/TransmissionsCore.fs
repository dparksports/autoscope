// F# port of Core\Services\TlsSni.cs, Core\Services\HttpStreamDecoder.cs,
// Core\Services\TlsDecryptor.cs, Core\Services\TlsKeylogService.cs and
// Core\Models\TlsDecryptResult.cs (namespaces AutoScope.Services /
// AutoScope.Models) for the Engines library. Behavioral faithfulness is the
// contract: same bounds checks, same failure strings, same null-vs-throw
// conventions, same archive-facing byte semantics.
//
// F# port notes (deviations forced by F#/C# interop, none behavioral):
//   • C# static classes become [<AbstractClass; Sealed>] types (the house
//     pattern, see Config.fs); C# nested result types become TOP-LEVEL
//     types in this namespace — F# cannot nest type declarations inside a
//     class, so what C# addressed as HttpStreamDecoder.HttpMessage is,
//     from C#, AutoScope.Engines.Watch.HttpMessage (import the namespace
//     and drop the qualification). TlsDecryptResult/TlsPlainRecord were
//     already top-level in AutoScope.Models.
//   • Private helpers shared by several classes (FormatBytes/IndexOf/
//     LooksLikeHttpStart were private duplicates in the C# classes) live
//     in file-private modules; the private nested classes of TlsDecryptor
//     (SuiteInfo, TlsRecord, ByteReader, …) live there too, out of the
//     public surface.
//   • The keylog directory is no longer hardcoded to
//     %LOCALAPPDATA%\AutoScope\pytrace: engines are app-agnostic, so it
//     is WatchConfig.Identity.DataRoot\pytrace (the identical physical
//     path for the AutoScope app). The DirOverride self-test seam stays.
//   • Null returns: C# `return null` on F#-defined class types is spelled
//     Unchecked.defaultof (F# reserves the null literal for BCL types);
//     Option appears only in private signatures, never on the public
//     surface.

namespace AutoScope.Engines.Watch

open System
open System.Collections.Generic
open System.IO
open System.IO.Compression
open System.Security.AccessControl
open System.Security.Cryptography
open System.Security.Principal
open System.Text

// ── file-private helpers shared by the decoders ──────────────────

module private TransmissionsCoreInternals =

    // F# has no C# `u8` string literals; these are the "\r\n"u8 / "\r\n\r\n"u8
    // needles the C# scanners searched for.
    let crlf: byte[] = [| 13uy; 10uy |]
    let crlfcrlf: byte[] = [| 13uy; 10uy; 13uy; 10uy |]

    let formatBytes (bytes: int64) =
        if bytes < 1024L then $"{bytes}B"
        elif bytes < 1048576L then $"{float bytes / 1024.0:F1}KB"
        else $"{float bytes / 1048576.0:F1}MB"

    // Both C# classes carried a private duplicate of this predicate.
    let looksLikeHttpStart (line: string) =
        line.Contains("HTTP/") && line.Split(' ').Length >= 2

    let indexOf (haystack: byte[]) (needle: byte[]) (start: int) =
        let mutable i = start
        let mutable found = -1
        while found < 0 && i <= haystack.Length - needle.Length do
            let mutable j = 0
            while j < needle.Length && haystack[i + j] = needle[j] do j <- j + 1
            if j = needle.Length then found <- i
            else i <- i + 1
        found

// ── private plumbing of TlsDecryptor (C# nested classes) ─────────

module private TlsDecryptorInternals =

    // ── crypto helpers (TLS PRF + HKDF-Expand-Label, in-box primitives) ──
    // F# port: file-scope functions, not private statics of TlsDecryptor,
    // because Direction13.RollKeyUpdate needs ExpandLabel and F# requires
    // define-before-use in file order — so the helpers come first.

    let hashLength (hash: HashAlgorithmName) =
        if hash = HashAlgorithmName.SHA384 then 48 else 32

    let createHmac (hash: HashAlgorithmName) (key: byte[]) : HMAC =
        if hash = HashAlgorithmName.SHA384 then new HMACSHA384(key) :> HMAC
        else new HMACSHA256(key) :> HMAC

    /// <summary>TLS 1.2 PRF (RFC 5246 §5): P_hash expansion of the master secret.</summary>
    let prf12 (secret: byte[]) (label: string) (seed: byte[]) (length: int) (hash: HashAlgorithmName) =
        let labelBytes = Encoding.ASCII.GetBytes label
        let input = Array.append labelBytes seed

        use hmac = createHmac hash secret
        let mutable a = hmac.ComputeHash input

        let output = Array.zeroCreate<byte> length
        let mutable filled = 0
        while filled < length do
            let block = hmac.ComputeHash(Array.append a input)
            let take = min block.Length (length - filled)
            Array.Copy(block, 0, output, filled, take)
            filled <- filled + take
            a <- hmac.ComputeHash a
        output

    /// <summary>HKDF-Expand (RFC 5869) — secrets from the keylog are already pseudorandom, so Extract is skipped.</summary>
    let hkdfExpand (secret: byte[]) (info: byte[]) (length: int) (hash: HashAlgorithmName) =
        let output = Array.zeroCreate<byte> length
        let mutable t = Array.empty<byte>
        let mutable filled = 0
        let mutable counter = 1
        use hmac = createHmac hash secret
        while filled < length do
            let input = Array.append (Array.append t info) [| byte counter |]
            t <- hmac.ComputeHash input
            let take = min t.Length (length - filled)
            Array.Copy(t, 0, output, filled, take)
            filled <- filled + take
            counter <- counter + 1
        output

    /// <summary>TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).</summary>
    let expandLabel (secret: byte[]) (label: string) (length: int) (hash: HashAlgorithmName) =
        let prefixed = Encoding.ASCII.GetBytes("tls13 " + label)
        let info = ResizeArray<byte>(label.Length + 8)
        info.Add(byte (length >>> 8))
        info.Add(byte (length &&& 0xFF))
        info.Add(byte prefixed.Length)
        info.AddRange(prefixed)
        info.Add(0uy) // empty context
        hkdfExpand secret (Seq.toArray info) length hash

    type SuiteInfo() =
        member val Id: uint16 = 0us with get, set
        member val Name: string = null with get, set
        member val KeyLen = 0 with get, set        // per-direction write key
        member val FixedIvLen = 0 with get, set    // TLS 1.2 key-block fixed IV; TLS 1.3 static IV
        member val MacLen = 0 with get, set        // TLS 1.2 CBC MAC length (0 for AEAD)
        member val Aead: string = null with get, set  // "gcm" | "chacha" | "cbc" | "t13gcm" | "t13chacha"
        member val Hash: HashAlgorithmName = Unchecked.defaultof<_> with get, set

    type TlsRecord() =
        member val Type: byte = 0uy with get, set
        member val Version: uint16 = 0us with get, set
        member val Payload: byte[] = null with get, set

    type ClientHelloInfo() =
        member val ClientRandom: byte[] = null with get, set
        member val Sni: string = null with get, set
        member val Alpn: string = null with get, set
        member val OfferedSuites: uint16[] = null with get, set
        member val OfferedTls13 = false with get, set

    type ServerHelloInfo() =
        member val SuiteId: uint16 = 0us with get, set
        member val IsTls13 = false with get, set

    type KeyHalf() =
        member val MacKey: byte[] = null with get, set
        member val EncKey: byte[] = null with get, set
        member val FixedIv: byte[] = null with get, set
        member val MacLen = 0 with get, set

    type Direction13() =
        member val HandshakeSecret: byte[] = null with get, set
        member val HandshakeKey: byte[] = null with get, set
        member val HandshakeIv: byte[] = null with get, set
        member val AppSecret: byte[] = null with get, set
        member val AppKey: byte[] = null with get, set
        member val AppIv: byte[] = null with get, set
        member val HandshakeSeq = 0L with get, set
        member val AppSeq = 0L with get, set
        member val AfterKeyUpdate = false with get, set

        /// <summary>RFC 8446 §7.2 KeyUpdate: next secret, fresh key/iv, sequence resets.</summary>
        member this.RollKeyUpdate(hash: HashAlgorithmName, keyLen: int) =
            this.AppSecret <- expandLabel this.AppSecret "traffic upd" (hashLength hash) hash
            this.AppKey <- expandLabel this.AppSecret "key" keyLen hash
            this.AppIv <- expandLabel this.AppSecret "iv" 12 hash
            this.AppSeq <- 0L
            this.AfterKeyUpdate <- true

    /// <summary>
    /// Byte reader for handshake parsing. All reads are bounds-guarded: a
    /// malformed or truncated handshake yields zeros/empties, never an
    /// out-of-range throw.
    /// </summary>
    type ByteReader(buffer: byte[]) =
        let mutable pos = 0

        member _.HasMore(count: int) = pos + count <= buffer.Length
        member _.Skip(count: int) = pos <- min (pos + count) buffer.Length
        member _.Position = pos
        member _.SeekTo(position: int) = pos <- Math.Clamp(position, 0, buffer.Length)

        member this.Take8() : byte =
            if this.HasMore 1 then
                let b = buffer[pos]
                pos <- pos + 1
                b
            else 0uy

        member this.Take16() : uint16 =
            if not (this.HasMore 2) then
                pos <- buffer.Length
                0us
            else
                let value = uint16 ((int buffer[pos] <<< 8) ||| int buffer[pos + 1])
                pos <- pos + 2
                value

        member _.Take(count: int) : byte[] =
            let count = min count (buffer.Length - pos)
            if count <= 0 then Array.empty
            else
                let part = buffer[pos..pos + count - 1]
                pos <- pos + count
                part

    // ── crypto helpers: moved above the types (see the note there) ──

// ── TlsSni ────────────────────────────────────────────────────────

/// <summary>
/// Minimal, bounds-checked TLS ClientHello SNI reader for the sinkhole
/// listener. Reads only what attribution needs — the server_name extension
/// of the first handshake — and never trusts lengths: a malformed or
/// truncated hello yields null, never a throw.
/// </summary>
[<AbstractClass; Sealed>]
type TlsSni private () =

    /// <summary>
    /// Attempts to read the SNI hostname from the front of a byte buffer
    /// holding the start of a TLS handshake stream (one or more records).
    /// Returns null when the buffer does not yet contain a complete
    /// ClientHello or carries none.
    /// </summary>
    static member TryReadSni(buffer: byte[], length: int) : string =
        if isNull buffer || length < 11 then null
        else
        // F# port: the C# method had a lattice of early `return null`s;
        // mirrored with a `bail` flag so the control flow — in particular
        // WHICH check failed first — stays identical.
        let mutable bail = false
        let mutable offset = 0
        let mutable hello: byte[] = null

        // Walk records until the ClientHello handshake message is complete
        while not bail && offset + 5 <= length && isNull hello do
            if int buffer[offset] <> 0x16 then bail <- true                  // not a handshake record
            else
                let recordLen = (int buffer[offset + 3] <<< 8) ||| int buffer[offset + 4]
                let bodyStart = offset + 5
                let bodyEnd = min (bodyStart + recordLen) length
                if bodyStart >= bodyEnd then bail <- true
                elif int buffer[bodyStart] <> 0x01 then bail <- true          // not a ClientHello
                elif bodyStart + 4 > bodyEnd then bail <- true                // truncated header
                else
                    let msgLen = (int buffer[bodyStart + 1] <<< 16) ||| (int buffer[bodyStart + 2] <<< 8) ||| int buffer[bodyStart + 3]
                    let msgEnd = min (bodyStart + 4 + msgLen) bodyEnd
                    if bodyStart + 4 >= msgEnd then bail <- true              // truncated body
                    else
                        hello <- Array.sub buffer (bodyStart + 4) (msgEnd - (bodyStart + 4))
                        offset <- bodyEnd                                     // unused after hello found

        if bail || isNull hello then null
        else
        // ClientHello body: version(2) random(32) session_id(1+n)
        // suites(2+n) compression(1+n) extensions(2+n)
        let helloLen = hello.Length
        let mutable p = 34
        let mutable failed = false
        let mutable result: string = null

        if p >= helloLen then failed <- true                                  // truncated before session id
        elif not (TlsSni.Skip(hello, &p, int hello[p], 1)) then failed <- true  // session id: 1-byte length
        elif p + 2 > helloLen then failed <- true
        elif not (TlsSni.Skip(hello, &p, (int hello[p] <<< 8) ||| int hello[p + 1], 2)) then failed <- true  // cipher suites
        elif p + 1 > helloLen then failed <- true
        elif not (TlsSni.Skip(hello, &p, int hello[p], 1)) then failed <- true  // compression methods
        elif p + 2 > helloLen then failed <- true
        else
            let extensionsEnd = min (p + 2 + ((int hello[p] <<< 8) ||| int hello[p + 1])) helloLen
            p <- p + 2
            let mutable stop = false
            while not stop && not failed && isNull result && p + 4 <= extensionsEnd do
                let extType = (int hello[p] <<< 8) ||| int hello[p + 1]
                let extLen = (int hello[p + 2] <<< 8) ||| int hello[p + 3]
                p <- p + 4
                let extEnd = min (p + extLen) extensionsEnd
                if p >= extEnd then stop <- true
                elif extType = 0 then                                          // server_name
                    if p + 2 > extEnd then failed <- true
                    else
                        let listLen = (int hello[p] <<< 8) ||| int hello[p + 1]  // server_name_list length
                        let listEnd = min (p + 2 + listLen) extEnd
                        let q = p + 2
                        if q + 1 > listEnd then failed <- true
                        else
                            let nameType = hello[q]                             // 0 = host_name
                            let q = q + 1
                            if nameType <> 0uy || q + 2 > listEnd then failed <- true
                            else
                                let nameLen = (int hello[q] <<< 8) ||| int hello[q + 1]
                                let q = q + 2
                                if q + nameLen > listEnd || nameLen = 0 then failed <- true
                                else result <- Encoding.ASCII.GetString(hello, q, nameLen)
                else p <- extEnd
        result

    /// <summary>Skips a length-prefixed field; false when it would run past the message.</summary>
    static member private Skip(hello: byte[], p: byref<int>, fieldLen: int, lenWidth: int) =
        if p + lenWidth > hello.Length then false
        else
            p <- p + lenWidth + fieldLen
            p <= hello.Length

// ── HTTP stream decoder ───────────────────────────────────────────

/// <summary>
/// One decoded HTTP message. F# port: this was nested as
/// HttpStreamDecoder.HttpMessage in C#; F# cannot nest types in a class, so
/// it is top-level in this namespace — from C#, AutoScope.Engines.Watch
/// HttpMessage (import the namespace and drop the qualification).
/// </summary>
type HttpMessage() =
    member val FromClient = false with get, set
    member val IsHttp = false with get, set          // parseable HTTP/1.x message
    member val StartLine: string = null with get, set // "POST /v1/x HTTP/1.1" / "HTTP/1.1 200 OK"
    member val MethodOrStatus: string = null with get, set // short grid label: "POST /v1/x" / "200"
    member val Headers = Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) with get
    member val Body: byte[] = null with get, set     // after chunked + content-encoding decode
    member val ContentEncoding: string = null with get, set
    member val Chunked = false with get, set
    member val ContentType: string = null with get, set
    member val Kind: string = null with get, set     // json / text / html / binary / empty / h2

    member this.Display =
        let arrow = if this.FromClient then "→ " else "← "
        let label =
            if this.IsHttp then (if isNull this.MethodOrStatus then "" else this.MethodOrStatus)
            else (if isNull this.Kind then "" else this.Kind)
        let len = if isNull this.Body then 0 else this.Body.Length
        let decoded = if isNull this.ContentEncoding then "" else $"  ({this.ContentEncoding} decoded)"
        $"{arrow}{label}  {TransmissionsCoreInternals.formatBytes (int64 len)}{decoded}"

    member this.HeaderText() =
        let sb = StringBuilder()
        sb.AppendLine(if isNull this.StartLine then "(not HTTP)" else this.StartLine) |> ignore
        for kv in this.Headers do
            sb.Append(kv.Key).Append(": ").AppendLine(kv.Value) |> ignore
        if this.Chunked then sb.AppendLine("(chunked transfer decoded)") |> ignore
        if this.ContentEncoding <> null then sb.AppendLine($"(content-encoding {this.ContentEncoding} decoded)") |> ignore
        sb.ToString()

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
[<AbstractClass; Sealed>]
type HttpStreamDecoder private () =

    /// <summary>Refuse to decode bodies larger than this — the capture
    /// caps a direction at 8 MB wire anyway; this is the belt to that.</summary>
    static let MaxDecodeBytes = 16 * 1024 * 1024

    /// <summary>
    /// Parses a whole direction. A direction that does not start like
    /// HTTP yields a single non-HTTP message carrying the raw bytes, so
    /// the viewer always has something truthful to show.
    /// </summary>
    static member Decode(stream: byte[], fromClient: bool, alpn: string) : ResizeArray<HttpMessage> =
        let messages = ResizeArray<HttpMessage>()
        if isNull stream || stream.Length = 0 then messages
        elif HttpStreamDecoder.IsHttp2(stream, alpn) then
            messages.Add(HttpMessage(FromClient = fromClient, IsHttp = false,
                                     MethodOrStatus = "HTTP/2", Kind = "h2", Body = stream))
            messages
        else
            let mutable pos = 0
            let mutable keepGoing = true
            while keepGoing && pos < stream.Length && messages.Count < 200 do
                // F# port: ParseOne returns HttpMessage option (C# returned
                // null) — the null literal is not a proper value for the
                // F#-defined class.
                match HttpStreamDecoder.ParseOne(stream, &pos, fromClient) with
                | None -> keepGoing <- false
                | Some msg -> messages.Add(msg)

            // Trailing bytes that never formed a complete message: surface
            // them rather than silently dropping them.
            if pos < stream.Length && messages.Count > 0 && messages[messages.Count - 1].IsHttp then
                messages.Add(HttpStreamDecoder.RawMessage(stream[pos..], fromClient, "partial"))
            if messages.Count = 0 then
                messages.Add(HttpStreamDecoder.RawMessage(stream, fromClient, null))
            messages

    static member private ParseOne(stream: byte[], pos: byref<int>, fromClient: bool) : HttpMessage option =
        let headerEnd = TransmissionsCoreInternals.indexOf stream TransmissionsCoreInternals.crlfcrlf pos
        if headerEnd < 0 then None
        else
        let head = Encoding.ASCII.GetString(stream, pos, headerEnd - pos)
        let lines = head.Split("\r\n")
        if lines.Length = 0 || not (TransmissionsCoreInternals.looksLikeHttpStart lines[0]) then None
        else
        let msg = HttpMessage(FromClient = fromClient, IsHttp = true, StartLine = lines[0])
        for line in lines[1..] do
            let colon = line.IndexOf(':')
            if colon > 0 then
                msg.Headers[line[..colon - 1].Trim()] <- line[colon + 1..].Trim()
        msg.MethodOrStatus <- (if fromClient then HttpStreamDecoder.FirstTwoTokens lines[0]
                               else HttpStreamDecoder.FirstToken lines[0])
        msg.ContentType <- (match msg.Headers.TryGetValue("Content-Type") with true, v -> v | _ -> null)

        let bodyStart = headerEnd + 4
        let mutable body: byte[] = Unchecked.defaultof<_>
        let te = HttpStreamDecoder.TryGetHeader(msg, "Transfer-Encoding")
        let cl = HttpStreamDecoder.TryGetHeader(msg, "Content-Length")
        if te <> null && te.Contains("chunked", StringComparison.OrdinalIgnoreCase) then
            msg.Chunked <- true
            let dechunked, consumed = HttpStreamDecoder.Dechunk(stream, bodyStart)
            body <- dechunked
            pos <- consumed
        elif cl <> null then
            match Int32.TryParse cl with
            | true, clVal when clVal >= 0 ->
                if bodyStart + clVal > stream.Length then
                    // Capture cut the body short — show what arrived.
                    body <- stream[bodyStart..]
                    pos <- stream.Length
                else
                    body <- stream[bodyStart..bodyStart + clVal - 1]
                    pos <- bodyStart + clVal
            | _ ->
                // No usable framing information: the rest of the direction
                // is the body (common for truncated captures and
                // connection-close responses).
                body <- stream[bodyStart..]
                pos <- stream.Length
        else
            // No framing information: the rest of the direction is the
            // body (common for truncated captures and connection-close
            // responses).
            body <- stream[bodyStart..]
            pos <- stream.Length

        let ce = HttpStreamDecoder.TryGetHeader(msg, "Content-Encoding")
        if ce <> null && body.Length > 0 then
            let decoded = HttpStreamDecoder.DecodeBody(body, ce)
            if decoded <> null then
                msg.ContentEncoding <- ce
                body <- decoded

        msg.Body <- body
        msg.Kind <- HttpStreamDecoder.ClassifyBody(msg.ContentType, body)
        Some msg

    // ── body decoding ────────────────────────────────────────────────

    static member private DecodeBody(body: byte[], contentEncoding: string) : byte[] =
        if body.Length = 0 || body.Length > MaxDecodeBytes then null
        else
        try
            let ce = contentEncoding.Trim().ToLowerInvariant()
            if ce = "gzip" || ce = "x-gzip" then
                // gzip streams may be concatenated (RFC 1952 §2.2); the
                // .NET decoder stops after the first member, so loop.
                use output = new MemoryStream()
                let mutable offset = 0
                let mutable members = 0
                while offset + 2 <= body.Length && body[offset] = 0x1Fuy && body[offset + 1] = 0x8Buy && members < 64 do
                    use input = new MemoryStream(body, offset, body.Length - offset, false)
                    use gz = new GZipStream(input, CompressionMode.Decompress)
                    gz.CopyTo output
                    offset <- int input.Position
                    members <- members + 1
                if members > 0 then output.ToArray() else null
            elif ce = "br" then
                use input = new MemoryStream(body)
                use br = new BrotliStream(input, CompressionMode.Decompress)
                use output = new MemoryStream()
                br.CopyTo output
                output.ToArray()
            elif ce = "deflate" then
                // "deflate" means zlib (RFC 1950), but half the internet
                // ships raw deflate — try both.
                try
                    use input = new MemoryStream(body)
                    use zlib = new ZLibStream(input, CompressionMode.Decompress)
                    use output = new MemoryStream()
                    zlib.CopyTo output
                    output.ToArray()
                with _ ->
                    use input2 = new MemoryStream(body)
                    use raw = new DeflateStream(input2, CompressionMode.Decompress)
                    use output2 = new MemoryStream()
                    raw.CopyTo output2
                    output2.ToArray()
            else null
        with _ ->
            null // undecodable body: show the compressed bytes, flagged

    /// <summary>Decodes chunked transfer coding; returns the payload and
    /// the stream position after the terminating zero chunk.</summary>
    static member private Dechunk(stream: byte[], start: int) : byte[] * int =
        use output = new MemoryStream()
        let mutable pos = start
        let mutable stop = false
        while not stop && pos < stream.Length do
            let lineEnd = TransmissionsCoreInternals.indexOf stream TransmissionsCoreInternals.crlf pos
            if lineEnd < 0 then stop <- true
            else
                let mutable sizeLine = Encoding.ASCII.GetString(stream, pos, lineEnd - pos)
                let semi = sizeLine.IndexOf(';') // chunk extensions
                if semi >= 0 then sizeLine <- sizeLine[..semi - 1]
                match Int32.TryParse(sizeLine.Trim(),
                                      System.Globalization.NumberStyles.HexNumber,
                                      System.Globalization.CultureInfo.InvariantCulture) with
                | false, _ -> stop <- true // not actually chunked — stop, keep what we have
                | true, size ->
                    pos <- lineEnd + 2
                    if size = 0 then
                        // trailer section ends at a blank line (or the capture end)
                        let trailerEnd = TransmissionsCoreInternals.indexOf stream TransmissionsCoreInternals.crlfcrlf (pos - 2)
                        pos <- (if trailerEnd < 0 then stream.Length else trailerEnd + 4)
                        stop <- true
                    elif pos + size > stream.Length then
                        output.Write(stream, pos, stream.Length - pos)
                        pos <- stream.Length
                        stop <- true // capture cut mid-chunk
                    else
                        output.Write(stream, pos, size)
                        pos <- pos + size + 2 // skip payload + CRLF
        (output.ToArray(), min pos stream.Length)

    // ── classification ───────────────────────────────────────────────

    static member private IsHttp2(stream: byte[], alpn: string) =
        if alpn <> null && alpn.Contains("h2", StringComparison.OrdinalIgnoreCase) then true
        else
            // HTTP/2 connection preface before the first SETTINGS frame
            stream.Length >= 9 + 3 &&
            Encoding.ASCII.GetString(stream, 0, 3) = "PRI" &&
            stream.Length >= 24 &&
            Encoding.ASCII.GetString(stream, 14, 10) = "SM\r\n\r\n"

    static member private ClassifyBody(contentType: string, body: byte[]) : string =
        if isNull body || body.Length = 0 then "empty"
        elif contentType <> null then
            let ct = (contentType.Split(';')[0]).Trim().ToLowerInvariant()
            if ct.Contains("json") then "json"
            elif ct.Contains("html") then "html"
            elif ct.StartsWith("text/") then "text"
            elif ct.Contains("xml") then "xml"
            elif ct.Contains("x-www-form-urlencoded") || ct.Contains("form-data") then "form"
            else "binary"
        else
            // Sniff: mostly printable ASCII → text; leading { or [ → json
            let probe = min body.Length 512
            let mutable printable = 0
            for i = 0 to probe - 1 do
                let b = body[i]
                if b = 9uy || b = 10uy || b = 13uy || (b >= 32uy && b < 127uy) then printable <- printable + 1
            let textish = printable * 100 / probe >= 95
            if textish && body.Length > 0 && (body[0] = byte '{' || body[0] = byte '[') then "json"
            elif textish then "text"
            else "binary"

    static member private RawMessage(data: byte[], fromClient: bool, kind: string) : HttpMessage =
        HttpMessage(FromClient = fromClient,
                    IsHttp = false,
                    MethodOrStatus = (if isNull kind then "raw" else kind),
                    Kind = (if isNull kind then HttpStreamDecoder.ClassifyBody(null, data) else kind),
                    Body = data)

    static member private TryGetHeader(msg: HttpMessage, name: string) : string =
        // Transfer/Content-Encoding can repeat — join, the decoders
        // handle a combined value, and the flag stays honest.
        match msg.Headers.TryGetValue(name) with
        | true, value -> value
        | _ -> null

    static member private FirstToken(line: string) =
        let parts = line.Split(' ')
        if parts.Length > 0 then parts[0] else line

    static member private FirstTwoTokens(line: string) =
        let parts = line.Split(' ')
        if parts.Length >= 2 then $"{parts[0]} {parts[1]}" else line

// ── decrypt result models (C# Core\Models\TlsDecryptResult.cs) ────

// F# port: TlsPlainRecord is declared FIRST because TlsDecryptResult
// references it (F# requires define-before-use; C# order was reversed).

/// <summary>One TLS record after decryption, with plaintext when it decrypted.</summary>
type TlsPlainRecord() =
    member val FromClient = false with get, set
    member val ContentType: string = null with get, set
    member val Decrypted = false with get, set
    member val Note: string = null with get, set
    member val Data: byte[] = null with get, set
    member this.Length = if isNull this.Data then 0L else int64 this.Data.Length

/// <summary>Outcome of decrypting one captured TLS flow.</summary>
type TlsDecryptResult() =
    /// <summary>True when at least one application-data record decrypted.</summary>
    member val Success = false with get, set

    /// <summary>Human-readable status: the reason when not successful.</summary>
    member val Status: string = null with get, set

    member val TlsVersion: string = null with get, set
    member val Sni: string = null with get, set
    member val Alpn: string = null with get, set
    member val CipherSuite: string = null with get, set
    member val Truncated = false with get, set

    member val ClientAppBytes = 0L with get, set
    member val ServerAppBytes = 0L with get, set

    member val Records = ResizeArray<TlsPlainRecord>() with get

    /// <summary>First HTTP/1.x messages parsed from the plaintext, when parseable.</summary>
    member val HttpSummary: string = null with get, set

    member this.HeaderLine =
        let tls = if isNull this.TlsVersion then "?" else this.TlsVersion
        let sni = if isNull this.Sni then "(no SNI)" else this.Sni
        let alpn = if String.IsNullOrEmpty this.Alpn then "" else $" · ALPN {this.Alpn}"
        let cipher = if this.CipherSuite <> null then $" · {this.CipherSuite}" else ""
        $"{tls} · {sni}{alpn}{cipher}"

// ── keylog service ────────────────────────────────────────────────

/// <summary>
/// Reads and tails the NSS-format TLS keylog that instrumented python
/// processes write (SSLKEYLOGFILE → pytrace\sslkeys.log), and owns the
/// file's hygiene: created with a current-user-only ACL, rotated at 5 MB,
/// the rotation leftover deleted at app exit, and a no-keylog flag file
/// that makes the hook stop setting the env var entirely.
///
/// Secrets live in memory only — they are never exported or logged.
/// </summary>
type TlsKeylogService() =

    static let mutable dirOverride: string = null
    static let RotateAtBytes = 5L * 1024L * 1024L

    // client_random (uppercase hex) → label → secret bytes
    let secrets = Dictionary<string, Dictionary<string, byte[]>>(StringComparer.OrdinalIgnoreCase)
    let lockObj = obj()
    let mutable readOffset = 0L
    let mutable fileGeneration = -1L

    let onError = DelegateEvent<Action<string>>()

    /// <summary>Self-test seam: redirects the pytrace dir when set (null in the app).</summary>
    static member DirOverride
        with get () = dirOverride
        and set (v: string) = dirOverride <- v

    // F# port: the C# dir was hardcoded to %LOCALAPPDATA%\AutoScope\pytrace.
    // Engines are app-agnostic — no app names or hardcoded app paths — so
    // the dir is DataRoot\pytrace via WatchConfig.Identity (the identical
    // physical path for the AutoScope app).
    static member Dir =
        if isNull dirOverride then Path.Combine(WatchConfig.Identity.DataRoot, "pytrace")
        else dirOverride

    static member KeylogPath = Path.Combine(TlsKeylogService.Dir, "sslkeys.log")
    static member OldKeylogPath = TlsKeylogService.KeylogPath + ".old"
    static member NoKeylogFlagPath = Path.Combine(TlsKeylogService.Dir, "no-keylog")

    [<CLIEvent>]
    member _.OnError = onError.Publish

    /// <summary>False when the user turned TLS keylogging off (flag file present).</summary>
    static member KeylogEnabled = not (File.Exists TlsKeylogService.NoKeylogFlagPath)

    /// <summary>Creates the keylog file with a current-user-only ACL if absent, rotates when oversized.</summary>
    static member EnsureHygiene() =
        try
            Directory.CreateDirectory TlsKeylogService.Dir |> ignore
            if not (File.Exists TlsKeylogService.KeylogPath) then
                TlsKeylogService.CreateWithUserOnlyAcl TlsKeylogService.KeylogPath
            elif (FileInfo TlsKeylogService.KeylogPath).Length > RotateAtBytes then
                TlsKeylogService.Rotate()
        with _ ->
            // hygiene is best-effort — decryption simply finds no secrets
            ()

    static member private CreateWithUserOnlyAcl(path: string) =
        (File.Create(path, 4096, FileOptions.None)).Dispose()
        let security = FileSecurity()
        security.SetAccessRuleProtection(true, false) // nothing inherited: current user only
        security.AddAccessRule(FileSystemAccessRule(
                WindowsIdentity.GetCurrent().User,
                FileSystemRights.FullControl, AccessControlType.Allow))
        (FileInfo path).SetAccessControl security

    static member private Rotate() =
        // Children open the log per record (append), so moving it under
        // them is safe; the .old from any previous rotation is dropped.
        File.Delete TlsKeylogService.OldKeylogPath
        File.Move(TlsKeylogService.KeylogPath, TlsKeylogService.OldKeylogPath)
        TlsKeylogService.CreateWithUserOnlyAcl TlsKeylogService.KeylogPath

    /// <summary>App-exit cleanup — call from MainWindow.OnClosed.</summary>
    static member CleanupAtExit() =
        try File.Delete TlsKeylogService.OldKeylogPath with _ -> ()

    /// <summary>
    /// Turns keylogging off for future instrumented launches: wipes the
    /// log and drops the flag file the hook checks before user code runs.
    /// </summary>
    static member DisableKeylogging() =
        try
            Directory.CreateDirectory TlsKeylogService.Dir |> ignore
            File.WriteAllText(TlsKeylogService.NoKeylogFlagPath, "TLS keylogging disabled from AutoScope settings")
            File.Delete TlsKeylogService.KeylogPath
        with ex ->
            raise (InvalidOperationException($"Could not disable keylogging: {ex.Message}", ex))

    /// <summary>Re-enables keylogging (removes the flag, recreates the ACL'd log).</summary>
    static member EnableKeylogging() =
        try
            File.Delete TlsKeylogService.NoKeylogFlagPath
            TlsKeylogService.EnsureHygiene()
        with ex ->
            raise (InvalidOperationException($"Could not enable keylogging: {ex.Message}", ex))

    /// <summary>Parses any new lines appended since the last call.</summary>
    member _.Refresh() =
        try
            let fi = FileInfo TlsKeylogService.KeylogPath
            if not fi.Exists then
                lock lockObj (fun () ->
                    secrets.Clear()
                    readOffset <- 0L
                    fileGeneration <- -1L)
            else
                let generation = fi.CreationTimeUtc.Ticks ^^^ fi.Length
                let rotated = generation <> fileGeneration && fileGeneration <> -1L
                let offset = if rotated then 0L else readOffset
                if not rotated && fi.Length <= offset then ()
                else
                use fs = new FileStream(TlsKeylogService.KeylogPath, FileMode.Open, FileAccess.Read,
                                        FileShare.ReadWrite ||| FileShare.Delete)
                fs.Seek(offset, SeekOrigin.Begin) |> ignore
                use reader = new StreamReader(fs)

                let parsed = ResizeArray<string * string * byte[]>(16)
                let mutable line = reader.ReadLine()
                while not (isNull line) do
                    match TlsKeylogService.ParseLine line with
                    | Some entry -> parsed.Add entry
                    | None -> ()
                    line <- reader.ReadLine()

                lock lockObj (fun () ->
                    for (randomHex, label, secret) in parsed do
                        match secrets.TryGetValue randomHex with
                        | true, labels -> labels[label] <- secret
                        | _ ->
                            let labels = Dictionary<string, byte[]>(8, StringComparer.Ordinal)
                            labels[label] <- secret
                            secrets[randomHex] <- labels
                    readOffset <- fs.Position
                    fileGeneration <- generation)
        with
        | :? IOException -> ()
        // mid-append read; the next Refresh retries from the last good offset
        | ex ->
            onError.Trigger [| box $"TLS keylog read failed: {ex.Message}" |]

    /// <summary>
    /// NSS keylog line: "LABEL client_random_hex secret_hex". TLS 1.2 uses
    /// CLIENT_RANDOM; TLS 1.3 logs the handshake/application traffic
    /// secrets per direction (plus _N successors after KeyUpdate).
    /// </summary>
    static member private ParseLine(line: string) : (string * string * byte[]) option =
        if String.IsNullOrWhiteSpace line || line.StartsWith("#") then None
        else
            let parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            if parts.Length <> 3 || parts[1].Length % 2 <> 0 || parts[2].Length % 2 <> 0 then None
            else
                let labelOk =
                    match parts[0] with
                    | "CLIENT_RANDOM"
                    | "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
                    | "SERVER_HANDSHAKE_TRAFFIC_SECRET"
                    | "CLIENT_TRAFFIC_SECRET_0"
                    | "SERVER_TRAFFIC_SECRET_0" -> true
                    | _ -> false // EXPORTER_* and KeyUpdate successors are not needed for decryption
                if not labelOk then None
                else
                    try
                        let secret = TlsKeylogService.HexToBytes parts[2]
                        if secret.Length < 16 then None
                        else Some(parts[1].ToUpperInvariant(), parts[0], secret)
                    with _ -> None

    /// <summary>All secrets logged for the given 32-byte client random, keyed by label.</summary>
    member _.GetSecrets(clientRandom: byte[]) : IReadOnlyDictionary<string, byte[]> =
        let key = TlsKeylogService.BytesToHex clientRandom
        lock lockObj (fun () ->
            match secrets.TryGetValue key with
            | true, labels -> Dictionary<string, byte[]>(labels, StringComparer.Ordinal) :> IReadOnlyDictionary<string, byte[]>
            | _ -> Unchecked.defaultof<_>)

    member _.SessionCount =
        lock lockObj (fun () -> secrets.Count)

    static member internal HexToBytes(hex: string) : byte[] =
        let bytes = Array.zeroCreate<byte> (hex.Length / 2)
        for i = 0 to bytes.Length - 1 do
            bytes[i] <- Convert.ToByte(hex.Substring(i * 2, 2), 16)
        bytes

    static member internal BytesToHex(bytes: byte[]) : string =
        let sb = Text.StringBuilder(bytes.Length * 2)
        for b in bytes do sb.Append(b.ToString("X2")) |> ignore
        sb.ToString()

// ── decryptor ─────────────────────────────────────────────────────

open TlsDecryptorInternals

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
[<AbstractClass; Sealed>]
type TlsDecryptor private () =

    // -----------------------------------------------------------------------
    // Cipher suites
    // -----------------------------------------------------------------------

    static let suites: Dictionary<uint16, SuiteInfo> =
        let list =
            [ // TLS 1.3
              SuiteInfo(Id = 0x1301us, Name = "TLS_AES_128_GCM_SHA256",        KeyLen = 16, FixedIvLen = 12, MacLen = 0, Aead = "t13gcm",    Hash = HashAlgorithmName.SHA256)
              SuiteInfo(Id = 0x1302us, Name = "TLS_AES_256_GCM_SHA384",        KeyLen = 32, FixedIvLen = 12, MacLen = 0, Aead = "t13gcm",    Hash = HashAlgorithmName.SHA384)
              SuiteInfo(Id = 0x1303us, Name = "TLS_CHACHA20_POLY1305_SHA256",  KeyLen = 32, FixedIvLen = 12, MacLen = 0, Aead = "t13chacha", Hash = HashAlgorithmName.SHA256)
              // TLS 1.2 AEAD
              SuiteInfo(Id = 0xC02Fus, Name = "ECDHE_RSA_AES_128_GCM_SHA256",   KeyLen = 16, FixedIvLen = 4,  MacLen = 0, Aead = "gcm",     Hash = HashAlgorithmName.SHA256)
              SuiteInfo(Id = 0xC030us, Name = "ECDHE_RSA_AES_256_GCM_SHA384",   KeyLen = 32, FixedIvLen = 4,  MacLen = 0, Aead = "gcm",     Hash = HashAlgorithmName.SHA384)
              SuiteInfo(Id = 0xC02Bus, Name = "ECDHE_ECDSA_AES_128_GCM_SHA256", KeyLen = 16, FixedIvLen = 4,  MacLen = 0, Aead = "gcm",     Hash = HashAlgorithmName.SHA256)
              SuiteInfo(Id = 0xC02Cus, Name = "ECDHE_ECDSA_AES_256_GCM_SHA384", KeyLen = 32, FixedIvLen = 4,  MacLen = 0, Aead = "gcm",     Hash = HashAlgorithmName.SHA384)
              SuiteInfo(Id = 0x009Cus, Name = "RSA_AES_128_GCM_SHA256",         KeyLen = 16, FixedIvLen = 4,  MacLen = 0, Aead = "gcm",     Hash = HashAlgorithmName.SHA256)
              SuiteInfo(Id = 0x009Dus, Name = "RSA_AES_256_GCM_SHA384",         KeyLen = 32, FixedIvLen = 4,  MacLen = 0, Aead = "gcm",     Hash = HashAlgorithmName.SHA384)
              SuiteInfo(Id = 0xCCA8us, Name = "ECDHE_RSA_CHACHA20_POLY1305",    KeyLen = 32, FixedIvLen = 12, MacLen = 0, Aead = "chacha",  Hash = HashAlgorithmName.SHA256)
              SuiteInfo(Id = 0xCCA9us, Name = "ECDHE_ECDSA_CHACHA20_POLY1305",  KeyLen = 32, FixedIvLen = 12, MacLen = 0, Aead = "chacha",  Hash = HashAlgorithmName.SHA256)
              // TLS 1.2 CBC (MAC stripped but not verified — flagged per record)
              SuiteInfo(Id = 0xC027us, Name = "ECDHE_RSA_AES_128_CBC_SHA",      KeyLen = 16, FixedIvLen = 16, MacLen = 20, Aead = "cbc",    Hash = HashAlgorithmName.SHA256)
              SuiteInfo(Id = 0xC014us, Name = "ECDHE_RSA_AES_256_CBC_SHA",      KeyLen = 32, FixedIvLen = 16, MacLen = 20, Aead = "cbc",    Hash = HashAlgorithmName.SHA256)
              SuiteInfo(Id = 0x003Cus, Name = "RSA_AES_128_CBC_SHA256",         KeyLen = 16, FixedIvLen = 16, MacLen = 32, Aead = "cbc",    Hash = HashAlgorithmName.SHA256)
              SuiteInfo(Id = 0x003Dus, Name = "RSA_AES_256_CBC_SHA256",         KeyLen = 32, FixedIvLen = 16, MacLen = 32, Aead = "cbc",    Hash = HashAlgorithmName.SHA256) ]
        let dict = Dictionary<uint16, SuiteInfo>()
        for s in list do dict[s.Id] <- s
        dict

    // -----------------------------------------------------------------------
    // Public entry point
    // -----------------------------------------------------------------------

    static member Decrypt(flow: TcpFlowRecord, keylog: TlsKeylogService) : TlsDecryptResult =
        let result = TlsDecryptResult(Truncated = flow.Truncated)

        let clientRecords = TlsDecryptor.ParseRecords flow.ClientData
        let serverRecords = TlsDecryptor.ParseRecords flow.ServerData
        if flow.Truncated then result.Status <- "Capture truncated mid-stream — some records may be missing."

        match TlsDecryptor.ParseClientHello clientRecords with
        | None ->
            result.Status <- "No TLS handshake found in this flow."
            result
        | Some hello ->
            let serverHello = TlsDecryptor.ParseServerHello serverRecords
            let suiteId =
                match serverHello with
                | Some sh -> sh.SuiteId
                | None ->
                    // F# port: C# OfferedSuites.FirstOrDefault(Suites.ContainsKey) —
                    // 0 (no suite) when nothing offered is supported.
                    match Array.tryFind suites.ContainsKey hello.OfferedSuites with
                    | Some s -> s
                    | None -> 0us
            let suiteOpt =
                if suiteId = 0us then None
                else match suites.TryGetValue suiteId with true, s -> Some s | _ -> None
            match suiteOpt with
            | None ->
                result.Status <- $"Unsupported cipher suite 0x{suiteId:X4}."
                result
            | Some suite ->
                result.Sni <- hello.Sni
                result.Alpn <- hello.Alpn
                result.CipherSuite <- suite.Name

                let secrets = keylog.GetSecrets hello.ClientRandom
                if isNull (box secrets) || secrets.Count = 0 then
                    result.Status <-
                        if TlsKeylogService.KeylogEnabled then
                            "Not instrumented — no TLS secrets logged for this session (install the hook in this python's environment)."
                        else
                            "TLS keylogging is disabled in settings."
                    result
                else
                    let tls13 =
                        match serverHello with
                        | Some sh -> sh.IsTls13
                        | None -> secrets.ContainsKey("CLIENT_HANDSHAKE_TRAFFIC_SECRET")
                    result.TlsVersion <- if tls13 then "TLS 1.3" else "TLS 1.2"

                    if tls13 then TlsDecryptor.DecryptTls13(result, clientRecords, serverRecords, secrets, suite)
                    else TlsDecryptor.DecryptTls12(result, clientRecords, serverRecords, secrets, suite)

                    result.Success <- result.Records |> Seq.exists (fun r -> r.Decrypted && r.ContentType = "application_data")
                    if result.Success then
                        result.Status <- $"{Seq.length (result.Records |> Seq.filter (fun r -> r.Decrypted))} record(s) decrypted"
                    elif String.IsNullOrEmpty result.Status || result.Status.StartsWith("Capture truncated") then
                        result.Status <- "Undecryptable (incomplete capture or missing secret)."

                    result.HttpSummary <- TlsDecryptor.SummarizeHttp result
                    result

    // -----------------------------------------------------------------------
    // TLS record parsing
    // -----------------------------------------------------------------------

    /// <summary>
    /// Splits a byte stream into TLS records. With head+tail retention the
    /// stream can contain a gap; parsing resynchronizes on the next
    /// plausible header instead of losing the tail.
    /// </summary>
    static member private ParseRecords(stream: byte[]) : ResizeArray<TlsRecord> =
        let records = ResizeArray<TlsRecord>()
        if isNull stream || stream.Length < 5 then records
        else
            let mutable pos = 0
            while pos + 5 <= stream.Length do
                let typ = stream[pos]
                let version = uint16 ((int stream[pos + 1] <<< 8) ||| int stream[pos + 2])
                let length = (int stream[pos + 3] <<< 8) ||| int stream[pos + 4]

                let plausible =
                    typ >= 20uy && typ <= 24uy &&
                    (int version >>> 8) = 0x03 && (int version &&& 0xFF) <= 0x04 &&
                    length > 0 && length <= 0x4200
                if not plausible || pos + 5 + length > stream.Length then
                    pos <- pos + 1 // resync scan
                else
                    let payload = Array.sub stream (pos + 5) length
                    records.Add(TlsRecord(Type = typ, Version = version, Payload = payload))
                    pos <- pos + 5 + length
            records

    // -----------------------------------------------------------------------
    // Handshake message parsing
    // -----------------------------------------------------------------------

    static member private ParseClientHello(records: ResizeArray<TlsRecord>) : ClientHelloInfo option =
        records
        |> Seq.filter (fun r -> r.Type = 22uy)
        |> Seq.tryPick (fun record ->
            match TlsDecryptor.HandshakeBody(record.Payload, 1uy) with // handshake type 1 = ClientHello
            | null -> None
            | body ->
                let info = ClientHelloInfo()
                let reader = ByteReader(body)
                reader.Skip 2                          // client_version
                info.ClientRandom <- reader.Take 32    // always at a fixed offset
                let sessionIdLen = int (reader.Take8())
                reader.Skip sessionIdLen
                let suitesLen = int (reader.Take16())
                let suitesMut = ResizeArray<uint16>()
                let mutable i = 0
                while i + 1 < suitesLen do
                    suitesMut.Add(reader.Take16())
                    i <- i + 2
                info.OfferedSuites <- Seq.toArray suitesMut
                let compLen = int (reader.Take8())
                reader.Skip compLen
                info.OfferedTls13 <-
                    TlsDecryptor.ParseExtensions(reader, fun extType ->
                        if extType = 43us then
                            let listLen = int (reader.Take8())
                            let mutable found13 = false
                            let mutable i = 0
                            while not found13 && i + 1 < listLen do
                                if reader.Take16() = 0x0304us then found13 <- true
                                else i <- i + 2
                            found13
                        else
                            if extType = 0us then
                                let listLen = int (reader.Take16())
                                let entryType = int (reader.Take8()) // (kept for shape parity)
                                let nameLen = int (reader.Take16())
                                info.Sni <- Encoding.ASCII.GetString(reader.Take(nameLen))
                                entryType |> ignore
                            elif extType = 16us then
                                let listLen = int (reader.Take16())
                                let protocols = ResizeArray<string>()
                                let mutable consumed = 0
                                while consumed < listLen do
                                    let protoLen = int (reader.Take8())
                                    protocols.Add(Encoding.ASCII.GetString(reader.Take(protoLen)))
                                    consumed <- consumed + 1 + protoLen
                                info.Alpn <- String.Join(", ", protocols)
                            false)
                Some info)

    static member private ParseServerHello(records: ResizeArray<TlsRecord>) : ServerHelloInfo option =
        records
        |> Seq.filter (fun r -> r.Type = 22uy)
        |> Seq.tryPick (fun record ->
            match TlsDecryptor.HandshakeBody(record.Payload, 2uy) with // handshake type 2 = ServerHello
            | null -> None
            | body ->
                let info = ServerHelloInfo()
                let reader = ByteReader(body)
                let version = reader.Take16()
                reader.Skip 32                        // random
                let sessionIdLen = int (reader.Take8())
                reader.Skip sessionIdLen
                info.SuiteId <- reader.Take16()
                reader.Skip 1                         // compression
                TlsDecryptor.ParseExtensions(reader, fun extType ->
                    if extType = 43us then            // supported_versions: the real one
                        info.IsTls13 <- reader.Take16() = 0x0304us
                    false) |> ignore
                if version = 0x0304us then info.IsTls13 <- true
                Some info)

    /// <summary>Returns the handshake body when the record starts with the wanted type.</summary>
    static member private HandshakeBody(payload: byte[], wantedType: byte) : byte[] =
        if payload.Length < 4 || payload[0] <> wantedType then null
        else
            let length = (int payload[1] <<< 16) ||| (int payload[2] <<< 8) ||| int payload[3]
            if 4 + length > payload.Length then null
            else Array.sub payload 4 length

    /// <summary>
    /// Walks an extension block; the callback may consume the extension
    /// body from the reader (it is given the type first) and returns true
    /// to abort the walk. The walker realigns to each extension's declared
    /// extent afterwards, so a callback that reads too much or too little
    /// cannot desync the following extensions.
    /// </summary>
    static member private ParseExtensions(reader: ByteReader, consume: uint16 -> bool) : bool =
        if not (reader.HasMore 2) then false
        else
            let extBlockLen = int (reader.Take16())
            let mutable consumed = 0
            let mutable abort = false
            while not abort && consumed + 4 <= extBlockLen && reader.HasMore 4 do
                let extType = reader.Take16()
                let extLen = int (reader.Take16())
                let bodyStart = reader.Position
                if consume extType then abort <- true
                else
                    reader.SeekTo(bodyStart + extLen)
                    consumed <- consumed + 4 + extLen
            abort

    // -----------------------------------------------------------------------
    // TLS 1.2
    // -----------------------------------------------------------------------

    static member private DecryptTls12(result: TlsDecryptResult,
                                       clientRecords: ResizeArray<TlsRecord>, serverRecords: ResizeArray<TlsRecord>,
                                       secrets: IReadOnlyDictionary<string, byte[]>, suite: SuiteInfo) =
        match secrets.TryGetValue "CLIENT_RANDOM" with
        | false, _ ->
            result.Status <- "CLIENT_RANDOM secret missing for this session."
        | true, masterSecret ->
            // The key block needs both randoms: client's from the hello we
            // parsed, server's from the ServerHello's fixed offset.
            let clientRandom =
                clientRecords
                |> Seq.filter (fun r -> r.Type = 22uy)
                |> Seq.tryPick (fun r -> match TlsDecryptor.HandshakeBody(r.Payload, 1uy) with
                                         | null -> None
                                         | _ -> Some (TlsDecryptor.ExtractRandom r.Payload))
                |> Option.defaultValue null
            let serverRandom =
                serverRecords
                |> Seq.filter (fun r -> r.Type = 22uy)
                |> Seq.tryPick (fun r -> match TlsDecryptor.HandshakeBody(r.Payload, 2uy) with
                                         | null -> None
                                         | _ -> Some (TlsDecryptor.ExtractRandom r.Payload))
                |> Option.defaultValue null
            if isNull clientRandom || isNull serverRandom then
                result.Status <- "Incomplete handshake capture (a hello is missing)."
            else
                let blockLen = suite.MacLen * 2 + suite.KeyLen * 2 + suite.FixedIvLen * 2
                let keyBlock = prf12 masterSecret "key expansion" (Array.append serverRandom clientRandom) blockLen suite.Hash

                let clientHalf, serverHalf = TlsDecryptor.SplitKeyBlock(keyBlock, suite)
                TlsDecryptor.DecryptDirection12(result, clientRecords, clientHalf, suite, true)
                TlsDecryptor.DecryptDirection12(result, serverRecords, serverHalf, suite, false)

    static member private ExtractRandom(handshakePayload: byte[]) : byte[] =
        // handshake header(4) + version(2) then the 32-byte random
        Array.sub handshakePayload 6 32

    static member private SplitKeyBlock(block: byte[], suite: SuiteInfo) : KeyHalf * KeyHalf =
        // RFC 5246 §6.3 key_block layout — grouped by kind, not per side:
        // [client MAC][server MAC][client key][server key][client IV][server IV]
        // F# port: the C# local function Take(len) closed over a mutable
        // cursor; F# closures cannot capture mutable locals, so the cursor
        // is a ref cell — same cuts, same order.
        let pos = ref 0
        let take (len: int) =
            let part = Array.sub block !pos len
            pos := !pos + len
            part
        let clientMac = take suite.MacLen
        let serverMac = take suite.MacLen
        let clientKey = take suite.KeyLen
        let serverKey = take suite.KeyLen
        let clientIv = take suite.FixedIvLen
        let serverIv = take suite.FixedIvLen
        (KeyHalf(MacKey = clientMac, EncKey = clientKey, FixedIv = clientIv, MacLen = suite.MacLen),
         KeyHalf(MacKey = serverMac, EncKey = serverKey, FixedIv = serverIv, MacLen = suite.MacLen))

    static member private DecryptDirection12(result: TlsDecryptResult, records: ResizeArray<TlsRecord>, keys: KeyHalf,
                                             suite: SuiteInfo, fromClient: bool) =
        // Per-direction record sequence for the AEAD AAD. RFC 5246 §6.1:
        // the counter resets when a new connection state becomes active
        // (ChangeCipherSpec). The CCS record itself is not counted — the
        // first encrypted record (the Finished) is sequence 0.
        let mutable seq = 0L
        let mutable ccsSeen = false // app data only becomes encrypted after ChangeCipherSpec

        for record in records do
            let recordSeq = seq
            match record.Type with
            | 20uy ->
                ccsSeen <- true
                seq <- -1L // the following record restarts at zero
                TlsDecryptor.AddPlaintext(result, fromClient, "change_cipher_spec", record.Payload)
            | 22uy when not ccsSeen ->
                TlsDecryptor.AddPlaintext(result, fromClient, "handshake", record.Payload)
            | 23uy when ccsSeen ->
                TlsDecryptor.DecryptAppRecord12(result, record, keys, suite, fromClient, recordSeq)
            | 21uy ->
                TlsDecryptor.AddPlaintext(result, fromClient, "alert", record.Payload)
            | _ -> ()
            seq <- seq + 1L

    /// <summary>Decrypts one TLS 1.2 application_data record with the direction's key half.</summary>
    static member private DecryptAppRecord12(result: TlsDecryptResult, record: TlsRecord, keys: KeyHalf,
                                             suite: SuiteInfo, fromClient: bool, seq: int64) =
        let plaintext =
            match suite.Aead with
            | "gcm" -> TlsDecryptor.DecryptGcm12(keys, record, seq)
            | "chacha" -> TlsDecryptor.DecryptChaCha12(keys, record, seq)
            | "cbc" -> TlsDecryptor.DecryptCbc12(keys, record)
            | _ -> null

        if plaintext <> null then
            TlsDecryptor.AddPlaintext(result, fromClient, "application_data", plaintext)
            if suite.Aead = "cbc" then
                result.Records[result.Records.Count - 1].Note <- "CBC record — padding valid, MAC not verified"
        else
            result.Records.Add(TlsPlainRecord(FromClient = fromClient,
                                              ContentType = "application_data",
                                              Decrypted = false,
                                              Note = "undecryptable (incomplete capture or missing secret)"))

    /// <summary>TLS 1.2 GCM: explicit nonce (8) ‖ ciphertext ‖ tag; implicit IV from the key block.</summary>
    static member private DecryptGcm12(keys: KeyHalf, record: TlsRecord, seq: int64) : byte[] =
        if record.Payload.Length < 8 + 16 then null
        else
            let nonce = Array.zeroCreate<byte> (4 + 8)
            Array.Copy(keys.FixedIv, 0, nonce, 0, 4)
            Array.Copy(record.Payload, 0, nonce, 4, 8)

            // AAD length is the plaintext fragment length (RFC 5288 §3):
            // total minus explicit nonce minus AEAD tag.
            let plainLen = record.Payload.Length - 8 - 16
            let aad = Array.zeroCreate<byte> 13
            for i = 0 to 7 do aad[i] <- byte (seq >>> (8 * (7 - i)))
            aad[8] <- record.Type
            aad[9] <- byte (int record.Version >>> 8)
            aad[10] <- byte (int record.Version &&& 0xFF)
            aad[11] <- byte (plainLen >>> 8)
            aad[12] <- byte (plainLen &&& 0xFF)

            TlsDecryptor.AeadDecrypt("gcm", keys.EncKey, nonce, record.Payload[8..], aad)

    /// <summary>
    /// TLS 1.2 ChaCha20-Poly1305 (RFC 7905): nonce = 4 zero bytes ‖ seq.
    /// The static-IV-XOR-seq variant is tried as a fallback — the AEAD tag
    /// makes a wrong construction fail safely rather than mis-decrypt.
    /// </summary>
    static member private DecryptChaCha12(keys: KeyHalf, record: TlsRecord, seq: int64) : byte[] =
        let nonce = Array.zeroCreate<byte> 12
        for i = 0 to 7 do nonce[11 - i] <- byte (seq >>> (8 * i))

        let plainLen = record.Payload.Length - 16 // AAD wants the plaintext length (tag excluded)
        let aad = Array.zeroCreate<byte> 13
        for i = 0 to 7 do aad[i] <- byte (seq >>> (8 * (7 - i)))
        aad[8] <- record.Type
        aad[9] <- byte (int record.Version >>> 8)
        aad[10] <- byte (int record.Version &&& 0xFF)
        aad[11] <- byte (plainLen >>> 8)
        aad[12] <- byte (plainLen &&& 0xFF)

        let plain = TlsDecryptor.AeadDecrypt("chacha", keys.EncKey, nonce, record.Payload, aad)
        if plain <> null then plain
        else
            let xorNonce = TlsDecryptor.Nonce13(keys.FixedIv, seq)
            TlsDecryptor.AeadDecrypt("chacha", keys.EncKey, xorNonce, record.Payload, aad)

    /// <summary>
    /// TLS 1.2 CBC: payload = IV ‖ encrypted; padding stripped per RFC
    /// 5246. The trailing MAC is removed but NOT verified (record-level
    /// sequence tracking across a possibly-resynchronized stream makes the
    /// MAC input unreliable) — records carry a note saying so.
    /// </summary>
    static member private DecryptCbc12(keys: KeyHalf, record: TlsRecord) : byte[] =
        let payload = record.Payload
        if payload.Length < 32 + keys.MacLen then null
        else
            let result =
                try
                    use aes = Aes.Create()
                    aes.Key <- keys.EncKey
                    aes.Mode <- CipherMode.CBC
                    aes.Padding <- PaddingMode.None

                    let iv = payload[..15]
                    let encrypted = payload[16..]
                    use decryptor = aes.CreateDecryptor()
                    Some (decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length))
                with _ ->
                    None
            match result with
            | None -> null
            | Some decrypted ->
                let padLen = int decrypted[decrypted.Length - 1]
                if padLen >= decrypted.Length then null
                else
                    // Sanity per RFC 5246: every padding byte equals the length
                    let mutable paddingOk = true
                    for i = decrypted.Length - padLen - 1 to decrypted.Length - 2 do
                        if int decrypted[i] <> padLen then paddingOk <- false
                    if not paddingOk then null
                    else
                        let contentLen = decrypted.Length - padLen - 1 - keys.MacLen
                        if contentLen > 0 then decrypted[..contentLen - 1] else null

    // -----------------------------------------------------------------------
    // TLS 1.3
    // -----------------------------------------------------------------------

    static member private DecryptTls13(result: TlsDecryptResult,
                                       clientRecords: ResizeArray<TlsRecord>, serverRecords: ResizeArray<TlsRecord>,
                                       secrets: IReadOnlyDictionary<string, byte[]>, suite: SuiteInfo) =
        let client = TlsDecryptor.BuildDirection13(secrets, "CLIENT", suite)
        let server = TlsDecryptor.BuildDirection13(secrets, "SERVER", suite)
        if isNull (box client) || isNull (box server) then
            result.Status <- "TLS 1.3 traffic secrets missing for this session."
        else
            // Records interleave across directions; process both in stream
            // order per direction — sequence numbers are per-direction anyway.
            TlsDecryptor.DecryptDirection13(result, clientRecords, client, suite, true)
            TlsDecryptor.DecryptDirection13(result, serverRecords, server, suite, false)

    static member private BuildDirection13(secrets: IReadOnlyDictionary<string, byte[]>, side: string, suite: SuiteInfo) : Direction13 =
        let handshakeSecret =
            match secrets.TryGetValue($"{side}_HANDSHAKE_TRAFFIC_SECRET") with true, v -> v | _ -> null
        let appSecret =
            match secrets.TryGetValue($"{side}_TRAFFIC_SECRET_0") with true, v -> v | _ -> null
        if isNull handshakeSecret && isNull appSecret then Unchecked.defaultof<_>
        else
            let dir = Direction13(HandshakeSecret = handshakeSecret, AppSecret = appSecret)
            if handshakeSecret <> null then
                dir.HandshakeKey <- expandLabel handshakeSecret "key" suite.KeyLen suite.Hash
                dir.HandshakeIv <- expandLabel handshakeSecret "iv" 12 suite.Hash
            if appSecret <> null then
                dir.AppKey <- expandLabel appSecret "key" suite.KeyLen suite.Hash
                dir.AppIv <- expandLabel appSecret "iv" 12 suite.Hash
            dir

    static member private DecryptDirection13(result: TlsDecryptResult, records: ResizeArray<TlsRecord>, dir: Direction13,
                                             suite: SuiteInfo, fromClient: bool) =
        // Early handshake records (the hello itself) are plaintext; from the
        // first encrypted record on, try app key first, then handshake key.
        let mutable seenEncrypted = false

        for record in records do
            if record.Type = 22uy && not seenEncrypted then
                TlsDecryptor.AddPlaintext(result, fromClient, "handshake", record.Payload)
            elif record.Type <> 23uy && record.Type <> 22uy then ()
            else
                seenEncrypted <- true
                let plaintext = TlsDecryptor.TryDecrypt13(record, dir, suite)

                if plaintext = null then
                    result.Records.Add(TlsPlainRecord(FromClient = fromClient,
                                                      ContentType = TlsDecryptor.ContentType13 record.Type,
                                                      Decrypted = false,
                                                      Note = (if dir.AfterKeyUpdate then "undecrypted after key update"
                                                              else "undecryptable (missing secret or incomplete capture)")))
                else
                    let innerType = if plaintext.Length > 0 then plaintext[plaintext.Length - 1] else 0uy
                    // F# port: the C# trimmed zero padding by re-slicing the
                    // array on every pass; same bytes kept with an index and
                    // one final slice.
                    let mutable hi = plaintext.Length - 1
                    while hi > 0 && plaintext[hi - 1] = 0uy do hi <- hi - 1 // zero padding
                    let content = if hi <= 0 then Array.empty else plaintext[0..hi - 1]

                    if innerType = 24uy then
                        TlsDecryptor.AddPlaintext(result, fromClient, "key_update", content)
                        if dir.AppSecret <> null then dir.RollKeyUpdate(suite.Hash, suite.KeyLen)
                    else
                        match innerType with
                        | 23uy -> TlsDecryptor.AddPlaintext(result, fromClient, "application_data", content)
                        | 22uy ->
                            for msg in TlsDecryptor.SplitHandshakeMessages content do
                                TlsDecryptor.AddPlaintext(result, fromClient, TlsDecryptor.HandshakeName msg[0], msg)
                        | 21uy -> TlsDecryptor.AddPlaintext(result, fromClient, "alert", content)
                        | t -> TlsDecryptor.AddPlaintext(result, fromClient, $"content {t}", content)

    /// <summary>Attempts app then handshake keys; advances the winning key's sequence.</summary>
    static member private TryDecrypt13(record: TlsRecord, dir: Direction13, suite: SuiteInfo) : byte[] =
        if dir.AppKey <> null then
            let nonce = TlsDecryptor.Nonce13(dir.AppIv, dir.AppSeq)
            let plain = TlsDecryptor.AeadDecrypt(suite.Aead, dir.AppKey, nonce, record.Payload, TlsDecryptor.AeadHeader13 record)
            if plain <> null then
                dir.AppSeq <- dir.AppSeq + 1L
                plain
            else TlsDecryptor.TryDecrypt13Handshake(record, dir, suite)
        else TlsDecryptor.TryDecrypt13Handshake(record, dir, suite)

    // F# port: C# inlined the handshake-key attempt in the same method's
    // tail; a small helper keeps the F# control flow (no early return
    // between the two attempts) equivalent.
    static member private TryDecrypt13Handshake(record: TlsRecord, dir: Direction13, suite: SuiteInfo) : byte[] =
        if dir.HandshakeKey <> null then
            let nonce = TlsDecryptor.Nonce13(dir.HandshakeIv, dir.HandshakeSeq)
            let plain = TlsDecryptor.AeadDecrypt(suite.Aead, dir.HandshakeKey, nonce, record.Payload, TlsDecryptor.AeadHeader13 record)
            if plain <> null then
                dir.HandshakeSeq <- dir.HandshakeSeq + 1L
                plain
            else null
        else null

    static member private Nonce13(staticIv: byte[], seq: int64) : byte[] =
        let nonce = (staticIv.Clone() :?> byte[])
        for i = 0 to 7 do
            let idx = nonce.Length - 1 - i
            nonce[idx] <- nonce[idx] ^^^ byte (seq >>> (8 * i))
        nonce

    static member private AeadHeader13(record: TlsRecord) : byte[] =
        // opaque_type(1)=record.Type, legacy_version(2)=0x0303, length(2)
        [| record.Type; 0x03uy; 0x03uy
           byte (record.Payload.Length >>> 8); byte (record.Payload.Length &&& 0xFF) |]

    // -----------------------------------------------------------------------
    // AEAD primitives — in-box crypto, tag failure = null (never a guess).
    // TLS 1.2 and 1.3 share the constructions; only the nonce/AAD wiring
    // (done by the callers) differs.
    // -----------------------------------------------------------------------

    static member private AeadDecrypt(kind: string, key: byte[], nonce: byte[], payload: byte[], aad: byte[]) : byte[] =
        if payload.Length < 16 then null
        else
            let ciphertext = payload[..payload.Length - 17]
            let tag = payload[payload.Length - 16..]
            let plaintext = Array.zeroCreate<byte> ciphertext.Length
            try
                match kind with
                | "gcm"
                | "t13gcm" ->
                    use aes = new AesGcm(key, 16)
                    aes.Decrypt(nonce, ciphertext, tag, plaintext, aad)
                    plaintext
                | "chacha"
                | "t13chacha" ->
                    use chacha = new ChaCha20Poly1305(key)
                    chacha.Decrypt(nonce, ciphertext, tag, plaintext, aad)
                    plaintext
                | _ -> null
            with
            | :? CryptographicException -> null // AEAD tag mismatch — wrong key/nonce/secret
            | _ -> null

    static member private SplitHandshakeMessages(content: byte[]) : ResizeArray<byte[]> =
        let messages = ResizeArray<byte[]>()
        let mutable pos = 0
        let mutable stop = false
        while not stop && pos + 4 <= content.Length do
            let length = (int content[pos + 1] <<< 16) ||| (int content[pos + 2] <<< 8) ||| int content[pos + 3]
            if pos + 4 + length > content.Length then stop <- true // C# `yield break`
            else
                messages.Add(content[pos..pos + 3 + length])
                pos <- pos + 4 + length
        messages

    static member private HandshakeName(typ: byte) : string =
        match typ with
        | 1uy -> "client_hello"
        | 2uy -> "server_hello"
        | 4uy -> "new_session_ticket"
        | 8uy -> "encrypted_extensions"
        | 11uy -> "certificate"
        | 13uy -> "certificate_request"
        | 14uy -> "finished"
        | 15uy -> "certificate_url"
        | 20uy -> "finished" // (never 20; kept exhaustive)
        | t -> $"handshake {t}"

    static member private ContentType13(typ: byte) : string =
        match typ with
        | 20uy -> "change_cipher_spec"
        | 21uy -> "alert"
        | 22uy -> "handshake"
        | 23uy -> "application_data"
        | t -> $"content {t}"

    static member private AddPlaintext(result: TlsDecryptResult, fromClient: bool, typ: string, data: byte[]) =
        result.Records.Add(TlsPlainRecord(FromClient = fromClient, ContentType = typ, Decrypted = true, Data = data))
        if typ = "application_data" then
            if fromClient then result.ClientAppBytes <- result.ClientAppBytes + int64 data.Length
            else result.ServerAppBytes <- result.ServerAppBytes + int64 data.Length

    // -----------------------------------------------------------------------
    // HTTP/1.x summary
    // -----------------------------------------------------------------------

    static member private SummarizeHttp(result: TlsDecryptResult) : string =
        let clientBytes = TlsDecryptor.ConcatRecords(result, true)
        let serverBytes = TlsDecryptor.ConcatRecords(result, false)
        if clientBytes.Length = 0 && serverBytes.Length = 0 then null
        else
            let sb = Text.StringBuilder()
            TlsDecryptor.AppendHttpMessages(sb, "→ request", clientBytes)
            TlsDecryptor.AppendHttpMessages(sb, "← response", serverBytes)
            (if sb.Length > 0 then sb.ToString() else null)

    static member private ConcatRecords(result: TlsDecryptResult, fromClient: bool) : byte[] =
        let parts =
            result.Records
            |> Seq.filter (fun r -> r.Decrypted && r.ContentType = "application_data" && r.FromClient = fromClient)
            |> Seq.map (fun r -> r.Data)
            |> Seq.toList
        let total = parts |> List.sumBy (fun p -> int64 p.Length)
        if total = 0L || total > 4L * 1024L * 1024L then Array.empty
        else
            let buffer = Array.zeroCreate<byte> (int total)
            let mutable offset = 0
            for part in parts do
                Array.Copy(part, 0, buffer, offset, part.Length)
                offset <- offset + part.Length
            buffer

    static member private AppendHttpMessages(sb: Text.StringBuilder, label: string, stream: byte[]) =
        let mutable shown = 0
        let mutable pos = 0
        let mutable keepGoing = true
        while keepGoing && shown < 3 && pos < stream.Length do
            let headerEnd = TransmissionsCoreInternals.indexOf stream TransmissionsCoreInternals.crlfcrlf pos
            if headerEnd < 0 then keepGoing <- false
            else
                let head = Encoding.ASCII.GetString(stream[pos..headerEnd - 1])
                let lines = head.Split("\r\n")
                if lines.Length = 0 || not (TransmissionsCoreInternals.looksLikeHttpStart lines[0]) then
                    // binary or chunked continuation — stop summarizing
                    keepGoing <- false
                else
                    sb.Append(label).Append(": ").Append(lines[0]).AppendLine() |> ignore
                    for line in lines[1..] do
                        if TlsDecryptor.HeaderOfInterest line then
                            sb.Append("    ").Append(line.TrimEnd()).AppendLine() |> ignore
                    shown <- shown + 1

                    let contentLength = TlsDecryptor.FindContentLength lines
                    pos <- (if contentLength >= 0 then headerEnd + 4 + contentLength else stream.Length)

    static member private HeaderOfInterest(line: string) =
        [ "Host:"; "User-Agent:"; "Content-Type:"; "Content-Length:"; "Server:"; "Location:" ]
        |> List.exists (fun name -> line.StartsWith(name, StringComparison.OrdinalIgnoreCase))

    static member private FindContentLength(lines: string[]) : int =
        lines
        |> Array.tryPick (fun line ->
            if line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase) then
                let rest = line[line.IndexOf(':') + 1..].Trim()
                match Int32.TryParse rest with
                | true, len -> Some len
                | _ -> None
            else None)
        |> Option.defaultValue -1
