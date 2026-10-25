using System;
using System.Text;

namespace AutoScope.Services
{
    /// <summary>
    /// Minimal, bounds-checked TLS ClientHello SNI reader for the sinkhole
    /// listener. Reads only what attribution needs — the server_name extension
    /// of the first handshake — and never trusts lengths: a malformed or
    /// truncated hello yields null, never a throw.
    /// </summary>
    public static class TlsSni
    {
        /// <summary>
        /// Attempts to read the SNI hostname from the front of a byte buffer
        /// holding the start of a TLS handshake stream (one or more records).
        /// Returns null when the buffer does not yet contain a complete
        /// ClientHello or carries none.
        /// </summary>
        public static string TryReadSni(byte[] buffer, int length)
        {
            if (buffer == null || length < 11) return null;

            // Walk records until the ClientHello handshake message is complete
            int offset = 0;
            byte[] hello = null;
            while (offset + 5 <= length && hello == null)
            {
                if (buffer[offset] != 0x16) return null;          // not a handshake record
                int recordLen = (buffer[offset + 3] << 8) | buffer[offset + 4];
                int bodyStart = offset + 5;
                int bodyEnd = Math.Min(bodyStart + recordLen, length);
                if (bodyStart >= bodyEnd) return null;

                if (buffer[bodyStart] != 0x01) return null;       // not a ClientHello
                if (bodyStart + 4 > bodyEnd) return null;         // truncated header
                int msgLen = (buffer[bodyStart + 1] << 16) | (buffer[bodyStart + 2] << 8) | buffer[bodyStart + 3];
                int msgEnd = Math.Min(bodyStart + 4 + msgLen, bodyEnd);
                if (bodyStart + 4 >= msgEnd) return null;         // truncated body

                hello = new byte[msgEnd - (bodyStart + 4)];
                Buffer.BlockCopy(buffer, bodyStart + 4, hello, 0, hello.Length);
                offset = bodyEnd;                                 // unused after hello found
            }
            if (hello == null) return null;

            // ClientHello body: version(2) random(32) session_id(1+n)
            // suites(2+n) compression(1+n) extensions(2+n)
            int p = 34;
            if (p >= hello.Length) return null;                  // truncated before session id
            if (!Skip(hello, ref p, hello[p], 1)) return null;    // session id: 1-byte length
            if (p + 2 > hello.Length) return null;
            if (!Skip(hello, ref p, (hello[p] << 8) | hello[p + 1], 2)) return null;   // cipher suites
            if (p + 1 > hello.Length) return null;
            if (!Skip(hello, ref p, hello[p], 1)) return null;    // compression methods

            if (p + 2 > hello.Length) return null;
            int extensionsEnd = Math.Min(p + 2 + ((hello[p] << 8) | hello[p + 1]), hello.Length);
            p += 2;
            while (p + 4 <= extensionsEnd)
            {
                int extType = (hello[p] << 8) | hello[p + 1];
                int extLen = (hello[p + 2] << 8) | hello[p + 3];
                p += 4;
                int extEnd = Math.Min(p + extLen, extensionsEnd);
                if (p >= extEnd) break;

                if (extType == 0)                                  // server_name
                {
                    if (p + 2 > extEnd) return null;
                    int listLen = (hello[p] << 8) | hello[p + 1];  // server_name_list length
                    int listEnd = Math.Min(p + 2 + listLen, extEnd);
                    int q = p + 2;
                    if (q + 1 > listEnd) return null;
                    int nameType = hello[q];                       // 0 = host_name
                    q++;
                    if (nameType != 0 || q + 2 > listEnd) return null;
                    int nameLen = (hello[q] << 8) | hello[q + 1];
                    q += 2;
                    if (q + nameLen > listEnd || nameLen == 0) return null;
                    return Encoding.ASCII.GetString(hello, q, nameLen);
                }
                p = extEnd;
            }
            return null;
        }

        /// <summary>Skips a length-prefixed field; false when it would run past the message.</summary>
        private static bool Skip(byte[] hello, ref int p, int fieldLen, int lenWidth)
        {
            if (p + lenWidth > hello.Length) return false;
            p += lenWidth + fieldLen;
            return p <= hello.Length;
        }
    }
}
