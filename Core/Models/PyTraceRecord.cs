using System;
using System.Text.Json.Serialization;

namespace AutoScope.Models
{
    /// <summary>
    /// One audit-hook record from an instrumented python process, as written
    /// by the embedded PyTraceHook payload (one JSON line per spawn-API call).
    /// </summary>
    public class PyTraceRecord
    {
        /// <summary>Epoch seconds (time.time() in the child).</summary>
        [JsonPropertyName("ts")]
        public double Ts { get; set; }

        [JsonPropertyName("pid")]
        public int Pid { get; set; }

        /// <summary>Audit event name, e.g. "subprocess.Popen" or "os.system".</summary>
        [JsonPropertyName("event")]
        public string Event { get; set; }

        /// <summary>Repr-safe (truncated) arguments as recorded by the hook.</summary>
        [JsonPropertyName("args")]
        public string[] Args { get; set; }

        /// <summary>Python stack at the moment the spawn API fired.</summary>
        [JsonPropertyName("stack")]
        public string Stack { get; set; }

        [JsonIgnore]
        public DateTime TimeUtc => DateTimeOffset.FromUnixTimeMilliseconds((long)(Ts * 1000)).UtcDateTime;

        [JsonIgnore]
        public string TimeDisplay => TimeUtc.ToLocalTime().ToString("HH:mm:ss.fff");

        /// <summary>Compact one-line header for list rendering.</summary>
        [JsonIgnore]
        public string Header => $"{TimeDisplay}  {Event}  {string.Join(" ", Args ?? Array.Empty<string>())}";
    }
}
