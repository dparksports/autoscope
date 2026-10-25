using System.Net;
using System.Net.Sockets;

namespace AutoScope.Services
{
    /// <summary>
    /// IP ownership classification against session-verified ranges.
    /// Used by the block-rule guardrails and the Blocked Rules manager so the
    /// UI can warn BEFORE a user blocks infrastructure Windows depends on.
    /// Note: SvchostTraceView keeps its own copy of this table for trace
    /// analysis; if the ranges change, update both (extract-to-library is the
    /// eventual fix).
    /// </summary>
    public static class IpClassifier
    {
        private static readonly (string Name, string[] Cidrs)[] Ranges =
        {
            ("Microsoft/Azure", new[] { "20.0.0.0/8", "40.0.0.0/8", "13.64.0.0/11", "13.104.0.0/14",
                                        "52.96.0.0/12", "52.112.0.0/14", "65.52.0.0/14", "72.145.32.0/19", "172.176.0.0/12" }),
            ("Akamai (MS CDN)", new[] { "23.32.0.0/11", "23.192.0.0/11", "2.16.0.0/13", "95.100.0.0/15", "184.24.0.0/13", "104.64.0.0/10" }),
            ("Gcore (MS CDN)",  new[] { "92.223.0.0/16" }),
        };

        public static string Classify(string ip)
        {
            if (!IPAddress.TryParse(ip, out var addr) || addr.AddressFamily != AddressFamily.InterNetwork)
                return "IPv6/other";
            uint v = ToUint(addr);
            foreach (var (name, cidrs) in Ranges)
                foreach (var cidr in cidrs)
                {
                    var parts = cidr.Split('/');
                    uint net = ToUint(IPAddress.Parse(parts[0]));
                    uint mask = uint.MaxValue << (32 - int.Parse(parts[1]));
                    if ((v & mask) == (net & mask)) return name;
                }
            return "Unclassified";
        }

        /// <summary>True when a block on this IP risks breaking Windows features.</summary>
        public static bool IsMicrosoftInfra(string ip) => Classify(ip) != "Unclassified" && Classify(ip) != "IPv6/other";

        /// <summary>Impact warning for the confirm dialog; empty when unclassified.</summary>
        public static string WarningText(string ip)
        {
            string c = Classify(ip);
            return c switch
            {
                "Microsoft/Azure" => $"⚠ {ip} belongs to Microsoft (Azure/M365 core).\n" +
                                     "Endpoints in these ranges carry Windows Update, Defender signatures,\n" +
                                     "push notifications (WNS) and Microsoft-account sign-in.\n" +
                                     "Blocking it can break updates, notifications or login — usually NOT what you want.",
                "Akamai (MS CDN)" => $"⚠ {ip} is an Akamai edge — a Microsoft CDN partner that delivers\n" +
                                     "Windows Update and Store content. Blocking it can break updates.",
                "Gcore (MS CDN)"  => $"⚠ {ip} is a Gcore edge — a Microsoft CDN partner for update delivery.\n" +
                                     "Blocking it can break updates.",
                _ => ""
            };
        }

        private static uint ToUint(IPAddress a)
        {
            var b = a.GetAddressBytes();
            return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
        }
    }
}
