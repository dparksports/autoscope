using System.Linq;

namespace SvchostAnalyzer.Core;

/// <summary>
/// The identity tokens of a svchost.exe command line. A line like
/// "svchost.exe -k netsvcs -p -s WpnService" means: drawn from the netsvcs
/// service group (-k — a compatibility pool dozens of instances share),
/// launched under per-service isolation (-p), hosting exactly one service
/// (-s — the actual identity). The SCM's PID→service map is the ground
/// truth; -s is self-identification that must corroborate it.
/// </summary>
public sealed record SvchostIdentity(string Group, string DeclaredService)
{
    public static readonly SvchostIdentity None = new(null, null);

    /// <summary>
    /// Extracts -k/-s from a svchost command line. Quoting-aware token
    /// walk; a value that is itself a flag (or end of line) reads as null.
    /// </summary>
    public static SvchostIdentity Parse(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return None;
        string group = null, declared = null;
        var tokens = Tokenize(commandLine);
        for (int i = 0; i < tokens.Count; i++)
        {
            if (!tokens[i].StartsWith('-')) continue;
            string value = i + 1 < tokens.Count && !tokens[i + 1].StartsWith('-')
                ? tokens[i + 1] : null;
            if (tokens[i].Equals("-k", StringComparison.OrdinalIgnoreCase)) group = value;
            else if (tokens[i].Equals("-s", StringComparison.OrdinalIgnoreCase)) declared = value;
        }
        return group == null && declared == null ? None : new SvchostIdentity(group, declared);
    }

    /// <summary>
    /// True when the command line's -s service is NOT among the SCM-resident
    /// services for the same PID — a genuine isolated svchost always matches;
    /// a mismatch (or an unmatchable claim) is a masquerade signal. Empty
    /// inputs never mismatch: there is nothing to corroborate.
    ///
    /// Per-user services (LPS) instantiate under a suffixed name — the
    /// command line hosts "-s CDPUserSvc" while the SCM registers
    /// "CDPUserSvc_56ec2" — so "template_" prefixed names count as matches.
    /// </summary>
    public static bool Mismatches(string declaredService, string scmServicesCsv)
    {
        if (string.IsNullOrEmpty(declaredService) || string.IsNullOrEmpty(scmServicesCsv))
            return false;
        foreach (string hosted in scmServicesCsv.Split(','))
        {
            string name = hosted.Trim();
            if (name.Length == 0) continue;
            if (name.Equals(declaredService, StringComparison.OrdinalIgnoreCase)) return false;
            if (name.StartsWith(declaredService + "_", StringComparison.OrdinalIgnoreCase)) return false;
        }
        return true;
    }

    /// <summary>Splits on whitespace outside double quotes (svchost never quotes its flags).</summary>
    private static List<string> Tokenize(string s)
    {
        var tokens = new List<string>();
        var sb = new System.Text.StringBuilder();
        bool inQuotes = false;
        foreach (char c in s)
        {
            if (c == '"') { inQuotes = !inQuotes; continue; }
            if (char.IsWhiteSpace(c) && !inQuotes)
            {
                if (sb.Length > 0) { tokens.Add(sb.ToString()); sb.Clear(); }
            }
            else sb.Append(c);
        }
        if (sb.Length > 0) tokens.Add(sb.ToString());
        return tokens;
    }
}
