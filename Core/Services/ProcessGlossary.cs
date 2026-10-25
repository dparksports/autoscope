namespace AutoScope.Services
{
    /// <summary>
    /// One-line plain-English descriptions for the handful of helper
    /// binaries whose names confuse people ("git-remote-what?"). The
    /// generic mechanism is the spawn chain — "spawned by git.exe" comes
    /// from the Sysmon create-record for every process — so this glossary
    /// only seeds the top offenders; unknown names get the parent line
    /// alone, which is usually enough to read a row.
    /// </summary>
    public static class ProcessGlossary
    {
        /// <summary>
        /// True with a one-line description when <paramref name="nameOrPath"/>
        /// names a known-confusing helper (file name or full path, any case).
        /// </summary>
        public static bool TryDescribe(string nameOrPath, out string description)
        {
            description = null;
            if (string.IsNullOrEmpty(nameOrPath)) return false;
            switch (System.IO.Path.GetFileName(nameOrPath).ToLowerInvariant())
            {
                case "git-remote-https.exe":
                    description = "Git's network helper — spawned by git.exe for every fetch/push over HTTPS";
                    return true;
                case "ssh.exe":
                    description = "SSH client — Git-over-SSH, remote shells and tunnels all run through it";
                    return true;
                case "conhost.exe":
                    description = "Console host — the terminal window behind every command-line app";
                    return true;
                case "msedgewebview2.exe":
                    description = "Embedded browser engine — widgets, Teams views and in-app web content";
                    return true;
                case "runtimebroker.exe":
                    description = "Windows activation broker — launches Store apps' sessions on demand";
                    return true;
                case "werfault.exe":
                    description = "Windows Error Reporting — the crash handler that fires when something dies";
                    return true;
            }
            return false;
        }
    }
}
