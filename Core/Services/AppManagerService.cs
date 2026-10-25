using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32;
using Windows.Management.Deployment;
using AutoScope.Helpers;
using AutoScope.Models;

namespace AutoScope.Services
{
    public class AppManagerService
    {
        private static AppManagerService _instance;
        public static AppManagerService Instance => _instance ??= new AppManagerService();

        /// <summary>
        /// Package name / display-name patterns treated as bloatware. Matched
        /// case-insensitively as substrings against both the package name and the
        /// display name. OneDrive is a Win32 desktop app rather than a Store package,
        /// so it is detected separately (see FindOneDriveAsync).
        /// </summary>
        public static readonly string[] BloatwarePatterns =
        {
            "Outlook",                // Outlook (new Outlook for Windows)
            "Xbox",                   // Xbox app suite
            "Family",                 // Microsoft Family Safety
            "Phone",                  // Phone Link
            "Copilot",                // Copilot
            "WindowsFeedbackHub",     // Feedback Hub
            "GetHelp",                // Get Help
            "BingNews",               // Microsoft News
            "Teams",                  // Teams (MSTeams / MicrosoftTeams)
            "Todos",                  // Microsoft To Do
            "CrossDevice",            // Mobile devices (Cross-Device Experience Host)
            "PowerAutomate",          // Power Automate
            "QuickAssist",            // Quick Assist
            "Solitaire",              // Solitaire & Casual Games
            "WindowsCalendar",        // Windows Calendar
            "WindowsCalculator",      // Calculator
            "WindowsSoundRecorder",   // Sound Recorder
            "WebExperience",          // Windows Web Experience Pack
            "WindowsTerminal",        // Terminal
            "WidgetsPlatformRuntime", // Widgets Platform Runtime
            "DevHome",                // Dev Home (including the retired 0.0.0 stub)
            "RemoteDesktop",          // Remote Desktop Store client (Microsoft.RemoteDesktop).
                                      // Note: the classic inbox mstsc.exe "Remote Desktop
                                      // Connection" is an OS component under System32 — it is
                                      // not a package and cannot be uninstalled.
            "OneDrive",               // Win32 — resolved by FindOneDriveAsync
        };

        /// <summary>
        /// FullName marker for the synthetic OneDrive item. OneDrive is a Win32
        /// desktop app, not a Store package, so it cannot carry a package full name.
        /// </summary>
        public const string OneDriveMarkerFullName = "Win32:Microsoft.OneDrive";

        /// <summary>
        /// The patterns in force: compiled-in defaults minus the user's opt-outs,
        /// plus user-added patterns. Every consumer (view, Fresh Setup, verify
        /// step) must read this so they can never disagree about the list.
        /// </summary>
        public static IEnumerable<string> EffectivePatterns
        {
            get
            {
                var (_, _, customPatterns) = BloatwareConfig.Instance.Snapshot();
                return BloatwarePatterns
                    .Where(p => !IsDefaultDisabled(p))
                    .Concat(customPatterns)
                    .Where(p => !string.IsNullOrWhiteSpace(p));
            }
        }

        /// <summary>True when the user opted out of a compiled-in default pattern.</summary>
        public static bool IsDefaultDisabled(string pattern)
        {
            var (disabled, _, _) = BloatwareConfig.Instance.Snapshot();
            return disabled.Contains(pattern);
        }

        /// <summary>Which part of the effective list a package is matched by.</summary>
        public enum BloatwareMatchSource { None, DefaultPattern, CustomPattern, CustomPackage }

        /// <summary>
        /// Resolves how (or whether) a package is covered by the current bloatware
        /// list, so UI toggles know whether removing it means disabling a default
        /// pattern or dropping a custom entry. matchedPattern receives the pattern
        /// that hit (null for exact-package matches). System-signed packages are
        /// never matched — the removal flow rejects them anyway.
        /// </summary>
        public static BloatwareMatchSource GetMatchSource(string packageName, string displayName, out string matchedPattern)
        {
            matchedPattern = null;
            if (string.IsNullOrWhiteSpace(packageName) && string.IsNullOrWhiteSpace(displayName))
                return BloatwareMatchSource.None;

            packageName ??= "";
            displayName ??= "";

            var (_, customPackages, customPatterns) = BloatwareConfig.Instance.Snapshot();
            foreach (var pattern in EffectivePatterns)
            {
                if (packageName.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
                    displayName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    matchedPattern = pattern;
                    return customPatterns.Contains(pattern)
                        ? BloatwareMatchSource.CustomPattern
                        : BloatwareMatchSource.DefaultPattern;
                }
            }
            if (customPackages.Contains(packageName))
                return BloatwareMatchSource.CustomPackage;

            return BloatwareMatchSource.None;
        }

        /// <summary>
        /// Finds bloatware (AppManagerService.BloatwarePatterns), optionally asks for
        /// confirmation, uninstalls each package, and reports per-package results.
        /// Returns Removed = -1 when the user cancelled the confirmation.
        /// </summary>
        public async Task<(List<AppPackageItem> Matched, int Removed, List<string> Failed)> RemoveBloatwareAsync(
            IProgress<string> progress = null, Func<List<AppPackageItem>, Task<bool>> confirm = null)
        {
            // Effective list = compiled-in defaults minus user opt-outs, plus
            // user-added entries (see BloatwareConfigManager)
            var matched = await FindBloatwareAsync();
            if (matched.Count == 0)
                return (matched, 0, new List<string>());

            if (confirm != null && !await confirm(matched))
                return (matched, -1, new List<string>());

            int removed = 0;
            var failed = new List<string>();
            foreach (var app in matched)
            {
                progress?.Report($"Removing {app.Name}…");
                bool ok = app.FullName == OneDriveMarkerFullName
                    ? await UninstallOneDriveAsync()
                    : await UninstallAppAsync(app.FullName);
                if (ok)
                    removed++;
                else
                    failed.Add(app.Name);
            }
            return (matched, removed, failed);
        }

        /// <summary>
        /// Lists installed apps the way Windows Settings → Apps → Installed apps does:
        /// user-visible main packages (frameworks, resource bundles, partially staged
        /// packages and OS system components are hidden). Set includeSystemComponents
        /// to true to also show System-signed OS components.
        /// </summary>
        public async Task<List<AppPackageItem>> GetInstalledAppsAsync(bool includeSystemComponents = false)
        {
            return await Task.Run(() =>
            {
                var items = new List<AppPackageItem>();
                try
                {
                    var packageManager = new PackageManager();
                    // Empty string targets the current user's packages
                    var packages = packageManager.FindPackagesForUser(string.Empty);

                    foreach (var p in packages)
                    {
                        try
                        {
                            if (p.IsFramework || p.IsResourcePackage) continue;

                            bool isSystem = p.SignatureKind == Windows.ApplicationModel.PackageSignatureKind.System;
                            if (isSystem && !includeSystemComponents) continue;

                            items.Add(MapPackage(p));
                        }
                        catch
                        {
                            // Skip packages whose metadata cannot be read
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"AppManagerService Error: {ex.Message}");
                }

                return items.OrderBy(i => i.Name).ToList();
            });
        }

        /// <summary>
        /// Finds bloatware using the effective list: compiled-in defaults minus
        /// the user's opt-outs, plus user-added patterns and exact packages.
        /// </summary>
        public Task<List<AppPackageItem>> FindBloatwareAsync()
        {
            var (_, customPackages, _) = BloatwareConfig.Instance.Snapshot();
            return FindBloatwareAsync(EffectivePatterns, customPackages);
        }

        /// <summary>
        /// Finds installed packages whose package name or display name contains any of the
        /// given patterns (case-insensitive), or whose package name exactly matches one
        /// of exactPackages — e.g. Outlook, Xbox, Family, Phone.
        /// </summary>
        public async Task<List<AppPackageItem>> FindBloatwareAsync(IEnumerable<string> patterns, IEnumerable<string> exactPackages = null)
        {
            var patternList = patterns?.Where(s => !string.IsNullOrWhiteSpace(s)).ToList() ?? new List<string>();
            var exactSet = new HashSet<string>(
                exactPackages?.Where(s => !string.IsNullOrWhiteSpace(s) ) ?? Enumerable.Empty<string>(),
                StringComparer.OrdinalIgnoreCase);
            if (patternList.Count == 0 && exactSet.Count == 0) return new List<AppPackageItem>();
            return await Task.Run(async () =>
            {
                var matches = new List<AppPackageItem>();
                try
                {
                    var packageManager = new PackageManager();
                    foreach (var p in packageManager.FindPackagesForUser(string.Empty))
                    {
                        try
                        {
                            if (p.IsFramework || p.IsResourcePackage) continue;

                            // System-signed OS components (e.g. XboxGameCallableUI) are
                            // non-removable — never offer them for removal
                            if (p.SignatureKind == Windows.ApplicationModel.PackageSignatureKind.System) continue;

                            string pkgName = p.Id.Name ?? "";
                            string displayName = "";
                            try { displayName = p.DisplayName ?? ""; } catch { }

                            bool hit = exactSet.Contains(pkgName) || patternList.Any(pattern =>
                                pkgName.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
                                displayName.Contains(pattern, StringComparison.OrdinalIgnoreCase));
                            if (!hit) continue;

                            matches.Add(MapPackage(p));
                        }
                        catch
                        {
                            // Skip packages whose metadata cannot be read
                        }
                    }

                    // OneDrive is a Win32 desktop app — PackageManager never lists it,
                    // so detect it separately when its pattern is requested.
                    if (patternList.Any(p => p.Equals("OneDrive", StringComparison.OrdinalIgnoreCase)))
                    {
                        var oneDrive = await FindOneDriveAsync();
                        if (oneDrive != null)
                            matches.Add(oneDrive);
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"FindBloatwareAsync Error: {ex.Message}");
                }

                return matches.OrderBy(i => i.Name).ToList();
            });
        }

        private static AppPackageItem MapPackage(Windows.ApplicationModel.Package p)
        {
            string installPath = "Unknown";
            try { installPath = p.InstalledLocation.Path; } catch { }

            bool isSystem = p.SignatureKind == Windows.ApplicationModel.PackageSignatureKind.System;

            return new AppPackageItem
            {
                Name = string.IsNullOrEmpty(p.DisplayName) ? p.Id.Name : p.DisplayName,
                // Exact package name — what custom user additions match against
                PackageName = p.Id.Name,
                FullName = p.Id.FullName,
                Version = $"{p.Id.Version.Major}.{p.Id.Version.Minor}.{p.Id.Version.Build}.{p.Id.Version.Revision}",
                Publisher = p.Id.Publisher,
                InstallLocation = installPath,
                SignatureStatus = DescribeSignature(p.SignatureKind),
                SignerCertificate = ExtractCommonName(p.Id.Publisher),
                IsSystem = isSystem
            };
        }

        /// <summary>
        /// The deployment engine validates a package's signature at install time, so
        /// SignatureKind is authoritative. (Parsing AppxSignature.p7x directly is not
        /// viable — it's a PKCS#7 blob, not a DER certificate.)
        /// </summary>
        private static string DescribeSignature(Windows.ApplicationModel.PackageSignatureKind kind)
        {
            return kind switch
            {
                Windows.ApplicationModel.PackageSignatureKind.System => "System component",
                Windows.ApplicationModel.PackageSignatureKind.Store => "Valid (Store)",
                Windows.ApplicationModel.PackageSignatureKind.Enterprise => "Valid (Enterprise)",
                Windows.ApplicationModel.PackageSignatureKind.Developer => "Developer-signed",
                _ => "Unsigned"
            };
        }

        /// <summary>
        /// Extracts the CN= component from a package publisher string, e.g.
        /// "CN=Microsoft Corporation, O=Microsoft Corporation, ..." → "Microsoft Corporation".
        /// </summary>
        private static string ExtractCommonName(string publisher)
        {
            if (string.IsNullOrWhiteSpace(publisher)) return "Unknown";
            if (!publisher.StartsWith("CN=")) return publisher;

            string cn = publisher.Substring(3);
            int comma = cn.IndexOf(',');
            if (comma >= 0) cn = cn.Substring(0, comma);
            return cn.Trim().Trim('"');
        }

        /// <summary>
        /// Detects OneDrive, which is a Win32 desktop app installed by OneDriveSetup.exe
        /// rather than a Store package, so it never appears in FindPackagesForUser.
        /// Returns null when OneDrive is not installed.
        /// </summary>
        public Task<AppPackageItem> FindOneDriveAsync()
        {
            return Task.Run(() =>
            {
                // Per-user installs live under %LOCALAPPDATA%\Microsoft\OneDrive;
                // machine-wide installs under %ProgramFiles%\Microsoft OneDrive.
                string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

                string[] roots =
                {
                    System.IO.Path.Combine(localAppData, "Microsoft", "OneDrive"),
                    System.IO.Path.Combine(programFiles, "Microsoft OneDrive"),
                    System.IO.Path.Combine(programFilesX86, "Microsoft OneDrive"),
                };

                string root = roots.FirstOrDefault(System.IO.Directory.Exists);
                if (root == null) return null;

                string version = ReadOneDriveRegistryEntry().Version;
                if (string.IsNullOrEmpty(version))
                {
                    try
                    {
                        version = System.Diagnostics.FileVersionInfo
                            .GetVersionInfo(System.IO.Path.Combine(root, "OneDrive.exe")).FileVersion;
                    }
                    catch { }
                }

                return new AppPackageItem
                {
                    Name = "OneDrive",
                    FullName = OneDriveMarkerFullName,
                    Version = string.IsNullOrEmpty(version) ? "Unknown" : version,
                    Publisher = "Microsoft Corporation",
                    InstallLocation = root,
                    SignatureStatus = "Win32 app (not a Store package)",
                    SignerCertificate = "Microsoft Corporation",
                    IsSystem = false
                };
            });
        }

        /// <summary>
        /// Uninstalls OneDrive through its own uninstaller (OneDriveSetup.exe /uninstall),
        /// falling back to winget. OneDrive is not a Store package, so
        /// PackageManager.RemovePackageAsync cannot remove it.
        /// </summary>
        public async Task<bool> UninstallOneDriveAsync()
        {
            try
            {
                var item = await FindOneDriveAsync();
                if (item == null) return true; // already gone

                // Ask the running sync client to exit cleanly first (best effort — the
                // uninstaller proceeds even if the client is hung or absent)
                try
                {
                    string oneDriveExe = System.IO.Path.Combine(item.InstallLocation, "OneDrive.exe");
                    if (System.IO.File.Exists(oneDriveExe))
                        await Task.Run(() => Helpers.ProcessRunner.Run(oneDriveExe, "/shutdown"))
                                 .WaitAsync(TimeSpan.FromSeconds(10));
                }
                catch { }

                bool success = false;
                string uninstaller = LocateOneDriveUninstaller(item.InstallLocation);
                if (uninstaller != null)
                {
                    var (_, _, exitCode) = await Helpers.ProcessRunner.RunWithDetailsAsync(uninstaller, "/uninstall");
                    success = exitCode == 0;
                }

                if (!success)
                {
                    var (_, _, wingetCode) = await Helpers.ProcessRunner.RunWithDetailsAsync(
                        "winget", "uninstall --id Microsoft.OneDrive --silent --disable-interactivity");
                    success = wingetCode == 0;
                }

                return success && await WaitForOneDriveRemoval(item.InstallLocation);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"UninstallOneDriveAsync Error: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Resolves the OneDrive uninstaller executable: the registered UninstallString
        /// first (it points at the versioned OneDriveSetup.exe), then a scan of the
        /// install root's versioned subfolders.
        /// </summary>
        private static string LocateOneDriveUninstaller(string installRoot)
        {
            string path = ExtractExecutablePath(ReadOneDriveRegistryEntry().UninstallString);
            if (path != null && System.IO.File.Exists(path)) return path;

            try
            {
                return System.IO.Directory.GetDirectories(installRoot)
                    .Select(dir => System.IO.Path.Combine(dir, "OneDriveSetup.exe"))
                    .Where(System.IO.File.Exists)
                    .OrderByDescending(p => System.IO.Path.GetDirectoryName(p), StringComparer.OrdinalIgnoreCase)
                    .FirstOrDefault();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Reads the OneDrive uninstaller registration (UninstallString and
        /// DisplayVersion). Per-user installs register under HKCU; machine-wide
        /// installs under HKLM (64-bit and 32-bit views).
        /// </summary>
        private static (string UninstallString, string Version) ReadOneDriveRegistryEntry()
        {
            const string subKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe";
            (RegistryKey Hive, string Path)[] candidates =
            {
                (Registry.CurrentUser, subKey),
                (Registry.LocalMachine, subKey),
                (Registry.LocalMachine, @"Software\WOW6432Node\" + subKey),
            };

            foreach (var (hive, path) in candidates)
            {
                try
                {
                    using var key = hive.OpenSubKey(path);
                    if (key == null) continue;
                    string uninstall = key.GetValue("UninstallString") as string;
                    string version = key.GetValue("DisplayVersion") as string;
                    if (!string.IsNullOrWhiteSpace(uninstall) || !string.IsNullOrWhiteSpace(version))
                        return (uninstall, version);
                }
                catch
                {
                    // Registry access failures fall through to the directory-based fallback
                }
            }
            return (null, null);
        }

        /// <summary>Extracts the exe path from an UninstallString like "C:\...\OneDriveSetup.exe" /uninstall.</summary>
        private static string ExtractExecutablePath(string uninstallString)
        {
            if (string.IsNullOrWhiteSpace(uninstallString)) return null;
            string value = uninstallString.Trim();
            if (value.StartsWith("\""))
            {
                int endQuote = value.IndexOf('"', 1);
                return endQuote > 0 ? value.Substring(1, endQuote - 1) : null;
            }
            int space = value.IndexOf(' ');
            return space > 0 ? value.Substring(0, space) : value;
        }

        /// <summary>Waits for the OneDrive executable to disappear after an uninstall.</summary>
        private static async Task<bool> WaitForOneDriveRemoval(string installRoot, int timeoutSeconds = 20)
        {
            string oneDriveExe = System.IO.Path.Combine(installRoot, "OneDrive.exe");
            for (int waitedMs = 0; waitedMs < timeoutSeconds * 1000; waitedMs += 500)
            {
                if (!System.IO.File.Exists(oneDriveExe)) return true;
                await Task.Delay(500);
            }
            return !System.IO.File.Exists(oneDriveExe);
        }

        public async Task<bool> UninstallAppAsync(string fullName)
        {
            try
            {
                var packageManager = new PackageManager();
                // Execute the native removal command
                var deploymentOperation = packageManager.RemovePackageAsync(fullName);

                // Await completion natively without spinning up external processes
                var tcs = new TaskCompletionSource<bool>();
                deploymentOperation.Completed = (info, status) =>
                {
                    if (status == Windows.Foundation.AsyncStatus.Completed)
                        tcs.SetResult(true);
                    else
                        tcs.SetResult(false);
                };

                return await tcs.Task;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"UninstallAppAsync Error: {ex.Message}");
                return false;
            }
        }
    }
}
