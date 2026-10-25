using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace AutoScope.Services
{
    /// <summary>
    /// Aggregated outcome of applying a firewall profile, for UI progress/summary reporting.
    /// </summary>
    public class ProfileApplyResult
    {
        public string ProfileName { get; set; }
        public List<FirewallService.GroupToggleResult> Groups { get; } = new List<FirewallService.GroupToggleResult>();
        public int TotalMatched { get; set; }
        public int TotalChanged { get; set; }
        public int TotalFailed { get; set; }
        public string FirstError { get; set; }
        public string Notes { get; set; }
    }

    /// <summary>
    /// Firewall profile presets using COM API.
    /// Ported from DeviceMonitorCS — now uses FirewallService instead of PowerShell.
    /// </summary>
    public class FirewallProfileService
    {
        private static FirewallProfileService _instance;
        public static FirewallProfileService Instance => _instance ??= new FirewallProfileService();

        public enum ProfileType
        {
            Custom,
            BlockSharingDiscoveryRemoteDesktop,
            AllowSharingDiscovery,
            AllowDiscoveryCast,
            ShieldsUpMdns,
            AllowSharingDiscoveryRemoteDesktop,
            ShieldsUp
        }

        public async Task<ProfileApplyResult> ApplyProfile(ProfileType profile, IProgress<string> progress = null)
        {
            var result = new ProfileApplyResult { ProfileName = profile.ToString() };

            switch (profile)
            {
                case ProfileType.BlockSharingDiscoveryRemoteDesktop:
                    await Toggle(result, progress, "File and Printer Sharing", false);
                    await Toggle(result, progress, "Network Discovery", false);
                    await Toggle(result, progress, "Remote Desktop", false);
                    break;
                case ProfileType.AllowSharingDiscovery:
                    await Toggle(result, progress, "File and Printer Sharing", true);
                    await Toggle(result, progress, "Network Discovery", true);
                    break;
                case ProfileType.AllowDiscoveryCast:
                    await Toggle(result, progress, "Network Discovery", true);
                    await Toggle(result, progress, "Cast to Device functionality", true);
                    break;
                case ProfileType.ShieldsUpMdns:
                {
                    progress?.Report("Shields Up + mDNS: disabling all grouped rules…");
                    var shield = await ApplyShieldsUpMdns();
                    result.Groups.Add(shield);
                    result.TotalMatched += shield.Matched;
                    result.TotalChanged += shield.Changed;
                    result.TotalFailed += shield.Failed;
                    if (shield.FirstError != null && result.FirstError == null) result.FirstError = shield.FirstError;
                    result.Notes = shield.Notes;
                    break;
                }
                case ProfileType.AllowSharingDiscoveryRemoteDesktop:
                    await Toggle(result, progress, "File and Printer Sharing", true);
                    await Toggle(result, progress, "Network Discovery", true);
                    await Toggle(result, progress, "Remote Desktop", true);
                    break;
                case ProfileType.ShieldsUp:
                {
                    progress?.Report("Shields Up: restoring Windows defaults…");
                    var lockdown = await FirewallService.Instance.ResetToDefaultsAndLockdownAsync(progress);
                    result.Groups.Add(lockdown);
                    result.TotalMatched += lockdown.Matched;
                    result.TotalChanged += lockdown.Changed;
                    result.TotalFailed += lockdown.Failed;
                    if (lockdown.FirstError != null && result.FirstError == null) result.FirstError = lockdown.FirstError;
                    result.Notes = lockdown.Notes;
                    break;
                }
            }

            return result;
        }

        private async Task Toggle(ProfileApplyResult acc, IProgress<string> progress, string group, bool enable)
        {
            progress?.Report($"{(enable ? "Enabling" : "Disabling")} group '{group}'…");
            FirewallService.GroupToggleResult r = enable ? await EnableGroup(group) : await DisableGroup(group);
            acc.Groups.Add(r);
            acc.TotalMatched += r.Matched;
            acc.TotalChanged += r.Changed;
            acc.TotalFailed += r.Failed;
            if (r.FirstError != null && acc.FirstError == null) acc.FirstError = r.FirstError;
        }

        private Task<FirewallService.GroupToggleResult> ApplyShieldsUpMdns()
        {
            // Disable ALL rules, then re-enable whitelisted groups
            return Task.Run(() =>
            {
                var result = new FirewallService.GroupToggleResult { GroupName = "Shields Up + mDNS (block all)" };
                try
                {
                    Type fwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                    dynamic fwPolicy = Activator.CreateInstance(fwPolicyType);
                    int disabledCount = 0;
                    int whitelistEnabled = 0;

                    // Pass 1: Disable everything with a group
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        try
                        {
                            string group = rule.Grouping ?? "";
                            if (string.IsNullOrEmpty(group)) continue;

                            bool wasEnabled = (bool)rule.Enabled;
                            rule.Enabled = false;
                            result.Matched++;
                            if (wasEnabled)
                            {
                                result.Changed++;
                                disabledCount++;
                            }
                        }
                        catch (Exception ex)
                        {
                            result.Failed++;
                            if (result.FirstError == null) result.FirstError = ex.Message;
                        }
                    }

                    // Pass 2: Re-enable whitelisted groups
                    var whitelist = new[] { "mDNS", "Core Networking" };
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        try
                        {
                            string group = rule.Grouping ?? "";
                            if (string.IsNullOrEmpty(group)) continue;
                            string display = FirewallService.ResolveGroupName(group);
                            bool whitelisted = false;
                            foreach (var wl in whitelist)
                            {
                                if (display.Equals(wl, StringComparison.OrdinalIgnoreCase) ||
                                    group.Equals(wl, StringComparison.OrdinalIgnoreCase))
                                {
                                    whitelisted = true;
                                    break;
                                }
                            }
                            if (!whitelisted) continue;

                            bool wasEnabled = (bool)rule.Enabled;
                            rule.Enabled = true;
                            result.Matched++;
                            whitelistEnabled++;
                            if (!wasEnabled) result.Changed++;
                        }
                        catch (Exception ex)
                        {
                            result.Failed++;
                            if (result.FirstError == null) result.FirstError = ex.Message;
                        }
                    }

                    result.Notes = $"{disabledCount} grouped rule(s) disabled, {whitelistEnabled} whitelist rule(s) processed for re-enable";
                }
                catch (Exception ex)
                {
                    result.FailedCompletely = true;
                    result.FirstError = ex.Message;
                }
                return result;
            });
        }

        private Task<FirewallService.GroupToggleResult> EnableGroup(string group)
        {
            return FirewallService.Instance.ToggleGroupAsync(group, true);
        }

        private Task<FirewallService.GroupToggleResult> DisableGroup(string group)
        {
            return FirewallService.Instance.ToggleGroupAsync(group, false);
        }
    }
}
