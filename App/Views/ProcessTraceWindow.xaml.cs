using System;
using AutoCommand.Engines.Bridge;
using AutoCommand.Engines.Watch;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Windows.UI;
using AutoScope.Services;

namespace AutoScope.Views
{
    /// <summary>
    /// PID Inquiry — "how was this PID spawned?" for any process visible in
    /// the Process Monitor (row context menu) or typed/picked in the PID
    /// dropdown. Renders the ProvenanceReport collected by
    /// ProcessProvenanceService: verdict, identity, verified ancestry chain,
    /// and corroborating records (Sysmon create-events, shell history,
    /// autostart entries, hosted services).
    /// </summary>
    // WinUI port: WPF Window → Microsoft.UI.Xaml.Window (kept in
    // AutoScope.Views, constructor unchanged). Show()/ShowDialog() →
    // Activate(); Owner/Topmost/WindowState had no equivalent and are gone.
    public partial class ProcessTraceWindow : Window
    {
        private readonly int _pid;
        private readonly string _knownName;
        private readonly string _knownImage;
        private readonly TaskLaunchInfo _taskHint;
        private readonly DateTime? _hintSeenUtc;
        private readonly DateTime? _knownCreatedUtc;
        private ProvenanceReport _report;
        private bool _busy;

        /// <summary>
        /// Raised after each successful collection. The Process Monitor
        /// subscribes so a resolved real name flows back onto the row that
        /// opened the inquiry (trace→row loop) instead of dying with the
        /// window.
        /// </summary>
        public event Action<ProvenanceReport> ReportCollected;

        public ProcessTraceWindow(int pid, string knownName, string knownImagePath, TaskLaunchInfo taskHint,
                                  DateTime? hintSeenUtc = null, DateTime? knownCreatedUtc = null)
        {
            _pid = pid;
            _knownName = knownName;
            _knownImage = knownImagePath;
            _taskHint = taskHint;
            _hintSeenUtc = hintSeenUtc;
            _knownCreatedUtc = knownCreatedUtc;
            InitializeComponent();
            Title = $"PID Inquiry — {pid} {knownName}".TrimEnd();
            // WinUI port: WPF Width=940 Height=700 MinWidth=720 MinHeight=520
            // WindowStartupLocation=CenterOwner → AppWindow.Resize (pixels, so
            // scale the DIP size); WinUI has no per-window minimums
            try
            {
                double scale = Windows.Graphics.Display.DisplayInformation.GetForCurrentView().RawPixelsPerViewPixel;
                AppWindow.Resize(new Windows.Graphics.SizeInt32(
                    (int)(940 * scale), (int)(700 * scale)));
            }
            catch { /* DPI info unavailable — keep the default size */ }
            // WinUI port: Window has no Loaded event — collect once on first
            // activation
            bool collected = false;
            Activated += (_, _) =>
            {
                if (collected) return;
                collected = true;
                _ = CollectAsync();
            };
        }

        private async Task CollectAsync()
        {
            if (_busy) return;
            _busy = true;
            try
            {
                StatusText.Text = "Collecting… (WMI snapshot, parent chain, Sysmon events, shell history)";
                var report = await Task.Run(() =>
                    ProcessProvenanceService.Collect(_pid, _knownName, _knownImage, _taskHint,
                        _hintSeenUtc, _knownCreatedUtc));
                _report = report;
                Render(report);
                ReportCollected?.Invoke(report);
                StatusText.Text = $"Collected in {report.Elapsed.TotalSeconds:F1}s · {DateTime.Now:HH:mm:ss} · " +
                                  "collection is read-only";
            }
            catch (Exception ex)
            {
                StatusText.Text = "Collection failed: " + ex.Message;
            }
            finally
            {
                _busy = false;
            }
        }

        private void Render(ProvenanceReport r)
        {
            Title = $"PID Inquiry — {r.Pid} · {Path.GetFileName(r.ExePath ?? r.Name ?? "?")}";

            VerdictKindText.Text = r.Verdict;
            VerdictDetailText.Text = r.VerdictDetail;
            // WinUI port: ColorConverter.ConvertFromString → Color.FromArgb
            (Color bg, Color fg) = r.Verdict switch
            {
                string v when v.StartsWith("User-launched", StringComparison.Ordinal) => (Color.FromArgb(255, 0x14, 0x35, 0x1F), Color.FromArgb(255, 0x7E, 0xD8, 0xA0)),
                string v when v.StartsWith("Scheduled", StringComparison.Ordinal)    => (Color.FromArgb(255, 0x3A, 0x2E, 0x10), Color.FromArgb(255, 0xFB, 0xBF, 0x24)),
                string v when v.StartsWith("Windows service", StringComparison.Ordinal) => (Color.FromArgb(255, 0x1A, 0x4A, 0x8A), Color.FromArgb(255, 0x7E, 0xB8, 0xF7)),
                _ => (Color.FromArgb(255, 0x3A, 0x15, 0x20), Color.FromArgb(255, 0xF2, 0xA0, 0xB4))
            };
            VerdictBanner.Background = new SolidColorBrush(bg);
            VerdictKindText.Foreground = new SolidColorBrush(fg);
            VerdictDetailText.Foreground = new SolidColorBrush(Color.FromArgb(0xD0, fg.R, fg.G, fg.B));

            IdentName.Text = r.Name ?? "?";
            IdentPid.Text = r.Pid.ToString();
            IdentCreated.Text = r.Created?.ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown";
            IdentOwner.Text = r.Owner ?? "unknown";
            IdentSession.Text = r.Session ?? "?";
            IdentMemory.Text = r.Alive ? r.Memory ?? "—" : "— (not running)";
            IdentImage.Text = r.ExePath;
            // svchost (and other SYSTEM) command lines are unreadable to a
            // standard user — say so instead of showing a blank field
            IdentCmd.Text = r.CommandLine ?? (
                IsSvchostReport(r)
                    ? "— hidden (standard users cannot read SYSTEM svchost lines; rerun elevated to corroborate -k/-s)"
                    : null);

            // Plain-English gloss for names that mean nothing on their own
            // ("git-remote-https.exe") — the chain below shows the raw
            // parentage; this line translates it
            IdentGloss.Text = AutoCommand.Engines.Watch.ProcessGlossary.TryDescribe(r.ExePath ?? r.Name, out string gloss)
                ? "ℹ " + gloss
                : null;

            var rows = new List<ChainRowVm>();
            for (int i = 0; i < r.Chain.Count; i++)
            {
                var link = r.Chain[i];
                rows.Add(new ChainRowVm
                {
                    Arrow = i == 0 ? "▸ this process" : "↑ spawned by",
                    Head = $"PID {link.Pid,-7} {link.Name ?? "?"}   started {link.Created?.ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown"}   {link.Owner ?? ""}",
                    // WinUI port: the WPF DataTrigger on Verified — the
                    // unverified links' pink lives here now
                    HeadForeground = link.Verified
                        ? (Brush)Application.Current.Resources["TextPrimaryBrush"]
                        : new SolidColorBrush(Color.FromArgb(255, 0xF2, 0xA0, 0xB4)),
                    Cmd = link.CommandLine,
                    Note = link.Note,
                    Verified = link.Verified
                });
            }
            ChainList.ItemsSource = rows;

            // WinUI port: the template x:Binds the EvidenceItem records
            // directly (public fields), so the WPF EvidenceRowVm projection —
            // which existed only to keep {Binding} off read-only Run.Text —
            // is not needed
            EvidenceList.ItemsSource = r.Evidence.ToList();

            WarningsText.Text = r.Warnings.Count == 0
                ? null
                : "⚠ " + string.Join("\n⚠ ", r.Warnings);
        }

        /// <summary>True when the report's subject is the svchost service-host image.</summary>
        private static bool IsSvchostReport(ProvenanceReport r) =>
            string.Equals(r.Name, "svchost.exe", StringComparison.OrdinalIgnoreCase) ||
            (r.ExePath?.EndsWith("\\svchost.exe", StringComparison.OrdinalIgnoreCase) ?? false);

        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => _ = CollectAsync();

        private void CopyBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_report == null) return;
            try
            {
                // WinUI port: Clipboard.SetText → DataPackage + SetContent;
                // BuildReportText now lives in AutoScope.Services.TraceText
                var package = new Windows.ApplicationModel.DataTransfer.DataPackage();
                package.SetText(TraceText.BuildReportText(_report));
                Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(package);
                StatusText.Text = "Report copied to clipboard.";
            }
            catch (Exception ex)
            {
                StatusText.Text = "Copy failed: " + ex.Message;
            }
        }

        // WinUI port: the static BuildReportText (the full report text, also
        // shared with the AI-access bridge's run_pid_inquiry tool) moved to
        // AutoScope.Services.TraceText — no local copy here.

        /// <summary>Display row for one ancestry hop.</summary>
        private sealed class ChainRowVm
        {
            public string Arrow { get; set; }
            public string Head { get; set; }
            // WinUI port: foreground for Head — the WPF DataTrigger on
            // Verified, computed in Render since WinUI styles have no triggers
            public Brush HeadForeground { get; set; }
            public string Cmd { get; set; }
            public string Note { get; set; }
            public bool Verified { get; set; } = true;
        }
    }
}
