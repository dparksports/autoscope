namespace AutoScope.Models
{
    public class ScheduledTaskItem
    {
        public string TaskName { get; set; }
        public string TaskPath { get; set; }
        public string State { get; set; }
        public string Action { get; set; }
        public string User { get; set; }
    }

    public class NetworkAdapterItem
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string Status { get; set; }
        public string MacAddress { get; set; }
        public string InterfaceType { get; set; }
        public string DeviceID { get; set; }
    }

    public class FirewallRuleItem : System.ComponentModel.INotifyPropertyChanged
    {
        public string Name { get; set; }
        public string DisplayName { get; set; }
        public string DisplayGroup { get; set; }
        public string Direction { get; set; }
        public string Action { get; set; }
        public string Profile { get; set; }
        public string Program { get; set; }
        public string Protocol { get; set; }
        public string LocalPort { get; set; }
        public string RemotePort { get; set; }
        public string RemoteAddress { get; set; }

        private bool _enabled;
        public bool Enabled
        {
            get => _enabled;
            set
            {
                if (_enabled != value)
                {
                    _enabled = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(EnabledDisplay));
                }
            }
        }

        public string EnabledDisplay => Enabled ? "Yes" : "No";

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(name));
        }
    }

    public class EfiFileResult
    {
        public string Status { get; set; }
        public string Path { get; set; }
        public Microsoft.UI.Xaml.Media.Brush StatusColor { get; set; }
    }

    public class NetworkConnectionItem : System.ComponentModel.INotifyPropertyChanged, IResolvableHost
    {
        public string Protocol { get; set; }
        public string LocalAddress { get; set; }
        public string RemoteAddress { get; set; }
        public string State { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }

        public string RemoteIp => RemoteAddress;

        public string Hostname
        {
            get => RemoteHost;
            set => RemoteHost = value;
        }

        private string _remoteHost;
        public string RemoteHost
        {
            get => _remoteHost;
            set
            {
                if (_remoteHost != value)
                {
                    _remoteHost = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(IsResolved));
                }
            }
        }

        public bool IsResolved => !string.IsNullOrEmpty(_remoteHost) && _remoteHost != RemoteAddress && _remoteHost != "0.0.0.0" && _remoteHost != "::";

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(name));
        }
    }

    public class StartupItem
    {
        public string Name { get; set; }
        public string Value { get; set; }
        public string Location { get; set; }
        public string TargetPath { get; set; }
    }

    public class AppPackageItem
    {
        public string Name { get; set; }

        /// <summary>Exact Appx package name (e.g. Microsoft.Todos) — identity used
        /// for user-added custom bloatware entries, unlike the display Name.</summary>
        public string PackageName { get; set; }
        public string FullName { get; set; }
        public string Version { get; set; }
        public string Publisher { get; set; }
        public string InstallLocation { get; set; }
        public string SignatureStatus { get; set; }
        public string SignerCertificate { get; set; }
        public bool IsSystem { get; set; }
    }
}

