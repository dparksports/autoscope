using System;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace AutoScope.Converters
{
    /// <summary>
    /// Value converters ported from AutoCommand's WPF FirewallConverters —
    /// WinUI IValueConverter signatures, same colors. (The grouping-only
    /// converters did not port: the toolkit DataGrid has no grouping.)
    /// </summary>
    public class EnabledToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, string language)
        {
            if (value is bool enabled)
            {
                return enabled
                    ? new SolidColorBrush(Color.FromArgb(255, 0x4E, 0xC9, 0x6F))  // AccentGreen
                    : new SolidColorBrush(Color.FromArgb(255, 0x9D, 0x9D, 0xA5)); // TextSecondary
            }
            return new SolidColorBrush(Color.FromArgb(255, 255, 255, 255));
        }

        public object ConvertBack(object value, Type targetType, object parameter, string language)
            => throw new NotImplementedException();
    }

    public class ActionToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, string language)
        {
            if (value is string action)
            {
                return action == "Allow"
                    ? new SolidColorBrush(Color.FromArgb(255, 0x4E, 0xC9, 0x6F))  // Green
                    : new SolidColorBrush(Color.FromArgb(255, 0xE5, 0x53, 0x4B)); // Red
            }
            return new SolidColorBrush(Color.FromArgb(255, 255, 255, 255));
        }

        public object ConvertBack(object value, Type targetType, object parameter, string language)
            => throw new NotImplementedException();
    }

    public class TaskStateToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, string language)
        {
            if (value is string state)
            {
                return state switch
                {
                    "Running" => new SolidColorBrush(Color.FromArgb(255, 0x4E, 0xC9, 0x6F)),   // Green
                    "Ready" => new SolidColorBrush(Color.FromArgb(255, 0x4C, 0x9E, 0xEB)),      // Blue
                    "Disabled" => new SolidColorBrush(Color.FromArgb(255, 0x9D, 0x9D, 0xA5)),   // Gray
                    _ => new SolidColorBrush(Color.FromArgb(255, 0xE5, 0xA6, 0x31))             // Amber
                };
            }
            return new SolidColorBrush(Color.FromArgb(255, 255, 255, 255));
        }

        public object ConvertBack(object value, Type targetType, object parameter, string language)
            => throw new NotImplementedException();
    }

    public class StatusToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, string language)
        {
            string status = value?.ToString()?.ToLower() ?? "";
            if (status.Contains("stopped") || status.Contains("disabled") || status.Contains("off") || status.Contains("not found"))
                return new SolidColorBrush(Color.FromArgb(255, 0x4E, 0xC9, 0x6F)); // Green = secure (stopped is good)
            if (status.Contains("running") || status.Contains("enabled") || status.Contains("on"))
                return new SolidColorBrush(Color.FromArgb(255, 0xE5, 0xA6, 0x31)); // Amber = attention
            return new SolidColorBrush(Color.FromArgb(255, 0x9D, 0x9D, 0xA5)); // Gray
        }

        public object ConvertBack(object value, Type targetType, object parameter, string language)
            => throw new NotImplementedException();
    }

    public class AppNameToDisplayConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, string language)
        {
            string app = value?.ToString();
            if (string.IsNullOrWhiteSpace(app) || app == "Any") return "All Applications";
            return app;
        }

        public object ConvertBack(object value, Type targetType, object parameter, string language)
            => throw new NotImplementedException();
    }
}
