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

}
