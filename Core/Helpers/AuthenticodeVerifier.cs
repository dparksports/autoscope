using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace AutoScope.Helpers
{
    /// <summary>
    /// Native Authenticode verification via WinVerifyTrust — used to validate
    /// downloaded third-party tools (e.g. Sysinternals sigcheck64.exe) before
    /// the app will execute them.
    /// </summary>
    public static class AuthenticodeVerifier
    {
        // WINTRUST_ACTION_GENERIC_VERIFY_V2
        private static readonly Guid GenericVerifyV2 = new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

        private const uint WTD_UI_NONE = 2;
        private const uint WTD_REVOKE_NONE = 0;
        private const uint WTD_CHOICE_FILE = 1;
        private const uint WTD_STATEACTION_VERIFY = 1;

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;              // union: WTD_CHOICE_FILE
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            [MarshalAs(UnmanagedType.LPWStr)] public string pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern int WinVerifyTrust(IntPtr hWnd, ref Guid actionId, ref WINTRUST_DATA data);

        /// <summary>
        /// Verifies the embedded Authenticode signature and returns the signer subject.
        /// Trusted = the signature chain validates to a root trusted by Windows.
        /// </summary>
        public static (bool Trusted, string Subject, int HResult) Verify(string filePath)
        {
            try
            {
                var fileInfo = new WINTRUST_FILE_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                    pcwszFilePath = filePath,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };

                var data = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice = WTD_CHOICE_FILE,
                    pFile = IntPtr.Zero,
                    dwStateAction = WTD_STATEACTION_VERIFY,
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = null,
                    dwProvFlags = 0,
                    dwUIContext = 0,
                    pSignatureSettings = IntPtr.Zero
                };

                data.pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
                try
                {
                    Marshal.StructureToPtr(fileInfo, data.pFile, false);
                    Guid actionId = GenericVerifyV2;
                    int hr = WinVerifyTrust(IntPtr.Zero, ref actionId, ref data);
                    return (hr == 0, GetSignerSubject(filePath), hr);
                }
                finally
                {
                    Marshal.FreeHGlobal(data.pFile);
                }
            }
            catch (Exception ex)
            {
                return (false, ex.Message, unchecked((int)0x80004005));
            }
        }

        /// <summary>
        /// True only when the file carries a valid Authenticode signature that
        /// chains to a trusted root AND was issued by Microsoft.
        /// </summary>
        public static bool IsMicrosoftSigned(string filePath, out string detail)
        {
            var (trusted, subject, hr) = Verify(filePath);
            detail = $"authenticode trusted={trusted}, hr=0x{hr:X8}, signer='{subject}'";
            return trusted && !string.IsNullOrEmpty(subject)
                   && subject.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static string GetSignerSubject(string filePath)
        {
            // SYSLIB0057: no modern replacement exists for extracting the embedded
            // Authenticode signer from an arbitrary PE — the API still works.
#pragma warning disable SYSLIB0057
            try
            {
                return X509Certificate.CreateFromSignedFile(filePath).Subject;
            }
            catch
            {
                return "(no Authenticode signature)";
            }
#pragma warning restore SYSLIB0057
        }
    }
}
