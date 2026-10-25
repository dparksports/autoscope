namespace AutoScope.Engines.Core

/// <summary>
/// One recorded connection — the engine-side view of a TransmissionRecord.
/// Engines never see UI models: apps map their own record types into this
/// row at the call site. Immutable by design.
/// </summary>
type TrafficRow =
    { TsUtc: System.DateTime
      Pid: int
      /// full image path where known
      Image: string
      /// process display name, e.g. "chrome.exe"
      Process: string
      RemoteIp: string
      RemotePort: int
      /// TLS server name indication, lowercase where normalized by the app
      Sni: string
      /// wire bytes, reassembled
      ClientBytes: int64
      ServerBytes: int64 }
