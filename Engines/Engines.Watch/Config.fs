namespace AutoScope.Engines.Watch

open AutoScope.Engines.Core

/// <summary>Host configuration for the watch engines: call
/// WatchConfig.configure(identity) once at app startup, before any engine
/// member is touched. Engines are app-agnostic; paths and ports come from
/// the identity.</summary>
[<AbstractClass; Sealed>]
type WatchConfig private () =
    static let mutable identity = Unchecked.defaultof<AppIdentity>
    static let mutable configured = false
    static member Configure(id: AppIdentity) =
        identity <- id
        configured <- true
    static member Identity =
        if not configured then failwith "WatchConfig.Configure(identity) must be called at app startup"
        identity
