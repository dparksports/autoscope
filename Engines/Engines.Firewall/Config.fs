namespace AutoScope.Engines.Firewall

open System.Collections.Generic
open System.IO
open System.Text.Json

/// <summary>
/// Persists firewall rule override state to JSON.
/// Ported from DeviceMonitorCS.
/// F# port: the C# Instance singleton and parameterless constructor are gone —
/// an instance is created with the app's dataRoot, and the hardcoded
/// C:\ProgramData\AutoScope path now routes under it.
/// </summary>
type ConfigManager(dataRoot: string) =

    // F# port: was Path.Combine(@"C:\ProgramData\AutoScope", "firewall_config.json")
    // (hardcoded) — the config file now routes under the injected dataRoot.
    let configPath = Path.Combine(dataRoot, "firewall_config.json")
    let mutable ruleOverrides = Dictionary<string, string>()

    let load () : unit =
        try
            if File.Exists(configPath) then
                let json = File.ReadAllText(configPath)
                match JsonSerializer.Deserialize<Dictionary<string, string>>(json) with
                | null -> ()
                | data -> ruleOverrides <- data
        with _ -> ()

    let save () : unit =
        try
            let dir = Path.GetDirectoryName(configPath)
            if dir <> null && not (Directory.Exists(dir)) then Directory.CreateDirectory(dir) |> ignore
            let json = JsonSerializer.Serialize(ruleOverrides, JsonSerializerOptions(WriteIndented = true))
            File.WriteAllText(configPath, json)
        with _ -> ()

    do load () // C# constructor called Load()

    member _.RuleOverrides
        with get (): Dictionary<string, string> = ruleOverrides
        and set (value: Dictionary<string, string>) = ruleOverrides <- value

    member _.Load() : unit = load ()

    member _.Save() : unit = save ()

    member this.SetOverride(ruleName: string, enabled: bool) : unit =
        let state = if enabled then "True" else "False"
        this.RuleOverrides.[ruleName] <- state
        this.Save()

    member _.GetOverride(ruleName: string) : string =
        let mutable value = Unchecked.defaultof<string>
        if ruleOverrides.TryGetValue(ruleName, &value) then value
        else Unchecked.defaultof<string>
