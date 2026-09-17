using System.Text.Json.Serialization;

namespace PTor
{
    // Source-generated JSON metadata for the NativeAOT uninstaller
    // (Uninstall\PTor.Uninstall.csproj compiles this file in too).
    //
    // NativeAOT has no runtime code generation, so reflection-based
    // JsonSerializer.Serialize<T>/Deserialize<T> would throw at runtime.
    // These [JsonSerializable] entries generate the metadata at compile
    // time instead. The main app uses the same context so both sides
    // read/write byte-identical JSON (default options, same as before).
    //
    // When adding a new state type persisted as JSON, add it here AND
    // use PtorJsonContext.Default.<Type> at the call site — never the
    // generic Serialize<T>/Deserialize<T> overloads in shared files.
    [JsonSerializable(typeof(CheckpointData))]
    [JsonSerializable(typeof(SystemProxyManager.ManagedState))]
    [JsonSerializable(typeof(UserEnvManager.EnvState))]
    internal partial class PtorJsonContext : JsonSerializerContext
    {
    }
}
