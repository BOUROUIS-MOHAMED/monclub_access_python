using System.Text.Json.Serialization;

namespace MonClubAccessUpdater;

public sealed class ReleaseManifest
{
    [JsonPropertyName("releaseId")]
    public string? ReleaseId { get; set; }

    [JsonPropertyName("outputs")]
    public ManifestOutputs? Outputs { get; set; }
}

public sealed class ManifestOutputs
{
    [JsonPropertyName("zipSha256")]
    public string? ZipSha256 { get; set; }
}
