using System.Globalization;

namespace MonClubAccessUpdater;

public sealed class UpdaterArgs
{
    public required string InstallRoot { get; init; }
    public required string ReleaseId { get; init; }
    public required string ZipPath { get; init; }
    public required string ManifestPath { get; init; }
    public required int WaitPid { get; init; }

    public string? LogPath { get; init; }
    public int ForceKillAfterSeconds { get; init; } = 0;

    public static UpdaterArgs Parse(string[] args)
    {
        // Very small parser: expects --key value
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < args.Length; i++)
        {
            var a = (args[i] ?? "").Trim();
            if (!a.StartsWith("--")) continue;

            var key = a.Substring(2);
            string val = "";

            if (i + 1 < args.Length && !(args[i + 1] ?? "").Trim().StartsWith("--"))
            {
                val = (args[i + 1] ?? "").Trim();
                i++;
            }

            map[key] = val;
        }

        string GetReq(string k)
        {
            if (!map.TryGetValue(k, out var v) || string.IsNullOrWhiteSpace(v))
                throw new ArgumentException($"Missing required arg: --{k}");
            return v.Trim();
        }

        string? GetOpt(string k)
        {
            if (!map.TryGetValue(k, out var v)) return null;
            v = (v ?? "").Trim();
            return string.IsNullOrWhiteSpace(v) ? null : v;
        }

        int GetInt(string k, int def = 0)
        {
            var v = GetOpt(k);
            if (string.IsNullOrWhiteSpace(v)) return def;
            if (int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var x)) return x;
            return def;
        }

        return new UpdaterArgs
        {
            InstallRoot = GetReq("installRoot"),
            ReleaseId = GetReq("releaseId"),
            ZipPath = GetReq("zip"),
            ManifestPath = GetReq("manifest"),
            WaitPid = GetInt("waitPid", 0),
            LogPath = GetOpt("log"),
            ForceKillAfterSeconds = GetInt("forceKillAfterSeconds", 0),
        };
    }

    public static string Usage() =>
@"MonClubAccessUpdater.exe ^
  --installRoot ""%LOCALAPPDATA%\MonClubAccess"" ^
  --releaseId ""20260210-124245Z"" ^
  --zip ""...\downloads\windows\stable\MonClubAccess-20260210-124245Z.zip"" ^
  --manifest ""...\downloads\windows\stable\MonClubAccess-20260210-124245Z.manifest.json"" ^
  --waitPid 12345 ^
  [--log ""...\logs\updater-<releaseId>.log""] ^
  [--forceKillAfterSeconds 20]
";
}
