using System.Security.Cryptography;
using System.Text;

namespace MonClubAccessUpdater;

public static class HashUtil
{
    public static string Sha256File(string path)
    {
        using var sha = SHA256.Create();
        using var fs = File.OpenRead(path);

        var hash = sha.ComputeHash(fs);
        var sb = new StringBuilder(hash.Length * 2);
        foreach (var b in hash) sb.Append(b.ToString("x2"));
        return sb.ToString().ToLowerInvariant();
    }
}
