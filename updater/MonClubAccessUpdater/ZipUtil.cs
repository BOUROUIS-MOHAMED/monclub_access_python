using System.IO.Compression;

namespace MonClubDesktopUpdater;

public static class ZipUtil
{
    public static void ExtractZip(string zipPath, string destDir)
    {
        Directory.CreateDirectory(destDir);
        ZipFile.ExtractToDirectory(zipPath, destDir, overwriteFiles: true);
    }

    public static string ResolvePayloadRoot(string extractRoot)
    {
        // Goal: return a folder that should become installRoot\current
        // Must contain MonClubAccess.exe (or at least something recognizable)
        string exeName = "MonClubAccess.exe";

        // 1) If extractRoot\current\MonClubAccess.exe exists => payloadRoot = extractRoot\current
        var rootCurrent = Path.Combine(extractRoot, "current");
        if (File.Exists(Path.Combine(rootCurrent, exeName)))
            return rootCurrent;

        // 2) If extractRoot contains exactly one directory:
        var dirs = Directory.GetDirectories(extractRoot);
        if (dirs.Length == 1)
        {
            var only = dirs[0];

            // 2a) only\current\MonClubAccess.exe
            var onlyCurrent = Path.Combine(only, "current");
            if (File.Exists(Path.Combine(onlyCurrent, exeName)))
                return onlyCurrent;

            // 2b) only\MonClubAccess.exe
            if (File.Exists(Path.Combine(only, exeName)))
                return only;

            // 2c) only is payload root by itself if root has exe inside somewhere shallow
            var found = FindExeParent(only, exeName, maxDepth: 3);
            if (found != null) return found;
        }

        // 3) If extractRoot\MonClubAccess.exe
        if (File.Exists(Path.Combine(extractRoot, exeName)))
            return extractRoot;

        // 4) Search shallow for MonClubAccess.exe
        var parent = FindExeParent(extractRoot, exeName, maxDepth: 4);
        if (parent != null) return parent;

        throw new InvalidOperationException($"Could not locate '{exeName}' inside extracted content.");
    }

    private static string? FindExeParent(string root, string exeName, int maxDepth)
    {
        // BFS-ish shallow search
        var q = new Queue<(string dir, int depth)>();
        q.Enqueue((root, 0));

        while (q.Count > 0)
        {
            var (dir, depth) = q.Dequeue();
            if (File.Exists(Path.Combine(dir, exeName)))
                return dir;

            if (depth >= maxDepth) continue;

            string[] sub;
            try { sub = Directory.GetDirectories(dir); }
            catch { continue; }

            foreach (var s in sub) q.Enqueue((s, depth + 1));
        }

        return null;
    }
}
