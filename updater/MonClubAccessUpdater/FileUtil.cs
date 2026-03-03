namespace MonClubAccessUpdater;

public static class FileUtil
{
    public static void EnsureDir(string path) => Directory.CreateDirectory(path);

    public static void DeleteDirectorySafe(string path, SimpleLogger? log = null)
    {
        if (!Directory.Exists(path)) return;

        try
        {
            foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                try
                {
                    var fi = new FileInfo(file);
                    fi.Attributes = FileAttributes.Normal;
                }
                catch { /* ignore */ }
            }

            Directory.Delete(path, recursive: true);
        }
        catch (Exception ex)
        {
            log?.Warn($"Failed to delete dir '{path}': {ex.Message}");
        }
    }

    public static void CopyDirectory(string sourceDir, string destDir)
    {
        Directory.CreateDirectory(destDir);

        foreach (var dir in Directory.EnumerateDirectories(sourceDir, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(sourceDir, dir);
            Directory.CreateDirectory(Path.Combine(destDir, rel));
        }

        foreach (var file in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(sourceDir, file);
            var target = Path.Combine(destDir, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: true);
        }
    }

    public static void MoveDirectoryRobust(string sourceDir, string destDir, SimpleLogger log)
    {
        // Try atomic move first.
        try
        {
            Directory.Move(sourceDir, destDir);
            return;
        }
        catch (Exception ex)
        {
            log.Warn($"Directory.Move failed (fallback to copy+delete): {ex.Message}");
        }

        CopyDirectory(sourceDir, destDir);
        DeleteDirectorySafe(sourceDir, log);
    }
}
