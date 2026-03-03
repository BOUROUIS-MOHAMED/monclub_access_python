namespace MonClubAccessUpdater;

public sealed class SimpleLogger
{
    private readonly string? _file;

    public SimpleLogger(string? filePath)
    {
        _file = string.IsNullOrWhiteSpace(filePath) ? null : filePath;
        if (_file != null)
        {
            var dir = Path.GetDirectoryName(_file);
            if (!string.IsNullOrWhiteSpace(dir)) Directory.CreateDirectory(dir);
        }
    }

    public void Info(string msg) => Write("INFO", msg);
    public void Warn(string msg) => Write("WARN", msg);
    public void Error(string msg) => Write("ERROR", msg);

    private void Write(string level, string msg)
    {
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {msg}";
        try { Console.WriteLine(line); } catch { /* ignore */ }

        if (_file != null)
        {
            try
            {
                File.AppendAllText(_file, line + Environment.NewLine);
            }
            catch
            {
                // ignore logging failures
            }
        }
    }
}
