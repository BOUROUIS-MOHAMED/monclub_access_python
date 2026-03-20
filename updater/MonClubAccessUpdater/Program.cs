using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace MonClubDesktopUpdater
{
    internal static class Program
    {
        // Kept for backward-compatible fallback only; installers pass the real component exe name.
        private const string DefaultAppExeName = "MonClubAccess.exe";

        private sealed class Manifest
        {
            public string? app { get; set; }
            public string? releaseId { get; set; }
            public Outputs? outputs { get; set; }

            public sealed class Outputs
            {
                public string? zipSha256 { get; set; }
            }
        }

        private sealed class SimpleLogger
        {
            private readonly string? _filePath;
            private readonly object _lock = new();

            public SimpleLogger(string? filePath)
            {
                _filePath = string.IsNullOrWhiteSpace(filePath) ? null : filePath;
                if (_filePath != null)
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
                }
            }

            public void Info(string msg) => Write("INFO", msg);
            public void Warn(string msg) => Write("WARN", msg);
            public void Error(string msg) => Write("ERROR", msg);

            private void Write(string level, string msg)
            {
                var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {msg}";
                lock (_lock)
                {
                    Console.WriteLine(line);
                    if (_filePath != null)
                    {
                        File.AppendAllText(_filePath, line + Environment.NewLine, Encoding.UTF8);
                    }
                }
            }
        }

        public static int Main(string[] args)
        {
            var parsed = ParseArgs(args);

            string installRoot = Require(parsed, "--installRoot");
            string releaseId   = Require(parsed, "--releaseId");
            string zipPath     = Require(parsed, "--zip");
            string manifestPath= Require(parsed, "--manifest");
            int waitPid        = int.Parse(Require(parsed, "--waitPid"));
            string appExeName  = parsed.TryGetValue("--appExeName", out var appExeValue) && !string.IsNullOrWhiteSpace(appExeValue)
                ? appExeValue
                : DefaultAppExeName;

            string? logPath = parsed.TryGetValue("--log", out var lp) ? lp : null;
            int forceKillAfterSeconds = parsed.TryGetValue("--forceKillAfterSeconds", out var fk)
                ? int.Parse(fk)
                : 0;

            var log = new SimpleLogger(logPath);

            try
            {
                log.Info("Updater started.");
                log.Info($"installRoot={installRoot}");
                log.Info($"releaseId={releaseId}");
                log.Info($"zip={zipPath}");
                log.Info($"manifest={manifestPath}");
                log.Info($"waitPid={waitPid}");
                log.Info($"appExeName={appExeName}");
                log.Info($"forceKillAfterSeconds={forceKillAfterSeconds}");

                // 1) Wait for app pid
                WaitForPidExit(waitPid, forceKillAfterSeconds, log);

                // 2) Extra safety: kill any other target-app processes still running from current\
                string currentDir = Path.Combine(installRoot, "current");
                KillRunningAppFromDir(currentDir, appExeName, log);

                // 3) Validate manifest + zip hash
                var manifest = LoadManifest(manifestPath);
                if (!string.IsNullOrWhiteSpace(manifest.releaseId) &&
                    !string.Equals(manifest.releaseId, releaseId, StringComparison.OrdinalIgnoreCase))
                {
                    throw new Exception($"Manifest releaseId mismatch. manifest={manifest.releaseId} arg={releaseId}");
                }
                var expectedZipSha = manifest.outputs?.zipSha256;
                if (string.IsNullOrWhiteSpace(expectedZipSha))
                {
                    throw new Exception("Manifest missing outputs.zipSha256");
                }

                log.Info("Computing sha256(zip)...");
                var actualZipSha = Sha256File(zipPath);
                log.Info($"sha256(zip)={actualZipSha}");
                if (!string.Equals(actualZipSha, expectedZipSha, StringComparison.OrdinalIgnoreCase))
                {
                    throw new Exception($"ZIP sha256 mismatch. expected={expectedZipSha} actual={actualZipSha}");
                }

                // 4) Extract
                string extractRoot = Path.Combine(Path.GetTempPath(), "MonClubDesktopUpdater", releaseId, Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(extractRoot);

                log.Info($"Extracting zip to: {extractRoot}");
                ZipFile.ExtractToDirectory(zipPath, extractRoot, overwriteFiles: true);

                // 5) Resolve payload root
                string payloadRoot = ResolvePayloadRoot(extractRoot, appExeName, log);
                log.Info($"Resolved payloadRoot: {payloadRoot}");

                // 6) Swap (with retries)
                string prevDir = Path.Combine(installRoot, "current.prev");
                EnsureDeletedWithRetries(prevDir, log);

                log.Info("Renaming current -> current.prev");
                MoveDirectoryWithRetries(currentDir, prevDir, log, maxSeconds: 60);

                try
                {
                    log.Info("Moving payload -> current");
                    MoveDirectoryWithRetries(payloadRoot, currentDir, log, maxSeconds: 60);

                    // 7) Start new app
                    string exePath = Path.Combine(currentDir, appExeName);
                    if (!File.Exists(exePath))
                    {
                        // fallback search
                        var found = Directory.GetFiles(currentDir, appExeName, SearchOption.AllDirectories);
                        if (found.Length > 0) exePath = found[0];
                    }
                    if (!File.Exists(exePath))
                    {
                        throw new Exception($"Cannot find {appExeName} after install in: {currentDir}");
                    }

                    log.Info($"Starting app: {exePath}");
                    StartExe(exePath, currentDir);

                    log.Info("Update install complete ✅");
                    return 0;
                }
                catch (Exception startEx)
                {
                    // Rollback
                    log.Error($"Start/install failed. Rolling back... ({startEx.Message})");
                    TryRollback(currentDir, prevDir, log);
                    throw;
                }
            }
            catch (Exception ex)
            {
                log.Error("FATAL: " + ex.Message);
                log.Error(ex.ToString());
                return 2;
            }
        }

        private static Dictionary<string, string> ParseArgs(string[] args)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < args.Length; i++)
            {
                var k = args[i];
                if (!k.StartsWith("--")) continue;

                if (i + 1 >= args.Length || args[i + 1].StartsWith("--"))
                {
                    d[k] = "true";
                }
                else
                {
                    d[k] = args[i + 1];
                    i++;
                }
            }
            return d;
        }

        private static string Require(Dictionary<string, string> d, string key)
        {
            if (!d.TryGetValue(key, out var v) || string.IsNullOrWhiteSpace(v))
            {
                PrintHelp($"Missing required arg: {key}");
                Environment.Exit(1);
            }
            return v!;
        }

        private static void PrintHelp(string err)
        {
            Console.WriteLine(err);
            Console.WriteLine();
            Console.WriteLine("MonClubDesktopUpdater.exe ^");
            Console.WriteLine(@"  --installRoot ""%LOCALAPPDATA%\MonClubAccess"" ^");
            Console.WriteLine(@"  --releaseId ""20260210-124245Z"" ^");
            Console.WriteLine(@"  --zip ""...\downloads\windows\stable\MonClubAccess-20260210-124245Z.zip"" ^");
            Console.WriteLine(@"  --manifest ""...\downloads\windows\stable\MonClubAccess-20260210-124245Z.manifest.json"" ^");
            Console.WriteLine(@"  --waitPid 12345 ^");
            Console.WriteLine(@"  [--appExeName ""MonClubAccess.exe""] ^");
            Console.WriteLine(@"  [--log ""...\logs\updater-<releaseId>.log""] ^");
            Console.WriteLine(@"  [--forceKillAfterSeconds 20]");
        }

        private static void WaitForPidExit(int pid, int forceKillAfterSeconds, SimpleLogger log)
        {
            try
            {
                var p = Process.GetProcessById(pid);
                log.Info($"Waiting for pid={pid} to exit...");

                if (forceKillAfterSeconds > 0)
                {
                    var sw = Stopwatch.StartNew();
                    while (!p.HasExited)
                    {
                        if (sw.Elapsed.TotalSeconds >= forceKillAfterSeconds)
                        {
                            log.Warn($"Force killing pid={pid} after {forceKillAfterSeconds}s");
                            try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
                            break;
                        }
                        Thread.Sleep(250);
                        p.Refresh();
                    }
                }
                else
                {
                    p.WaitForExit();
                }

                log.Info(p.HasExited ? "App process already exited." : "App process forced/ended.");
            }
            catch (ArgumentException)
            {
                // already exited
                log.Info("App process already exited.");
            }
        }

        private static void KillRunningAppFromDir(string currentDir, string appExeName, SimpleLogger log)
        {
            try
            {
                if (!Directory.Exists(currentDir)) return;

                string processName = Path.GetFileNameWithoutExtension(appExeName);
                foreach (var p in Process.GetProcessesByName(processName))
                {
                    try
                    {
                        // MainModule can throw sometimes; guard it.
                        var exe = p.MainModule?.FileName;
                        if (exe == null) continue;

                        if (exe.StartsWith(currentDir, StringComparison.OrdinalIgnoreCase))
                        {
                            log.Warn($"Found running {processName} (pid={p.Id}) from current\\. Closing...");
                            try
                            {
                                p.CloseMainWindow();
                                if (!p.WaitForExit(3000))
                                {
                                    log.Warn($"Killing {processName} pid={p.Id}");
                                    p.Kill(entireProcessTree: true);
                                    p.WaitForExit(5000);
                                }
                            }
                            catch { /* ignore */ }
                        }
                    }
                    catch { /* ignore */ }
                }
            }
            catch { /* ignore */ }
        }

        private static Manifest LoadManifest(string path)
        {
            var json = File.ReadAllText(path, Encoding.UTF8);
            var man = JsonSerializer.Deserialize<Manifest>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            if (man == null) throw new Exception("Failed to parse manifest JSON");
            return man;
        }

        private static string Sha256File(string path)
        {
            using var fs = File.OpenRead(path);
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(fs);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        private static string ResolvePayloadRoot(string extractRoot, string appExeName, SimpleLogger log)
        {
            string expectedRootName = Path.GetFileNameWithoutExtension(appExeName);

            var dirs = Directory.GetDirectories(extractRoot);
            if (dirs.Length == 1)
            {
                var only = dirs[0];
                if (Path.GetFileName(only).Equals(expectedRootName, StringComparison.OrdinalIgnoreCase))
                    return only;
            }

            if (File.Exists(Path.Combine(extractRoot, appExeName)))
                return extractRoot;

            var found = Directory.GetFiles(extractRoot, appExeName, SearchOption.AllDirectories);
            if (found.Length > 0)
            {
                return Path.GetDirectoryName(found[0])!;
            }

            // Fallback: use extractRoot
            log.Warn("Could not detect payload root cleanly; using extractRoot.");
            return extractRoot;
        }

        private static void EnsureDeletedWithRetries(string dir, SimpleLogger log)
        {
            if (!Directory.Exists(dir)) return;

            log.Info($"Deleting existing: {dir}");
            for (int i = 1; i <= 40; i++)
            {
                try
                {
                    Directory.Delete(dir, recursive: true);
                    return;
                }
                catch
                {
                    Thread.Sleep(250);
                }
            }
            // last try
            Directory.Delete(dir, recursive: true);
        }

        private static void MoveDirectoryWithRetries(string src, string dst, SimpleLogger log, int maxSeconds)
        {
            var deadline = DateTime.UtcNow.AddSeconds(maxSeconds);
            int attempt = 0;

            while (true)
            {
                attempt++;
                try
                {
                    if (!Directory.Exists(src))
                        throw new Exception($"Source directory does not exist: {src}");

                    Directory.Move(src, dst);
                    return;
                }
                catch (IOException ioex) when (IsSharingOrLockViolation(ioex))
                {
                    if (DateTime.UtcNow >= deadline)
                        throw;

                    log.Warn($"Move locked (attempt {attempt}). Retrying... {ioex.Message}");
                    Thread.Sleep(500);
                }
                catch (UnauthorizedAccessException uaex)
                {
                    if (DateTime.UtcNow >= deadline)
                        throw;

                    log.Warn($"Move denied/locked (attempt {attempt}). Retrying... {uaex.Message}");
                    Thread.Sleep(500);
                }
            }
        }

        private static bool IsSharingOrLockViolation(IOException ex)
        {
            // Common HRESULTs:
            // 0x80070020 (ERROR_SHARING_VIOLATION=32)
            // 0x80070021 (ERROR_LOCK_VIOLATION=33)
            int hr = ex.HResult;
            return hr == unchecked((int)0x80070020) || hr == unchecked((int)0x80070021);
        }

        private static void StartExe(string exePath, string workingDir)
        {
            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                WorkingDirectory = workingDir,
                UseShellExecute = true
            };
            Process.Start(psi);
        }

        private static void TryRollback(string currentDir, string prevDir, SimpleLogger log)
        {
            try
            {
                // If current exists (broken), delete it (best effort)
                if (Directory.Exists(currentDir))
                {
                    log.Warn("Rollback: deleting broken current...");
                    try { Directory.Delete(currentDir, recursive: true); } catch { /* ignore */ }
                }

                // Move prev back to current
                if (Directory.Exists(prevDir))
                {
                    log.Warn("Rollback: restoring current.prev -> current...");
                    Directory.Move(prevDir, currentDir);
                }
            }
            catch (Exception ex)
            {
                log.Error("Rollback failed: " + ex.Message);
            }
        }
    }
}
