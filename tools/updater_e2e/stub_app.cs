// TEST-ONLY stub payload for the installer end-to-end runs (design.md section 8 step 11).
// Compiled by tools/updater_e2e/build_stub_payloads.ps1 as MonClubAccess.exe / MonClubTV.exe.
// It is never part of a release: build_release.ps1 stages the real PyInstaller output.
//
// Behaviour, chosen by stub_mode.txt next to the exe (ok | noboot | crash; default ok):
//   ok      after 3 s writes <install_root>\state\boot_ok.json {"version","pid","at"} with the
//           "version" of version.json next to the exe, then stays alive until killed;
//   noboot  stays alive, never writes boot_ok.json (health timeout);
//   crash   exits with code 3 after 3 s, never writes boot_ok.json.
// Every start appends one line to <install_root>\logs\stub.log: time, pid, mode, version,
// exe path and the WORKING DIRECTORY (the evidence that gyms' launch rule was kept).
using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;

static class StubApp
{
    static int Main(string[] args)
    {
        string exe = System.Reflection.Assembly.GetExecutingAssembly().Location;
        string exeDir = Path.GetDirectoryName(exe);
        string root = Path.GetDirectoryName(exeDir);
        string mode = "ok";
        try { mode = File.ReadAllText(Path.Combine(exeDir, "stub_mode.txt")).Trim().ToLowerInvariant(); } catch { }
        string version = "";
        try
        {
            Match m = Regex.Match(File.ReadAllText(Path.Combine(exeDir, "version.json")), "\"version\"\\s*:\\s*\"([^\"]*)\"");
            if (m.Success) version = m.Groups[1].Value;
        }
        catch { }
        int pid = System.Diagnostics.Process.GetCurrentProcess().Id;
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "logs"));
            File.AppendAllText(Path.Combine(root, "logs", "stub.log"),
                string.Format("{0:o} pid={1} mode={2} version={3} exe={4} cwd={5}\r\n",
                    DateTime.UtcNow, pid, mode, version, exe, Environment.CurrentDirectory));
        }
        catch { }

        Thread.Sleep(3000);
        if (mode == "crash") return 3;
        if (mode == "ok")
        {
            string state = Path.Combine(root, "state");
            Directory.CreateDirectory(state);
            string json = string.Format("{{\"version\":\"{0}\",\"pid\":{1},\"at\":\"{2}\"}}",
                version, pid, DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"));
            string tmp = Path.Combine(state, "boot_ok.json.tmp");
            File.WriteAllText(tmp, json);
            string dst = Path.Combine(state, "boot_ok.json");
            if (File.Exists(dst)) File.Delete(dst);
            File.Move(tmp, dst);
        }
        while (true) Thread.Sleep(60000);
    }
}
