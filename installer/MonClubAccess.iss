; installer\MonClubAccess.iss
; Build with:
;   ISCC.exe installer\MonClubAccess.iss /DAppVersion=1.0.0 /DStageDir="C:\...\release\_staging\MonClubAccess-20260326-120000Z\MonClubAccess" /DOutputBaseFilename=monclub_access_1.0.0

#define AppName "MonClub Access"

#ifndef AppVersion
  #error AppVersion define is missing. Pass /DAppVersion=1.0.0
#endif

#ifndef ReleaseId
  #define ReleaseId "DEV"
#endif

#ifndef StageDir
  #error StageDir define is missing. Pass /DStageDir="full\path\to\staged\MonClubAccess"
#endif

#ifndef OutputBaseFilename
  #define OutputBaseFilename "monclub_access"
#endif

#define AppPublisher "MonClub"
#define MainExe "MonClubAccess.exe"
#define TauriExe "monclub-access-ui.exe"
#define DefaultInstallRoot "{localappdata}\MonClubAccess"
#define LegacyInstallRoot "{localappdata}\MonClub Access"
; Inno's uninstall registry key for this AppId (HKCU, PrivilegesRequired=lowest).
#define UninstallKeyName "{9B77A9C2-2B97-4F62-A9E8-4B4C65F3A9B1}_is1"
; MonClub TV's key: the Access uninstall keeps TV's data while TV is installed (D26).
#define OtherUninstallKeyName "{4A8D6A8A-7AC6-4C87-862D-2E5A6B644D27}_is1"

#ifdef UPDATER_TEST_FAIL
  ; Test-only build (build_installer.ps1 -TestFail). The file name says so, and
  ; publish_github_release.ps1 refuses the release file such a build writes.
  #define OutputBaseFilename OutputBaseFilename + "_TESTFAIL_" + UPDATER_TEST_FAIL
#endif

; Branding assets (relative to this .iss file)
#define SetupIcon "assets\setup.ico"
#define WizardImage "assets\wizard.bmp"
#define WizardSmall "assets\wizard_small.bmp"

[Setup]
; Built with Python 3.14, which runs on Windows 10 and newer only.
MinVersion=10.0
AppId={{9B77A9C2-2B97-4F62-A9E8-4B4C65F3A9B1}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
SetupIconFile={#SetupIcon}
; Icon shown in Windows Settings > Apps. Without it Inno writes no DisplayIcon and
; Windows shows a generic icon there.
UninstallDisplayIcon={app}\current\{#MainExe}
WizardImageFile={#WizardImage}
WizardSmallImageFile={#WizardSmall}
DefaultDirName={code:GetInstallRootDefault}
PrivilegesRequired=lowest
UsePreviousAppDir=yes
UsePreviousTasks=yes
CloseApplications=yes
CloseApplicationsFilter={#MainExe},{#TauriExe}
RestartApplications=no
DisableProgramGroupPage=yes
; D26: OVERWRITE the uninstall log instead of appending to it (Inno's default). Appending kept
; every older version's entries -- 1.4.x recorded "[UninstallDelete] {commonappdata}\MonClub
; Access" -- and an uninstall replays ALL of them, so the old whole-data-root delete still ran
; even though this script no longer has it (E2E 2026-10-09, e2e\L2\21-*). Nothing is lost by
; overwriting: [UninstallDelete] removes {app} entirely, neither installer ever had [Registry]
; entries, and both shortcuts are listed in [UninstallDelete] in case an older install made
; one whose task is unticked now.
UninstallLogMode=overwrite
OutputDir=..\release
OutputBaseFilename={#OutputBaseFilename}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Always write Setup's log (%TEMP%\Setup Log <date> #<n>.txt), as /LOG would. The
; 1.4.35 in-app update starts this installer with /VERYSILENT and no /LOG, so without it a
; silent update left no log at all -- including the watchdog registration's output ([Run],
; Flags: logoutput). The v2 client passes /LOG=<install_root>\logs\update-<ver>-<ts>.log;
; last_update.json records which file it was ("log").
SetupLogging=yes

[Tasks]
; Start Menu shortcut: ticked for a new install; an existing install keeps its previous
; choice (UsePreviousTasks=yes). It used Flags: checkedonce, which unticked it at every
; update of a PC where it had been ticked (Inno Setup source, see the watchdog entries
; below). An update records that choice, so a PC already updated once keeps it unticked.
Name: "startmenuicon"; Description: "Create a &Start Menu shortcut"; GroupDescription: "Additional icons:"
Name: "desktopicon"; Description: "Create a &Desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked
; "Keep MonClub Access running" registers a per-user scheduled task that both starts
; MonClub Access at logon and restarts it if the backend process dies.
;
; TICKED for a NEW install, UNTICKED by default on an existing one (owner decision,
; 2026-09-26). Hence two entries with the same name, exactly one of them shown
; (IsFreshInstall below). On an existing install Inno then restores the previous
; choice from the uninstall key (UsePreviousTasks=yes): ticked stays ticked, unticked
; stays unticked. An install whose version predates this box has no recorded choice,
; and the unticked entry keeps it off: a routine update -- the silent in-app one
; included -- must never give a PC a new startup entry by itself.
;
; NOT Flags: checkedonce. It does the opposite of what it sounds like here: a task
; previously SELECTED comes back unchecked, and a task missing from the previous
; install's lists falls back to its base state (Inno Setup source,
; Setup.WizardForm.pas, TWizardForm.CreateTaskButtons).
;
; Ticked on an existing install, the [Run] entry below re-registers the task; a task
; that exists and is DISABLED stays disabled (register_watchdog.ps1).
Name: "watchdog"; Description: "Keep MonClub Access running (start at logon, restart if it stops)"; GroupDescription: "Reliability:"; Check: IsFreshInstall
Name: "watchdog"; Description: "Keep MonClub Access running (start at logon, restart if it stops)"; GroupDescription: "Reliability:"; Flags: unchecked; Check: not IsFreshInstall

[Dirs]
Name: "{app}\current"
Name: "{app}\downloads"
Name: "{app}\logs"
Name: "{app}\state"

[Files]
; Safe-swap helper (updater v2): extracted to {tmp} for Setup's own use (dontcopy) ...
Source: "update_helper.ps1"; Flags: dontcopy
; The new watchdog is also extracted (dontcopy) and put in place by PrepareToInstall BEFORE
; current\ is emptied: on the 1.4.35 -> 1.5.0 hop, a power cut in the copy would otherwise leave
; the OLD watchdog -- no journal rule -- standing down for ever on "exe missing" (review #3).
Source: "..\packaging\watchdog\monclub_access_watchdog.ps1"; Flags: dontcopy
; Watchdog scripts live OUTSIDE current\ on purpose: an update empties and refills
; current\ (and a rollback refills it again), and the scheduled task's action path must
; stay valid across both.
Source: "..\packaging\watchdog\monclub_access_watchdog.ps1"; DestDir: "{app}\watchdog"; Flags: ignoreversion
Source: "..\packaging\watchdog\register_watchdog.ps1";       DestDir: "{app}\watchdog"; Flags: ignoreversion
Source: "..\packaging\watchdog\monclub_access_watchdog_hidden.vbs"; DestDir: "{app}\watchdog"; Flags: ignoreversion
; ... and installed beside the watchdog, which applies the install-journal rule with it
; (design section 8 step 12).
Source: "update_helper.ps1"; DestDir: "{app}\watchdog"; Flags: ignoreversion
; version.json and then the exe are copied LAST (Inno installs [Files] in script order): if
; power is cut during the copy, a present exe means the whole payload is there, and a
; version.json without the exe is never taken for an installed version (review #3 / #5).
Source: "{#StageDir}\*"; Excludes: "\{#MainExe},\version.json"; DestDir: "{app}\current"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#StageDir}\version.json"; DestDir: "{app}\current"; Flags: ignoreversion
Source: "{#StageDir}\{#MainExe}"; DestDir: "{app}\current"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\MonClubAccess"; Filename: "{app}\current\{#MainExe}"; Tasks: startmenuicon
Name: "{userdesktop}\MonClubAccess"; Filename: "{app}\current\{#MainExe}"; Tasks: desktopicon

[Run]
; Register the watchdog BEFORE launching the app, and only when the task is ticked.
; Unticked, an existing task is left exactly as it is. Ticked, the script replaces
; the task with the current definition, keeping it DISABLED if it was disabled -- an
; update must never switch the watchdog back on (register_watchdog.ps1).
; runascurrentuser keeps it a per-user task (PrivilegesRequired=lowest, and the app
; needs the interactive desktop session for its tray icon and Tauri window -- a
; SYSTEM task would start it in session 0 where nobody can see it).
; logoutput: the script's output goes into Setup's log (SetupLogging=yes). Nothing reads
; its exit code; the script also writes its outcome to {app}\logs\watchdog-register.log.
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\watchdog\register_watchdog.ps1"" -InstallRoot ""{app}"""; \
  StatusMsg: "Registering the MonClub Access watchdog..."; \
  Flags: runhidden runascurrentuser waituntilterminated logoutput; \
  Tasks: watchdog

; Interactive installs only. A silent install/update starts the app itself in ssPostInstall
; (update_safety.iss) and waits for it to prove it is healthy, rolling back if not.
Filename: "{app}\current\{#MainExe}"; Description: "Launch MonClub Access"; Flags: nowait postinstall; Check: not WizardSilent

[UninstallRun]
; Remove the scheduled task before {app} disappears, otherwise Task Scheduler is
; left with an entry pointing at a script that no longer exists.
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\watchdog\register_watchdog.ps1"" -Remove"; \
  Flags: runhidden runascurrentuser waituntilterminated; \
  RunOnceId: "RemoveMonClubWatchdog"

[UninstallDelete]
Type: files; Name: "{userprograms}\MonClubAccess.lnk"
Type: files; Name: "{userdesktop}\MonClubAccess.lnk"
Type: filesandordirs; Name: "{app}\previous"
Type: filesandordirs; Name: "{app}\current.failed"
Type: filesandordirs; Name: "{app}\state"
Type: filesandordirs; Name: "{app}\downloads"
Type: filesandordirs; Name: "{app}"
Type: filesandordirs; Name: "{userappdata}\MonClub Access"
Type: filesandordirs; Name: "{userappdata}\MonClubAccess"
; The DATA root ({commonappdata}\MonClub Access, else {localappdata}\MonClub Access --
; app/core/utils.py::_candidate_data_roots) is SHARED with MonClub TV: it is removed in
; CurUninstallStepChanged(usPostUninstall), keeping TV's part while TV is installed (D26).

[Code]
const
  WebView2ClientId = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';

var
  RuntimeCheckPage: TWizardPage;
  RuntimeCheckStatusLabel: TNewStaticText;
  RuntimeCheckMemo: TNewMemo;
  RuntimeHasWarning: Boolean;
  ExistingInstallDetected: Boolean;
  ExistingInstallRoot: string;
  ExistingInstallVersion: string;

function ExpandPath(const Value: string): string;
begin
  Result := ExpandConstant(Value);
end;

function DefaultInstallRoot(): string;
begin
  Result := ExpandPath('{#DefaultInstallRoot}');
end;

function LegacyInstallRoot(): string;
begin
  Result := ExpandPath('{#LegacyInstallRoot}');
end;

function PathHasInstalledPayload(const RootPath: string): Boolean;
begin
  Result :=
    DirExists(RootPath) and (
      FileExists(AddBackslash(RootPath) + 'current\version.json') or
      FileExists(AddBackslash(RootPath) + 'current\{#MainExe}')
    );
end;

function DetectExistingInstallRoot(): string;
begin
  Result := '';

  if PathHasInstalledPayload(DefaultInstallRoot()) then
  begin
    Result := DefaultInstallRoot();
    exit;
  end;

  if PathHasInstalledPayload(LegacyInstallRoot()) then
  begin
    Result := LegacyInstallRoot();
    exit;
  end;
end;

function TryExtractJsonStringValue(const JsonText: string; const Key: string; var Value: string): Boolean;
var
  Needle: string;
  KeyPos: Integer;
  ColonPos: Integer;
  StartPos: Integer;
  EndPos: Integer;
begin
  Result := False;
  Value := '';
  Needle := '"' + Key + '"';
  KeyPos := Pos(Needle, JsonText);
  if KeyPos = 0 then
    exit;

  ColonPos := KeyPos + Length(Needle);
  while (ColonPos <= Length(JsonText)) and (JsonText[ColonPos] <> ':') do
    ColonPos := ColonPos + 1;
  if ColonPos > Length(JsonText) then
    exit;

  StartPos := ColonPos + 1;
  while (StartPos <= Length(JsonText)) and ((JsonText[StartPos] = ' ') or (JsonText[StartPos] = #9) or (JsonText[StartPos] = #10) or (JsonText[StartPos] = #13)) do
    StartPos := StartPos + 1;
  if (StartPos > Length(JsonText)) or (JsonText[StartPos] <> '"') then
    exit;

  StartPos := StartPos + 1;
  EndPos := StartPos;
  while EndPos <= Length(JsonText) do
  begin
    if (JsonText[EndPos] = '"') and ((EndPos = StartPos) or (JsonText[EndPos - 1] <> '\')) then
      break;
    EndPos := EndPos + 1;
  end;
  if EndPos > Length(JsonText) then
    exit;

  Value := Copy(JsonText, StartPos, EndPos - StartPos);
  Result := True;
end;

function TryReadInstalledVersion(const RootPath: string; var Version: string): Boolean;
var
  VersionPath: string;
  JsonText: AnsiString;
begin
  Result := False;
  Version := '';
  VersionPath := AddBackslash(RootPath) + 'current\version.json';
  if not FileExists(VersionPath) then
    exit;
  if not LoadStringFromFile(VersionPath, JsonText) then
    exit;
  Result := TryExtractJsonStringValue(JsonText, 'version', Version);
end;

function SameVersionInstalled(): Boolean;
begin
  Result := ExistingInstallDetected and
    (Trim(ExistingInstallVersion) <> '') and
    (Lowercase(Trim(ExistingInstallVersion)) = Lowercase('{#AppVersion}'));
end;

function GetInstallRootDefault(Param: string): string;
begin
  if ExistingInstallDetected and (Trim(ExistingInstallRoot) <> '') then
    Result := ExistingInstallRoot
  else
    Result := DefaultInstallRoot();
end;

function IsFreshInstall(): Boolean;
begin
  // Picks which of the two [Tasks] "watchdog" entries is shown: ticked for a
  // new install, unticked by default otherwise. "Existing" is read both ways
  // on purpose -- Inno's own uninstall record (PrevAppDir, from 'Inno Setup:
  // App Path') and the files this script already detects -- so an install
  // with either one left behind is never mistaken for a new one.
  Result := (not ExistingInstallDetected) and (WizardForm.PrevAppDir = '');
end;

procedure ExecAndLog(const CmdLine: string);
var
  ResultCode: Integer;
begin
  if Exec(ExpandConstant('{cmd}'), '/C ' + CmdLine, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('Exec [' + CmdLine + '] exit=' + IntToStr(ResultCode))
  else
    Log('Exec failed [' + CmdLine + ']');
end;

procedure KillRunningMonClubProcesses();
begin
  Log('Ensuring MonClub Access processes are stopped...');
  ExecAndLog('taskkill /F /T /IM "{#MainExe}"');
  ExecAndLog('taskkill /F /T /IM "{#TauriExe}"');
end;

function ZkemkeeperClsid(): string;
var
  Clsid: string;
begin
  // Read HKLM\SOFTWARE\Classes DIRECTLY, and only then fall back to the merged
  // HKEY_CLASSES_ROOT view.
  //
  // Field failure (1.4.24): regsvr32 genuinely succeeded -- the same command run
  // by hand straight afterwards worked -- yet this post-check said the class was
  // missing and setup showed an alarming "still not registered" error. HKCR is a
  // MERGED view (HKLM\Software\Classes + HKCU\Software\Classes) and a process
  // that has already read it can keep serving that cached view, so the pre-check
  // ("is it already registered?") poisoned the post-check in the very same run.
  // Reading the real hive avoids the merged-view cache entirely.
  Result := '';
  if RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Classes\zkemkeeper.CZKEM\CLSID', '', Clsid) then
  begin
    Result := Trim(Clsid);
    if Result <> '' then Exit;
  end;
  if RegQueryStringValue(HKEY_CURRENT_USER, 'Software\Classes\zkemkeeper.CZKEM\CLSID', '', Clsid) then
  begin
    Result := Trim(Clsid);
    if Result <> '' then Exit;
  end;
  if RegQueryStringValue(HKEY_CLASSES_ROOT, 'zkemkeeper.CZKEM\CLSID', '', Clsid) then
    Result := Trim(Clsid);
end;

function ZkemkeeperRegisteredDll(): string;
var
  Clsid: string;
  DllRef: string;
begin
  // Setup declares no ArchitecturesInstallIn64BitMode, so it runs as a 32-bit
  // process and these reads resolve against the 32-bit registry view -- the
  // correct view for the 32-bit zkemkeeper COM server.
  Result := '';
  Clsid := ZkemkeeperClsid();
  if Clsid = '' then
    Exit;
  if RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Classes\CLSID\' + Clsid + '\InprocServer32', '', DllRef) then
  begin
    Result := RemoveQuotes(Trim(DllRef));
    if Result <> '' then Exit;
  end;
  if RegQueryStringValue(HKEY_CURRENT_USER, 'Software\Classes\CLSID\' + Clsid + '\InprocServer32', '', DllRef) then
  begin
    Result := RemoveQuotes(Trim(DllRef));
    if Result <> '' then Exit;
  end;
  if RegQueryStringValue(HKEY_CLASSES_ROOT, 'CLSID\' + Clsid + '\InprocServer32', '', DllRef) then
    Result := RemoveQuotes(Trim(DllRef));
end;

function ZkemkeeperIsRegistered(): Boolean;
var
  DllRef: string;
begin
  // A CLSID whose InprocServer32 points at a file that no longer exists is
  // worse than no registration at all -- report that as unregistered so we
  // re-register instead of silently skipping.
  DllRef := ZkemkeeperRegisteredDll();
  Result := (DllRef <> '') and FileExists(DllRef);
end;

procedure RegisterZkemkeeper();
var
  Regsvr: string;
  DllPath: string;
  ResultCode: Integer;
  Failure: string;
begin
  DllPath := ExpandConstant('{app}\current\sdk\zkemkeeper.dll');
  if not FileExists(DllPath) then
  begin
    Log('ZKEMKeeper DLL not found: ' + DllPath);
    Exit;
  end;

  // Skip when it is already registered AND the target file still exists, so
  // routine updates and re-installs raise no needless elevation prompt.
  if ZkemkeeperIsRegistered() then
  begin
    Log('ZKEMKeeper COM already registered -> ' + ZkemkeeperRegisteredDll() + ' (skipping regsvr32).');
    Exit;
  end;

  if IsWin64 then
    Regsvr := ExpandConstant('{syswow64}\regsvr32.exe')
  else
    Regsvr := ExpandConstant('{sys}\regsvr32.exe');

  // SILENT (in-app update): never 'runas'. A UAC prompt nobody answers blocked the whole
  // silent update -- and the relaunch -- on PullSDK-only PCs that never had zkemkeeper
  // registered (D23). A PC where it IS registered never gets here: the registration points
  // at {app}\current\sdk\zkemkeeper.dll, the update refills that same path, and the
  // ZkemkeeperIsRegistered check above returns before this line. Nothing in the app
  // registers it later (there is no regsvr32 call in app/, shared/ or tv/), so a PC that
  // needs it must run this installer interactively once, or the regsvr32 line as admin.
  if WizardSilent() then
  begin
    Log('ZKEMKeeper COM is NOT registered and this is a silent install: not elevating. ' +
        'MB2000-class terminals need it; run the installer interactively once, or as admin: ' +
        Regsvr + ' /s "' + DllPath + '"');
    Exit;
  end;

  // Three separate defects are fixed here. All three had to be, because each
  // one alone was enough to stop a fingerprint turnstile from ever working:
  //
  //   1. Do NOT route this through ExecAndLog. That helper wraps its argument
  //      in 'cmd /C', and this command line carries FOUR quote characters,
  //      which trips cmd's quote-stripping rule (see 'cmd /?'): it strips the
  //      leading quote and the final quote and mangles the line. Measured
  //      behaviour was cmd exiting 1 with regsvr32 never launched at all.
  //      ShellExec below runs regsvr32 directly, with no cmd in between.
  //   2. Elevate. PrivilegesRequired=lowest, but DllRegisterServer writes to
  //      HKLM\SOFTWARE\Classes, which a standard user may not do. The 'runas'
  //      verb raises the UAC prompt this step has always silently needed.
  //   3. Honour ResultCode. ExecAndLog logged the exit code then discarded it,
  //      so a failed registration looked exactly like a successful one.
  //
  // zkemkeeper.dll statically imports zkemsdk.dll -> commpro.dll; both now ship
  // in sdk/ beside it, which is what regsvr32 needs to resolve the load chain.
  Failure := '';
  if not ShellExec('runas', Regsvr, '/s "' + DllPath + '"', '',
                   SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Failure := 'the elevation prompt was declined, or regsvr32 could not be started'
  else if ResultCode <> 0 then
    Failure := 'regsvr32 exited with code ' + IntToStr(ResultCode);

  // Deliberately NOT treating "regsvr32 said OK but I cannot see the class" as a
  // failure. In the field that combination was a false alarm every time: the
  // registration had genuinely worked and the identical command run by hand a
  // minute later succeeded. regsvr32's exit code is the authoritative signal;
  // this process's own registry view is not (see ZkemkeeperClsid). Log the
  // discrepancy so it stays diagnosable, but do not alarm the installer with a
  // scary, wrong message about hardware that is in fact fine.
  if (Failure = '') and (not ZkemkeeperIsRegistered()) then
    Log('ZKEMKeeper: regsvr32 succeeded but this process cannot yet see the class '
        + '(merged-view cache); treating as registered. DLL: ' + DllPath);

  if Failure = '' then
  begin
    Log('ZKEMKeeper COM registered OK -> ' + DllPath);
    Exit;
  end;

  // Never fail the whole install over this: gyms whose turnstiles speak PullSDK
  // do not need the standalone SDK at all. Surface it loudly instead -- a silent
  // skip here is precisely how this reached a client unnoticed.
  Log('ZKEMKeeper registration FAILED (' + Failure + '). DLL: ' + DllPath);
  if not WizardSilent() then
    MsgBox('MonClub Access could not register the ZKTeco standalone SDK' + #13#10 +
           '(' + Failure + ').' + #13#10 + #13#10 +
           'The application will install and run normally. Fingerprint turnstiles' + #13#10 +
           'such as the MB2000 will NOT connect until this is registered.' + #13#10 + #13#10 +
           'To fix it, run this once from an ADMINISTRATOR command prompt:' + #13#10 + #13#10 +
           '  ' + Regsvr + ' "' + DllPath + '"',
           mbError, MB_OK);
end;

procedure UnregisterZkemkeeper();
var
  Regsvr: string;
  DllPath: string;
  Registered: string;
  ResultCode: Integer;
begin
  // Only unregister when the live registration still points inside THIS
  // install. Another product -- ZKTeco's own software, or the on-site script
  // pack -- may own the registration and point it at C:\Windows\SysWOW64.
  // Tearing that down on our uninstall would break software we do not own.
  DllPath := ExpandConstant('{app}\current\sdk\zkemkeeper.dll');
  Registered := ZkemkeeperRegisteredDll();
  if (Registered = '') or (CompareText(Registered, DllPath) <> 0) then
  begin
    Log('ZKEMKeeper: registration is not ours (' + Registered + ') -- leaving it alone.');
    Exit;
  end;
  if not FileExists(DllPath) then
    Exit;

  if IsWin64 then
    Regsvr := ExpandConstant('{syswow64}\regsvr32.exe')
  else
    Regsvr := ExpandConstant('{sys}\regsvr32.exe');

  // Never raise a UAC prompt in a silent uninstall (nobody is there to answer it). The
  // CLSID then points at a deleted file, which ZkemkeeperIsRegistered treats as unregistered.
  if UninstallSilent() then
  begin
    Log('ZKEMKeeper: silent uninstall -- not elevating to unregister ' + DllPath);
    Exit;
  end;

  // Best-effort only: an uninstall must not stall on a declined UAC prompt.
  if ShellExec('runas', Regsvr, '/s /u "' + DllPath + '"', '',
               SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then
    Log('ZKEMKeeper COM unregistered.')
  else
    Log('ZKEMKeeper unregister skipped or failed (exit=' + IntToStr(ResultCode) + ').');
end;

function IsWebView2RuntimePresent(var Version: string): Boolean;
begin
  Version := '';

  Result := RegQueryStringValue(
    HKCU,
    'SOFTWARE\Microsoft\EdgeUpdate\Clients\' + WebView2ClientId,
    'pv',
    Version
  );

  if (not Result) and IsWin64 then
    Result := RegQueryStringValue(
      HKLM64,
      'SOFTWARE\Microsoft\EdgeUpdate\Clients\' + WebView2ClientId,
      'pv',
      Version
    );

  if not Result then
    Result := RegQueryStringValue(
      HKLM,
      'SOFTWARE\Microsoft\EdgeUpdate\Clients\' + WebView2ClientId,
      'pv',
      Version
    );

  if not Result then
    Result := DirExists(ExpandConstant('{localappdata}\Microsoft\EdgeWebView\Application'));
end;

function IsZkScannerDriverLikelyPresent(var Details: string): Boolean;
var
  ComPath: string;
begin
  Details := '';
  Result := False;

  if RegQueryStringValue(HKCR, 'CLSID\{00853A19-BD51-419B-9269-2DABE57EB61F}\InprocServer32', '', ComPath) then
  begin
    if FileExists(ComPath) then
    begin
      Details := 'zkemkeeper COM detected: ' + ComPath;
      Result := True;
      exit;
    end;
  end;

  if FileExists(ExpandConstant('{syswow64}\zkemkeeper.dll')) then
  begin
    Details := ExpandConstant('{syswow64}\zkemkeeper.dll');
    Result := True;
    exit;
  end;

  if FileExists(ExpandConstant('{sys}\zkemkeeper.dll')) then
  begin
    Details := ExpandConstant('{sys}\zkemkeeper.dll');
    Result := True;
    exit;
  end;

  if RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\zkfp') then
  begin
    Details := 'Service key found: HKLM\\SYSTEM\\CurrentControlSet\\Services\\zkfp';
    Result := True;
    exit;
  end;

  if RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\ZKFPService') then
  begin
    Details := 'Service key found: HKLM\\SYSTEM\\CurrentControlSet\\Services\\ZKFPService';
    Result := True;
    exit;
  end;

  if RegKeyExists(HKLM, 'SOFTWARE\ZKTeco') then
  begin
    Details := 'Registry key found: HKLM\\SOFTWARE\\ZKTeco';
    Result := True;
    exit;
  end;

  if IsWin64 and RegKeyExists(HKLM64, 'SOFTWARE\ZKTeco') then
  begin
    Details := 'Registry key found: HKLM64\\SOFTWARE\\ZKTeco';
    Result := True;
    exit;
  end;
end;

procedure RunRuntimeChecks();
var
  WebVersion: string;
  ZkDetails: string;
  WebOk: Boolean;
  ZkOk: Boolean;
begin
  RuntimeHasWarning := False;
  RuntimeCheckMemo.Lines.Clear;

  if SameVersionInstalled() then
  begin
    RuntimeCheckMemo.Lines.Add('MonClub Access ' + '{#AppVersion}' + ' is already installed.');
    RuntimeCheckMemo.Lines.Add('No update is needed for this package.');
    RuntimeCheckStatusLabel.Caption := 'Status: already up to date.';
    exit;
  end;

  if ExistingInstallDetected then
  begin
    RuntimeCheckMemo.Lines.Add('Existing installation detected:');
    RuntimeCheckMemo.Lines.Add('  Root: ' + ExistingInstallRoot);
    if Trim(ExistingInstallVersion) <> '' then
      RuntimeCheckMemo.Lines.Add('  Installed version: ' + ExistingInstallVersion);
    RuntimeCheckMemo.Lines.Add('  Package version: ' + '{#AppVersion}');
    RuntimeCheckMemo.Lines.Add('');
  end
  else
  begin
    RuntimeCheckMemo.Lines.Add('No existing MonClub Access installation detected.');
    RuntimeCheckMemo.Lines.Add('This package will run as a fresh installer.');
    RuntimeCheckMemo.Lines.Add('');
  end;

  RuntimeCheckMemo.Lines.Add('Installer runtime checks:');
  RuntimeCheckMemo.Lines.Add('');

  WebOk := IsWebView2RuntimePresent(WebVersion);
  if WebOk then
  begin
    if WebVersion <> '' then
      RuntimeCheckMemo.Lines.Add('[OK] WebView2 runtime detected (version: ' + WebVersion + ').')
    else
      RuntimeCheckMemo.Lines.Add('[OK] WebView2 runtime detected.');
  end
  else
  begin
    RuntimeHasWarning := True;
    RuntimeCheckMemo.Lines.Add('[WARN] WebView2 runtime not detected.');
    RuntimeCheckMemo.Lines.Add('       Tauri UI may not start until WebView2 Runtime is installed.');
  end;

  ZkOk := IsZkScannerDriverLikelyPresent(ZkDetails);
  if ZkOk then
    RuntimeCheckMemo.Lines.Add('[OK] ZKTeco driver hint detected: ' + ZkDetails)
  else
  begin
    RuntimeHasWarning := True;
    RuntimeCheckMemo.Lines.Add('[WARN] No clear ZKTeco scanner driver marker detected.');
    RuntimeCheckMemo.Lines.Add('       Fingerprint enrollment can fail until the correct ZKTeco driver is installed.');
  end;

  RuntimeCheckMemo.Lines.Add('');
  RuntimeCheckMemo.Lines.Add('Reference URLs:');
  RuntimeCheckMemo.Lines.Add('- WebView2 Runtime: https://go.microsoft.com/fwlink/p/?LinkId=2124703');
  RuntimeCheckMemo.Lines.Add('- ZKTeco: install the driver from your SDK package (same version as SDK DLLs).');
  RuntimeCheckMemo.Lines.Add('');
  RuntimeCheckMemo.Lines.Add('You can continue installation even with warnings.');

  if RuntimeHasWarning then
    RuntimeCheckStatusLabel.Caption := 'Status: warnings found. Click Next to continue or Cancel to stop.'
  else if ExistingInstallDetected then
    RuntimeCheckStatusLabel.Caption := 'Status: ready to update the existing installation.'
  else
    RuntimeCheckStatusLabel.Caption := 'Status: ready to install.';
end;

#include "update_safety.iss"

function InitializeSetup(): Boolean;
begin
  ExistingInstallRoot := DetectExistingInstallRoot();
  ExistingInstallDetected := Trim(ExistingInstallRoot) <> '';
  ExistingInstallVersion := '';
  if ExistingInstallDetected then
    TryReadInstalledVersion(ExistingInstallRoot, ExistingInstallVersion);

  // Same version only when current\ really holds it (exe + version.json, no leftover journal):
  // a re-run installer must be able to repair a half-written current\ (review #5).
  if SameVersionInstalled() and UpdCurrentComplete(ExistingInstallRoot) then
  begin
    // D22: silent -> no box, ABORTED same_version, app relaunched (update_safety.iss).
    UpdHandleSameVersion();
    Result := False;
    exit;
  end;

  Result := True;
end;

procedure InitializeWizard();
begin
  RuntimeCheckPage := CreateCustomPage(
    wpWelcome,
    'Runtime Prerequisite Check',
    'MonClub Access checks required runtimes before installation or update.'
  );

  RuntimeCheckStatusLabel := TNewStaticText.Create(RuntimeCheckPage);
  RuntimeCheckStatusLabel.Parent := RuntimeCheckPage.Surface;
  RuntimeCheckStatusLabel.Left := ScaleX(0);
  RuntimeCheckStatusLabel.Top := ScaleY(0);
  RuntimeCheckStatusLabel.Width := RuntimeCheckPage.SurfaceWidth;
  RuntimeCheckStatusLabel.AutoSize := False;
  RuntimeCheckStatusLabel.Height := ScaleY(18);

  RuntimeCheckMemo := TNewMemo.Create(RuntimeCheckPage);
  RuntimeCheckMemo.Parent := RuntimeCheckPage.Surface;
  RuntimeCheckMemo.Left := ScaleX(0);
  RuntimeCheckMemo.Top := ScaleY(24);
  RuntimeCheckMemo.Width := RuntimeCheckPage.SurfaceWidth;
  RuntimeCheckMemo.Height := RuntimeCheckPage.SurfaceHeight - ScaleY(24);
  RuntimeCheckMemo.ReadOnly := True;
  RuntimeCheckMemo.ScrollBars := ssVertical;
  RuntimeCheckMemo.WordWrap := True;

  RunRuntimeChecks();
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (Assigned(RuntimeCheckPage)) and (CurPageID = RuntimeCheckPage.ID) then
    RunRuntimeChecks();
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;

  if (Assigned(RuntimeCheckPage)) and (CurPageID = RuntimeCheckPage.ID) then
  begin
    RunRuntimeChecks();

    if RuntimeHasWarning and not WizardSilent() then
      Result := (MsgBox(
        'Some runtime checks returned warnings (WebView2 and/or ZKTeco driver).' + #13#10 +
        'Continue installation anyway?',
        mbConfirmation,
        MB_YESNO or MB_DEFBUTTON2
      ) = IDYES);
    // In silent mode (WizardSilent = True): proceed regardless of warnings.
    // The app may not function correctly if WebView2/ZKTeco is missing,
    // but a silent update should never block due to a warning dialog.
  end;
end;

// Review #3: the journal-aware watchdog and its helper must be in {app}\watchdog before
// current\ is touched (on an update from 1.4.x the old watchdog has no journal rule).
procedure InstallWatchdogEarly(const Root: string);
var
  Dir: string;
begin
  Dir := AddBackslash(Root) + 'watchdog';
  if not DirExists(Dir) then exit;   // fresh install: [Files] puts them there
  ExtractTemporaryFile('monclub_access_watchdog.ps1');
  if FileCopy(UpdHelperPath(), Dir + '\update_helper.ps1', False) and
     FileCopy(ExpandConstant('{tmp}\monclub_access_watchdog.ps1'), Dir + '\monclub_access_watchdog.ps1', False) then
    Log('Watchdog + update_helper updated in ' + Dir + ' before the swap')
  else
    Log('WARNING: could not update ' + Dir + ' before the swap');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Root: string;
begin
  // NeedsRestart is never set: the 1.4.35 client starts Setup without /NORESTART.
  Root := RemoveBackslashUnlessRoot(ExpandConstant('{app}'));

  // The watchdog stands down on this sentinel while Setup stops the app, swaps current\
  // and waits for the new version (it ages out after 30 min on the watchdog side).
  UpdSetPauseSentinel(Root);

  KillRunningMonClubProcesses();
  Sleep(900);

  InstallWatchdogEarly(Root);

  // Back up current\ -> previous\ and empty current\ (never DelTree it, D21). On failure the
  // old app is restarted, ABORTED is recorded and Setup stops here.
  Result := UpdPrepareBackup();
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    RegisterZkemkeeper();
    // Health wait / rollback / result, then the sentinel is cleared (update_safety.iss).
    UpdPostInstall();
  end;
end;

procedure DeinitializeSetup();
begin
  UpdDeinitialize();
end;

function OtherProductInstalled(): Boolean;
begin
  Result := RegKeyExists(HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#OtherUninstallKeyName}') or
            RegKeyExists(HKEY_LOCAL_MACHINE, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#OtherUninstallKeyName}');
end;

procedure DeleteDataDir(const PathValue: string);
begin
  if DirExists(PathValue) then
  begin
    if DelTree(PathValue, True, True, True) then
      Log('Deleted data: ' + PathValue)
    else
      Log('Could not fully delete data: ' + PathValue);
  end;
end;

// D26. The data root is shared with MonClub TV (app/core/utils.py DATA_ROOT). TV keeps its
// own data in DATA_ROOT\tv (tv/storage.py, app/core/tv_local_cache.py) and both apps use
// DATA_ROOT\shared (install.json, single-instance locks). Access owns data\ (legacy combined
// app.db -- which TV only READS to import the login, tv/auth_bridge.py -- logs, cache),
// access\ (access.db, erase backups), backups\ and versions\. While TV is installed only
// those go; otherwise the whole root, as before.
procedure RemoveAccessData(const Root: string);
begin
  if not DirExists(Root) then exit;
  if OtherProductInstalled() then
  begin
    Log('MonClub TV is installed: removing only the Access data under ' + Root);
    DeleteDataDir(AddBackslash(Root) + 'data');
    DeleteDataDir(AddBackslash(Root) + 'access');
    DeleteDataDir(AddBackslash(Root) + 'backups');
    DeleteDataDir(AddBackslash(Root) + 'versions');
  end
  else
    DeleteDataDir(Root);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    // Stop the watchdog from resurrecting the app we are about to remove.
    // [UninstallRun] unregisters the task, but that runs after this step.
    UpdSetPauseSentinel(RemoveBackslashUnlessRoot(ExpandConstant('{app}')));

    // Drop our own COM registration before {app} is deleted, otherwise the
    // CLSID is left pointing at a file that no longer exists.
    UnregisterZkemkeeper();
    KillRunningMonClubProcesses();
    Sleep(900);
  end;
  if CurUninstallStep = usPostUninstall then
  begin
    RemoveAccessData(ExpandConstant('{commonappdata}\MonClub Access'));
    RemoveAccessData(ExpandConstant('{localappdata}\MonClub Access'));
  end;
end;
