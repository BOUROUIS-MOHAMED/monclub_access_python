; installer\MonClubTV.iss
; Build with:
;   ISCC.exe installer\MonClubTV.iss /DAppVersion=1.0.0 /DStageDir="C:\...\release\_staging\MonClubTV-20260326-120000Z\MonClubTV" /DOutputBaseFilename=monclub_tv_1.0.0

#define AppName "MonClub TV"

#ifndef AppVersion
  #error AppVersion define is missing. Pass /DAppVersion=1.0.0
#endif

#ifndef ReleaseId
  #define ReleaseId "DEV"
#endif

#ifndef StageDir
  #error StageDir define is missing. Pass /DStageDir="full\path\to\staged\MonClubTV"
#endif

#ifndef OutputBaseFilename
  #define OutputBaseFilename "monclub_tv"
#endif

#define AppPublisher "MonClub"
#define MainExe "MonClubTV.exe"
#define TauriExe "monclub-tv-ui.exe"
#define DefaultInstallRoot "{localappdata}\MonClubTV"
#define LegacyInstallRoot "{localappdata}\MonClub TV"
; Inno's uninstall registry key for this AppId (HKCU, PrivilegesRequired=lowest).
#define UninstallKeyName "{4A8D6A8A-7AC6-4C87-862D-2E5A6B644D27}_is1"
; MonClub Access's key: the TV uninstall keeps the shared data while Access is installed (D26).
#define OtherUninstallKeyName "{9B77A9C2-2B97-4F62-A9E8-4B4C65F3A9B1}_is1"

#ifdef UPDATER_TEST_FAIL
  ; Test-only build (build_installer.ps1 -TestFail). The file name says so, and
  ; publish_github_release.ps1 refuses the release file such a build writes.
  #define OutputBaseFilename OutputBaseFilename + "_TESTFAIL_" + UPDATER_TEST_FAIL
#endif

#define SetupIcon "assets\monclub_tv.ico"
#define WizardImage "assets\tv_wizard.bmp"
#define WizardSmall "assets\tv_wizard_small.bmp"

[Setup]
; Built with Python 3.14, which runs on Windows 10 and newer only.
MinVersion=10.0
AppId={{4A8D6A8A-7AC6-4C87-862D-2E5A6B644D27}
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
; Always write Setup's log (%TEMP%\Setup Log <date> #<n>.txt), as /LOG would (D32): the 1.4.35
; in-app update passes no /LOG. The v2 client passes /LOG=<install_root>\logs\update-<ver>-<ts>.log;
; last_update.json records which file it was ("log").
SetupLogging=yes

[Tasks]
; Start Menu shortcut: ticked for a new install; an existing install keeps its previous choice
; (UsePreviousTasks=yes). NOT Flags: checkedonce -- it unticks a previously ticked task at every
; update (Inno Setup source, Setup.WizardForm.pas, TWizardForm.CreateTaskButtons; D32, same fix
; as MonClubAccess.iss).
Name: "startmenuicon"; Description: "Create a &Start Menu shortcut"; GroupDescription: "Additional icons:"
Name: "desktopicon"; Description: "Create a &Desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Dirs]
; The DATA root (app/core/utils.py::_candidate_data_roots, ProgramData first), SHARED by Access
; and TV: BUILTIN\Users get Modify on it, inherited by everything below. Without it, a root an
; ELEVATED launch created holds admin-owned files Users can only read, and every normal or
; watchdog launch dies on "attempt to write a readonly database" (owner's PC, 2026-10-17).
; Setup runs at PrivilegesRequired=lowest: it can set these permissions on a root it creates
; (or one its user owns), and on any root when Setup itself is elevated; otherwise Inno skips
; them silently (Inno help, [Dirs] Permissions) and the app's own repair on an elevated launch
; does it (shared/data_root_permissions.py). Whether Inno re-applies them to files already in
; the folder is [UNVERIFIED]. uninsneveruninstall: the data root is removed by
; CurUninstallStepChanged (D26), never by this entry. Check: see DataRootDirWanted.
Name: "{commonappdata}\MonClub Access"; Permissions: users-modify; Flags: uninsneveruninstall; Check: DataRootDirWanted
Name: "{app}\current"
Name: "{app}\downloads"
Name: "{app}\logs"
Name: "{app}\state"

[Files]
; Safe-swap helper (updater v2), extracted to {tmp} for Setup's own use.
Source: "update_helper.ps1"; Flags: dontcopy
; Also installed: the v2 client's install wrapper and start-up restore run
; {app}\watchdog\update_helper.ps1 -Action recover (the one journal rule, design 8.0; L4 review H1).
Source: "update_helper.ps1"; DestDir: "{app}\watchdog"; Flags: ignoreversion
; version.json and then the exe are copied LAST (Inno installs [Files] in script order): if
; power is cut during the copy, a present exe means the whole payload is there, and a
; version.json without the exe is never taken for an installed version (review #3 / #5).
Source: "{#StageDir}\*"; Excludes: "\{#MainExe},\version.json"; DestDir: "{app}\current"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#StageDir}\version.json"; DestDir: "{app}\current"; Flags: ignoreversion
Source: "{#StageDir}\{#MainExe}"; DestDir: "{app}\current"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\MonClubTV"; Filename: "{app}\current\{#MainExe}"; Tasks: startmenuicon
Name: "{userdesktop}\MonClubTV"; Filename: "{app}\current\{#MainExe}"; Tasks: desktopicon

[Run]
; Interactive installs only. A silent install/update starts the app itself in ssPostInstall
; (update_safety.iss) and waits for it to prove it is healthy, rolling back if not.
Filename: "{app}\current\{#MainExe}"; Description: "Launch MonClub TV"; Flags: nowait postinstall; Check: not WizardSilent

[UninstallDelete]
Type: files; Name: "{userprograms}\MonClubTV.lnk"
Type: files; Name: "{userdesktop}\MonClubTV.lnk"
Type: filesandordirs; Name: "{app}\previous"
Type: filesandordirs; Name: "{app}\current.failed"
Type: filesandordirs; Name: "{app}\state"
Type: filesandordirs; Name: "{app}\downloads"
Type: filesandordirs; Name: "{app}"
; D26: TV's data is NOT in "MonClub TV" folders (nothing reads them). It lives in the data
; root SHARED with MonClub Access (app/core/utils.py DATA_ROOT = {commonappdata}\MonClub Access,
; else {localappdata}\MonClub Access), sub-folder tv\ -- removed in
; CurUninstallStepChanged(usPostUninstall).

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

function DataRootDirWanted(): Boolean;
begin
  // The [Dirs] data-root entry: only when that root exists already, or when no database sits in
  // the {localappdata} fallback root. The app takes ProgramData first as soon as it can create
  // it there (_pick_data_root), so creating it on a PC whose live data fell back to
  // {localappdata} would make the next start open an EMPTY database. Files, not the folder:
  // {localappdata}\MonClub Access is also the LEGACY install root (LegacyInstallRoot).
  Result := DirExists(ExpandConstant('{commonappdata}\MonClub Access')) or
    ((not FileExists(ExpandConstant('{localappdata}\MonClub Access\access\access.db'))) and
     (not FileExists(ExpandConstant('{localappdata}\MonClub Access\data\app.db'))) and
     (not FileExists(ExpandConstant('{localappdata}\MonClub Access\tv\tv.db'))));
end;

function GetInstallRootDefault(Param: string): string;
begin
  if ExistingInstallDetected and (Trim(ExistingInstallRoot) <> '') then
    Result := ExistingInstallRoot
  else
    Result := DefaultInstallRoot();
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
  Log('Ensuring MonClub TV processes are stopped...');
  ExecAndLog('taskkill /F /T /IM "{#MainExe}"');
  ExecAndLog('taskkill /F /T /IM "{#TauriExe}"');
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

procedure RunRuntimeChecks();
var
  WebVersion: string;
  WebOk: Boolean;
begin
  RuntimeHasWarning := False;
  RuntimeCheckMemo.Lines.Clear;

  if SameVersionInstalled() then
  begin
    RuntimeCheckMemo.Lines.Add('MonClub TV ' + '{#AppVersion}' + ' is already installed.');
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
    RuntimeCheckMemo.Lines.Add('No existing MonClub TV installation detected.');
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

  RuntimeCheckMemo.Lines.Add('');
  RuntimeCheckMemo.Lines.Add('Reference URL:');
  RuntimeCheckMemo.Lines.Add('- WebView2 Runtime: https://go.microsoft.com/fwlink/p/?LinkId=2124703');
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
    'MonClub TV checks required runtimes before installation or update.'
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
        'WebView2 runtime warning detected.' + #13#10 +
        'Continue installation anyway?',
        mbConfirmation,
        MB_YESNO or MB_DEFBUTTON2
      ) = IDYES);
    // In silent mode (WizardSilent = True): proceed regardless of warnings.
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Root: string;
begin
  // NeedsRestart is never set: the 1.4.35 client starts Setup without /NORESTART.
  Root := RemoveBackslashUnlessRoot(ExpandConstant('{app}'));
  if UpdAnotherSetupRunning(Root) then
  begin
    Result := '{#AppName}: another installer is already running; try again when it has finished.';
    exit;
  end;
  UpdSetPauseSentinel(Root);

  KillRunningMonClubProcesses();
  Sleep(900);

  // Back up current\ -> previous\ and empty current\ (never DelTree it, D21). On failure the
  // old app is restarted, ABORTED is recorded and Setup stops here.
  Result := UpdPrepareBackup();
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    UpdPostInstall();
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

// D26. TV's own data is DATA_ROOT\tv (tv/storage.py: tv.db, config; app/core/tv_local_cache.py:
// tv\media) -- always TV's, always removed. DATA_ROOT\shared (install.json, single-instance
// locks) is shared with Access: removed only when Access is not installed. Everything else
// under the root is Access's and is never deleted here; empty folders TV's start-up created
// (ensure_dirs) are removed when they are empty, and the root when it is empty.
procedure RemoveTvData(const Root: string);
begin
  if not DirExists(Root) then exit;
  DeleteDataDir(AddBackslash(Root) + 'tv');
  if OtherProductInstalled() then
  begin
    Log('MonClub Access is installed: keeping the shared data under ' + Root);
    exit;
  end;
  DeleteDataDir(AddBackslash(Root) + 'shared');
  // RemoveDir only removes EMPTY folders: Access data, if any, is never touched.
  RemoveDir(AddBackslash(Root) + 'data\logs');
  RemoveDir(AddBackslash(Root) + 'data\cache\images');
  RemoveDir(AddBackslash(Root) + 'data\cache');
  RemoveDir(AddBackslash(Root) + 'data');
  RemoveDir(AddBackslash(Root) + 'access\logs');
  RemoveDir(AddBackslash(Root) + 'access');
  RemoveDir(AddBackslash(Root) + 'backups');
  RemoveDir(AddBackslash(Root) + 'versions');
  if RemoveDir(Root) then Log('Removed empty data root ' + Root);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    KillRunningMonClubProcesses();
    Sleep(900);
  end;
  if CurUninstallStep = usPostUninstall then
  begin
    RemoveTvData(ExpandConstant('{commonappdata}\MonClub Access'));
    RemoveTvData(ExpandConstant('{localappdata}\MonClub Access'));
  end;
end;
