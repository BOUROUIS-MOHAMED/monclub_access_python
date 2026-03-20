; installer\MonClubAccess.iss
; Build with:
;   ISCC.exe installer\MonClubAccess.iss /DReleaseId=20260210-124245Z /DStageDir="C:\...\release\_staging\MonClubAccess-20260210-124245Z\MonClubAccess"

#define AppName "MonClubAccess"

#ifndef ReleaseId
  #define ReleaseId "DEV"
#endif

#ifndef StageDir
  #error StageDir define is missing. Pass /DStageDir="full\path\to\staged\MonClubAccess"
#endif

#ifndef UpdaterSourcePath
  #error UpdaterSourcePath define is missing. Pass /DUpdaterSourcePath="full\path\to\MonClubDesktopUpdater.exe"
#endif

#ifndef UpdaterDestExe
  #define UpdaterDestExe "MonClubAccessUpdater.exe"
#endif

#define AppVersion ReleaseId
#define AppPublisher "MonClub"
#define MainExe "MonClubAccess.exe"

; Branding assets (relative to this .iss file)
#define SetupIcon "assets\setup.ico"
#define WizardImage "assets\wizard.bmp"
#define WizardSmall "assets\wizard_small.bmp"

[Setup]
AppId={{9B77A9C2-2B97-4F62-A9E8-4B4C65F3A9B1}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}

; Installer EXE icon
SetupIconFile={#SetupIcon}

; Installer wizard branding images
WizardImageFile={#WizardImage}
WizardSmallImageFile={#WizardSmall}

; Install per-user (no admin) so auto-updates can write without UAC.
DefaultDirName={localappdata}\MonClubAccess
PrivilegesRequired=lowest
UsePreviousAppDir=no
UsePreviousTasks=no
CloseApplications=yes
CloseApplicationsFilter=MonClubAccess.exe,monclub-access-ui.exe,{#UpdaterDestExe}
RestartApplications=no

DisableProgramGroupPage=yes
OutputDir=..\release
OutputBaseFilename=MonClubAccessSetup-{#ReleaseId}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "startmenuicon"; Description: "Create a &Start Menu shortcut"; GroupDescription: "Additional icons:"; Flags: checkedonce
Name: "desktopicon"; Description: "Create a &Desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Dirs]
; Pre-create update layout (nice for cleaner runtime behavior)
Name: "{app}\current"
Name: "{app}\updater"
Name: "{app}\downloads"
Name: "{app}\downloads\windows"
Name: "{app}\downloads\windows\stable"
Name: "{app}\downloads\windows\beta"
Name: "{app}\logs"

[Files]
; Install staged folder under {app}\current\...
Source: "{#StageDir}\*"; DestDir: "{app}\current"; Flags: ignoreversion recursesubdirs createallsubdirs

; Ship updater exe into {app}\updater
Source: "{#UpdaterSourcePath}"; DestDir: "{app}\updater"; DestName: "{#UpdaterDestExe}"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\MonClubAccess"; Filename: "{app}\current\{#MainExe}"; Tasks: startmenuicon
Name: "{userdesktop}\MonClubAccess"; Filename: "{app}\current\{#MainExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\current\{#MainExe}"; Description: "Launch MonClubAccess"; Flags: nowait postinstall skipifsilent

[Code]
const
  WebView2ClientId = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';

var
  RuntimeCheckPage: TWizardPage;
  RuntimeCheckStatusLabel: TNewStaticText;
  RuntimeCheckMemo: TNewMemo;
  RuntimeHasWarning: Boolean;

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
  Log('Ensuring MonClub processes are stopped...');
  ExecAndLog('taskkill /F /T /IM "MonClubAccess.exe"');
  ExecAndLog('taskkill /F /T /IM "monclub-access-ui.exe"');
  ExecAndLog('taskkill /F /T /IM "MonClubAccessUpdater.exe"');
end;

procedure DeleteTreeIfExists(const PathValue: string);
begin
  if DirExists(PathValue) then
  begin
    Log('Deleting directory tree: ' + PathValue);
    if DelTree(PathValue, True, True, True) then
      Log('Deleted: ' + PathValue)
    else
      Log('Delete failed or partially failed: ' + PathValue);
  end;
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
  else
    RuntimeCheckStatusLabel.Caption := 'Status: checks passed.';
end;

procedure InitializeWizard();
begin
  RuntimeCheckPage := CreateCustomPage(
    wpWelcome,
    'Runtime Prerequisite Check',
    'MonClub Access checks required runtimes before installation.'
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

    if RuntimeHasWarning then
      Result := (MsgBox(
        'Some runtime checks returned warnings (WebView2 and/or ZKTeco driver).' + #13#10 +
        'Continue installation anyway?',
        mbConfirmation,
        MB_YESNO or MB_DEFBUTTON2
      ) = IDYES);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';

  { Fresh install behavior requested:
    - stop running app/UI/updater
    - remove previous install folder
    - remove persisted data roots (ProgramData/LocalAppData/Roaming) }
  KillRunningMonClubProcesses();
  Sleep(900);

  DeleteTreeIfExists(ExpandConstant('{localappdata}\MonClubAccess'));
  DeleteTreeIfExists(ExpandConstant('{commonappdata}\MonClub Access'));
  DeleteTreeIfExists(ExpandConstant('{localappdata}\MonClub Access'));
  DeleteTreeIfExists(ExpandConstant('{userappdata}\MonClub Access'));
  DeleteTreeIfExists(ExpandConstant('{userappdata}\MonClubAccess'));
end;
