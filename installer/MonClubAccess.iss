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

; Branding assets (relative to this .iss file)
#define SetupIcon "assets\setup.ico"
#define WizardImage "assets\wizard.bmp"
#define WizardSmall "assets\wizard_small.bmp"

[Setup]
AppId={{9B77A9C2-2B97-4F62-A9E8-4B4C65F3A9B1}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
SetupIconFile={#SetupIcon}
WizardImageFile={#WizardImage}
WizardSmallImageFile={#WizardSmall}
DefaultDirName={code:GetInstallRootDefault}
PrivilegesRequired=lowest
UsePreviousAppDir=yes
UsePreviousTasks=yes
CloseApplications=yes
CloseApplicationsFilter={#MainExe},{#TauriExe},MonClubAccessUpdater.exe
RestartApplications=no
DisableProgramGroupPage=yes
OutputDir=..\release
OutputBaseFilename={#OutputBaseFilename}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "startmenuicon"; Description: "Create a &Start Menu shortcut"; GroupDescription: "Additional icons:"; Flags: checkedonce
Name: "desktopicon"; Description: "Create a &Desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Dirs]
Name: "{app}\current"
Name: "{app}\downloads"
Name: "{app}\downloads\windows"
Name: "{app}\downloads\windows\stable"
Name: "{app}\downloads\windows\beta"
Name: "{app}\logs"

[Files]
Source: "{#StageDir}\*"; DestDir: "{app}\current"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{userprograms}\MonClubAccess"; Filename: "{app}\current\{#MainExe}"; Tasks: startmenuicon
Name: "{userdesktop}\MonClubAccess"; Filename: "{app}\current\{#MainExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\current\{#MainExe}"; Description: "Launch MonClub Access"; Flags: nowait postinstall

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
Type: filesandordirs; Name: "{commonappdata}\MonClub Access"
Type: filesandordirs; Name: "{localappdata}\MonClub Access"
Type: filesandordirs; Name: "{userappdata}\MonClub Access"
Type: filesandordirs; Name: "{userappdata}\MonClubAccess"

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

function InitializeSetup(): Boolean;
begin
  ExistingInstallRoot := DetectExistingInstallRoot();
  ExistingInstallDetected := Trim(ExistingInstallRoot) <> '';
  ExistingInstallVersion := '';
  if ExistingInstallDetected then
    TryReadInstalledVersion(ExistingInstallRoot, ExistingInstallVersion);

  if SameVersionInstalled() then
  begin
    MsgBox(
      'MonClub Access version ' + '{#AppVersion}' + ' is already installed on this PC.' + #13#10 +
      'Nothing will be changed.',
      mbInformation,
      MB_OK
    );
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

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';

  KillRunningMonClubProcesses();
  Sleep(900);

  DeleteTreeIfExists(ExpandConstant('{app}\current'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    KillRunningMonClubProcesses();
    Sleep(900);
  end;
end;
