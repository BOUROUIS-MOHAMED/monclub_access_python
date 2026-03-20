; installer\MonClubTV.iss

#define AppName "MonClubTV"

#ifndef ReleaseId
  #define ReleaseId "DEV"
#endif

#ifndef StageDir
  #error StageDir define is missing. Pass /DStageDir="full\path\to\staged\MonClubTV"
#endif

#ifndef UpdaterSourcePath
  #error UpdaterSourcePath define is missing. Pass /DUpdaterSourcePath="full\path\to\MonClubDesktopUpdater.exe"
#endif

#ifndef UpdaterDestExe
  #define UpdaterDestExe "MonClubTVUpdater.exe"
#endif

#define AppVersion ReleaseId
#define AppPublisher "MonClub"
#define MainExe "MonClubTV.exe"
#define TauriExe "monclub-tv-ui.exe"

#define SetupIcon "assets\setup.ico"
#define WizardImage "assets\wizard.bmp"
#define WizardSmall "assets\wizard_small.bmp"

[Setup]
AppId={{4A8D6A8A-7AC6-4C87-862D-2E5A6B644D27}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
SetupIconFile={#SetupIcon}
WizardImageFile={#WizardImage}
WizardSmallImageFile={#WizardSmall}
DefaultDirName={localappdata}\MonClubTV
PrivilegesRequired=lowest
UsePreviousAppDir=no
UsePreviousTasks=no
CloseApplications=yes
CloseApplicationsFilter={#MainExe},{#TauriExe},{#UpdaterDestExe}
RestartApplications=no
DisableProgramGroupPage=yes
OutputDir=..\release
OutputBaseFilename=MonClubTVSetup-{#ReleaseId}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "startmenuicon"; Description: "Create a &Start Menu shortcut"; GroupDescription: "Additional icons:"; Flags: checkedonce
Name: "desktopicon"; Description: "Create a &Desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Dirs]
Name: "{app}\current"
Name: "{app}\updater"
Name: "{app}\downloads"
Name: "{app}\downloads\windows"
Name: "{app}\downloads\windows\stable"
Name: "{app}\downloads\windows\beta"
Name: "{app}\logs"

[Files]
Source: "{#StageDir}\*"; DestDir: "{app}\current"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#UpdaterSourcePath}"; DestDir: "{app}\updater"; DestName: "{#UpdaterDestExe}"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\MonClubTV"; Filename: "{app}\current\{#MainExe}"; Tasks: startmenuicon
Name: "{userdesktop}\MonClubTV"; Filename: "{app}\current\{#MainExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\current\{#MainExe}"; Description: "Launch MonClubTV"; Flags: nowait postinstall skipifsilent

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
  Log('Ensuring MonClub TV processes are stopped...');
  ExecAndLog('taskkill /F /T /IM "MonClubTV.exe"');
  ExecAndLog('taskkill /F /T /IM "monclub-tv-ui.exe"');
  ExecAndLog('taskkill /F /T /IM "{#UpdaterDestExe}"');
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

procedure RunRuntimeChecks();
var
  WebVersion: string;
  WebOk: Boolean;
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

  RuntimeCheckMemo.Lines.Add('');
  RuntimeCheckMemo.Lines.Add('Reference URL:');
  RuntimeCheckMemo.Lines.Add('- WebView2 Runtime: https://go.microsoft.com/fwlink/p/?LinkId=2124703');
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
    'MonClub TV checks required runtimes before installation.'
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
        'WebView2 runtime warning detected.' + #13#10 +
        'Continue installation anyway?',
        mbConfirmation,
        MB_YESNO or MB_DEFBUTTON2
      ) = IDYES);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';

  KillRunningMonClubProcesses();
  Sleep(900);

  DeleteTreeIfExists(ExpandConstant('{localappdata}\MonClubTV'));
  DeleteTreeIfExists(ExpandConstant('{commonappdata}\MonClub TV'));
  DeleteTreeIfExists(ExpandConstant('{localappdata}\MonClub TV'));
  DeleteTreeIfExists(ExpandConstant('{userappdata}\MonClub TV'));
  DeleteTreeIfExists(ExpandConstant('{userappdata}\MonClubTV'));
end;
