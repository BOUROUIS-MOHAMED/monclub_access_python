// installer\update_safety.iss -- updater v2 safe swap, shared by MonClubAccess.iss and MonClubTV.iss.
// #include'd inside [Code] AFTER the host has defined: MainExe, TauriExe, AppName, AppVersion,
// UninstallKeyName (defines) and ExistingInstallRoot, ExistingInstallVersion,
// ExistingInstallDetected, PathHasInstalledPayload, TryReadInstalledVersion, ExecAndLog,
// KillRunningMonClubProcesses (code).
//
// Design: docs\access-updater-v2\design.md section 8 (the journal / last_update.json contract
// is in 8.0). The heavy lifting (copy, restore, health wait, process lookup by path) is in
// update_helper.ps1, extracted to {tmp}; this file decides WHEN and records the result.
//
// Rules this file exists to keep:
//   - never DelTree {app}\current; never rename it (working-directory trap, 8.0);
//   - every path that ends Setup after the app was stopped writes last_update.json FIRST and
//     then starts the old (or new, if healthy) app -- the 1.4.35 client has no wrapper;
//   - no message box in silent mode; never ask for a restart (NeedsRestart stays False).

#ifdef UPDATER_TEST_FAIL
  #if UPDATER_TEST_FAIL != "after_copy" && UPDATER_TEST_FAIL != "health" && UPDATER_TEST_FAIL != "crash"
    #error UPDATER_TEST_FAIL must be after_copy, health or crash
  #endif
#endif

type
  TUpdSystemTime = record
    wYear: Word;
    wMonth: Word;
    wDayOfWeek: Word;
    wDay: Word;
    wHour: Word;
    wMinute: Word;
    wSecond: Word;
    wMilliseconds: Word;
  end;

procedure UpdGetSystemTime(var T: TUpdSystemTime);
  external 'GetSystemTime@kernel32.dll stdcall';

var
  UpdInstallRoot: string;     // {app}, captured once it is known (PrepareToInstall)
  UpdFromVersion: string;     // version found in current\version.json before the swap
  UpdHelper: string;          // extracted update_helper.ps1
  UpdBackupDone: Boolean;     // previous\ holds the old version, current\ was emptied
  UpdFinalized: Boolean;      // a terminal result was handled; DeinitializeSetup does nothing
  UpdRolledBackTo: string;    // set after a post-install rollback (uninstall key fix-up)

function UpdPad(Value, Width: Integer): string;
begin
  Result := IntToStr(Value);
  while Length(Result) < Width do
    Result := '0' + Result;
end;

function UpdUtcStamp(): string;
var
  T: TUpdSystemTime;
begin
  UpdGetSystemTime(T);
  Result := UpdPad(T.wYear, 4) + '-' + UpdPad(T.wMonth, 2) + '-' + UpdPad(T.wDay, 2) + 'T' +
            UpdPad(T.wHour, 2) + ':' + UpdPad(T.wMinute, 2) + ':' + UpdPad(T.wSecond, 2) + 'Z';
end;

function UpdHex4(Value: Integer): string;
var
  Digits: string;
  i: Integer;
begin
  Digits := '0123456789abcdef';
  Result := '';
  for i := 1 to 4 do
  begin
    Result := Copy(Digits, (Value mod 16) + 1, 1) + Result;
    Value := Value div 16;
  end;
end;

// JSON string body, ASCII only (non-ASCII as \uXXXX) so the file reads the same in any codec.
function UpdJsonEscape(const S: string): string;
var
  i: Integer;
  C: Char;
begin
  Result := '';
  for i := 1 to Length(S) do
  begin
    C := S[i];
    if C = '\' then Result := Result + '\\'
    else if C = '"' then Result := Result + '\"'
    else if Ord(C) < 32 then Result := Result + '\u' + UpdHex4(Ord(C))
    else if Ord(C) > 127 then Result := Result + '\u' + UpdHex4(Ord(C))
    else Result := Result + C;
  end;
end;

function UpdSetupLogPath(): string;
begin
  try
    Result := ExpandConstant('{log}');
  except
    Result := '';
  end;
end;

procedure UpdWriteFileAtomic(const PathValue, Content: string);
var
  TmpPath: string;
begin
  ForceDirectories(ExtractFileDir(PathValue));
  TmpPath := PathValue + '.tmp';
  if not SaveStringToFile(TmpPath, Content, False) then
  begin
    Log('WARNING: could not write ' + TmpPath);
    exit;
  end;
  if FileExists(PathValue) then
    DeleteFile(PathValue);
  if not RenameFile(TmpPath, PathValue) then
    Log('WARNING: could not rename ' + TmpPath + ' -> ' + PathValue);
end;

procedure UpdWriteLastUpdate(const Root, ResultValue, FromValue, ToValue, Reason: string);
var
  Json: string;
begin
  if Root = '' then
  begin
    Log('last_update.json not written (install root unknown): ' + ResultValue + ' ' + Reason);
    exit;
  end;
  Json := '{"result":"' + UpdJsonEscape(ResultValue) + '",' +
          '"from":"' + UpdJsonEscape(FromValue) + '",' +
          '"to":"' + UpdJsonEscape(ToValue) + '",' +
          '"reason":"' + UpdJsonEscape(Reason) + '",' +
          '"log":"' + UpdJsonEscape(UpdSetupLogPath()) + '",' +
          '"at":"' + UpdUtcStamp() + '"}';
  UpdWriteFileAtomic(AddBackslash(Root) + 'state\last_update.json', Json);
  Log('last_update.json: ' + Json);
end;

procedure UpdDeleteJournal(const Root: string);
var
  J: string;
begin
  J := AddBackslash(Root) + 'state\install_journal.json';
  if FileExists(J) then
  begin
    if DeleteFile(J) then Log('install journal deleted') else Log('WARNING: could not delete ' + J);
  end;
end;

function UpdPauseSentinelPath(const Root: string): string;
begin
  Result := AddBackslash(Root) + '.update-in-progress';
end;

procedure UpdSetPauseSentinel(const Root: string);
begin
  // The Access watchdog stands down while this file is fresh (< 30 min), so it cannot
  // relaunch the app from a half-replaced current\ while this Setup works.
  ForceDirectories(Root);
  if SaveStringToFile(UpdPauseSentinelPath(Root), 'install in progress', False) then
    Log('Pause sentinel written: ' + UpdPauseSentinelPath(Root))
  else
    Log('WARNING: could not write pause sentinel: ' + UpdPauseSentinelPath(Root));
end;

procedure UpdClearPauseSentinel(const Root: string);
begin
  if (Root <> '') and FileExists(UpdPauseSentinelPath(Root)) then
  begin
    if DeleteFile(UpdPauseSentinelPath(Root)) then
      Log('Pause sentinel cleared.')
    else
      Log('WARNING: could not delete pause sentinel; it will age out on its own.');
  end;
end;

function UpdHelperPath(): string;
begin
  if UpdHelper = '' then
  begin
    ExtractTemporaryFile('update_helper.ps1');
    UpdHelper := ExpandConstant('{tmp}\update_helper.ps1');
  end;
  Result := UpdHelper;
end;

function UpdPowerShell(): string;
begin
  Result := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  if not FileExists(Result) then
    Result := 'powershell.exe';
end;

// Runs update_helper.ps1 and copies its log into Setup's log. Returns its exit code, or -1
// when PowerShell could not be started at all. Working directory = {tmp}, never current\.
function UpdRunHelper(const Action, Root, Extra: string): Integer;
var
  Params, HelperLog: string;
  RC, i: Integer;
  Lines: TArrayOfString;
begin
  Result := -1;
  HelperLog := ExpandConstant('{tmp}\update_helper_' + Action + '.log');
  DeleteFile(HelperLog);
  Params := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden' +
            ' -File "' + UpdHelperPath() + '"' +
            ' -Action ' + Action +
            ' -InstallRoot "' + RemoveBackslashUnlessRoot(Root) + '"' +
            ' -AppExe "{#MainExe}" -UiExe "{#TauriExe}"' +
            ' -FromVersion "' + UpdFromVersion + '" -ToVersion "{#AppVersion}"' +
            ' -LogPath "' + HelperLog + '"' + Extra;
  Log('update_helper ' + Action + ': ' + UpdPowerShell() + ' ' + Params);
  if Exec(UpdPowerShell(), Params, ExpandConstant('{tmp}'), SW_HIDE, ewWaitUntilTerminated, RC) then
    Result := RC
  else
    Log('update_helper ' + Action + ': PowerShell could not be started: ' + SysErrorMessage(RC));
  if LoadStringsFromFile(HelperLog, Lines) then
    for i := 0 to GetArrayLength(Lines) - 1 do
      Log('  ' + Lines[i]);
  Log('update_helper ' + Action + ' exit=' + IntToStr(Result));
end;

// Start the installed app from current\ unless it already runs from there. Falls back to a
// direct start when PowerShell is unusable, so this never depends on the helper alone.
procedure UpdRelaunch(const Root: string);
var
  Exe: string;
  RC: Integer;
begin
  if Root = '' then exit;
  Exe := AddBackslash(Root) + 'current\{#MainExe}';
  if UpdRunHelper('relaunch', Root, '') = 0 then exit;
  if FileExists(Exe) then
  begin
    if Exec(Exe, '', AddBackslash(Root) + 'current', SW_SHOWNORMAL, ewNoWait, RC) then
      Log('Relaunched directly: ' + Exe)
    else
      Log('ERROR: could not relaunch ' + Exe + ': ' + SysErrorMessage(RC));
  end
  else
    Log('ERROR: nothing to relaunch, ' + Exe + ' is missing');
end;

function UpdTestFailIs(const Mode: string): Boolean;
begin
#ifdef UPDATER_TEST_FAIL
  Result := CompareText('{#UPDATER_TEST_FAIL}', Mode) = 0;
#else
  Result := False;
#endif
end;

// SAME VERSION (D22). Called from InitializeSetup, where {app} is not yet known: works on
// ExistingInstallRoot. Silent: no box, record ABORTED, make sure the app runs again.
procedure UpdHandleSameVersion();
begin
  UpdFinalized := True;
  UpdFromVersion := ExistingInstallVersion;
  if WizardSilent() then
  begin
    Log('Same version {#AppVersion} already installed -- silent: nothing changed, relaunching.');
    UpdWriteLastUpdate(ExistingInstallRoot, 'ABORTED', ExistingInstallVersion, '{#AppVersion}', 'same_version');
    UpdRelaunch(ExistingInstallRoot);
  end
  else
    MsgBox('{#AppName} version {#AppVersion} is already installed on this PC.' + #13#10 +
           'Nothing will be changed.', mbInformation, MB_OK);
end;

// PrepareToInstall body, after the app processes were stopped. Returns '' to continue, or
// the error text that aborts Setup (after the old app was restarted).
function UpdPrepareBackup(): string;
var
  RC: Integer;
begin
  Result := '';
  UpdInstallRoot := RemoveBackslashUnlessRoot(ExpandConstant('{app}'));
  UpdFromVersion := '';
  if not PathHasInstalledPayload(UpdInstallRoot) then
  begin
    Log('No installed payload in ' + UpdInstallRoot + '\current -- fresh install, no backup.');
    exit;
  end;
  TryReadInstalledVersion(UpdInstallRoot, UpdFromVersion);
  Log('Backing up ' + UpdInstallRoot + '\current (version ' + UpdFromVersion + ') to previous\');
  RC := UpdRunHelper('backup', UpdInstallRoot, '');
  if RC = 0 then
  begin
    UpdBackupDone := True;
    exit;
  end;
  // Backup failed. RC 2: current\ is as it was. RC 3 / -1: it could not be confirmed; the
  // journal (if any) makes the next start-up / watchdog restore it.
  UpdFinalized := True;
  if RC = 3 then
    UpdWriteLastUpdate(UpdInstallRoot, 'ABORTED', UpdFromVersion, '{#AppVersion}', 'restore_failed')
  else
    UpdWriteLastUpdate(UpdInstallRoot, 'ABORTED', UpdFromVersion, '{#AppVersion}', 'backup_failed');
  UpdRelaunch(UpdInstallRoot);
  UpdClearPauseSentinel(UpdInstallRoot);
  Result := '{#AppName} could not back up the installed version, so nothing was changed. ' +
            'See the setup log: ' + UpdSetupLogPath();
end;

// Rollback after the new files were copied: restore previous\, record, start the old app.
procedure UpdRollback(const Reason: string);
var
  RC: Integer;
begin
  Log('Rolling back to ' + UpdFromVersion + ' (' + Reason + ')');
  RC := UpdRunHelper('restore', UpdInstallRoot, '');
  if RC = 0 then
  begin
    UpdWriteLastUpdate(UpdInstallRoot, 'ROLLED_BACK', '{#AppVersion}', UpdFromVersion, Reason);
    UpdDeleteJournal(UpdInstallRoot);
    UpdRolledBackTo := UpdFromVersion;
  end
  else
    // The journal stays (phase restoring): the next start-up / watchdog retries the restore.
    UpdWriteLastUpdate(UpdInstallRoot, 'ROLLED_BACK', '{#AppVersion}', UpdFromVersion, 'restore_failed');
  UpdRelaunch(UpdInstallRoot);
  UpdClearPauseSentinel(UpdInstallRoot);
  UpdFinalized := True;
end;

// ssPostInstall body (after the host's own post-install work).
procedure UpdPostInstall();
var
  RC: Integer;
  Extra: string;
begin
  if UpdInstallRoot = '' then
    UpdInstallRoot := RemoveBackslashUnlessRoot(ExpandConstant('{app}'));

  if UpdTestFailIs('after_copy') then
  begin
    // TEST ONLY: behave as if Setup failed after the copy -- the success flag is never set,
    // so DeinitializeSetup runs the real restore path.
    Log('TEST (UPDATER_TEST_FAIL=after_copy): leaving ssPostInstall without finishing');
    exit;
  end;

  if not WizardSilent() then
  begin
    // Interactive install: the [Run] entry offers to start the app; no health wait.
    UpdWriteLastUpdate(UpdInstallRoot, 'INSTALLED', UpdFromVersion, '{#AppVersion}', 'interactive');
    UpdDeleteJournal(UpdInstallRoot);
    UpdClearPauseSentinel(UpdInstallRoot);
    UpdFinalized := True;
    exit;
  end;

  if not UpdBackupDone then
  begin
    // Silent fresh install: nothing to go back to; just start it.
    UpdWriteLastUpdate(UpdInstallRoot, 'INSTALLED', '', '{#AppVersion}', 'fresh_install');
    UpdRelaunch(UpdInstallRoot);
    UpdClearPauseSentinel(UpdInstallRoot);
    UpdFinalized := True;
    exit;
  end;

  Extra := ' -TimeoutSec 300';
  if UpdTestFailIs('health') then Extra := Extra + ' -TestFail health';
  if UpdTestFailIs('crash') then Extra := Extra + ' -TestFail crash';
  RC := UpdRunHelper('launch-wait', UpdInstallRoot, Extra);
  if RC = 0 then
  begin
    UpdWriteLastUpdate(UpdInstallRoot, 'INSTALLED', UpdFromVersion, '{#AppVersion}', '');
    UpdDeleteJournal(UpdInstallRoot);
    UpdClearPauseSentinel(UpdInstallRoot);
    UpdFinalized := True;
    Log('Update {#AppVersion} healthy; previous\ kept for a manual rollback.');
  end
  else if RC = 11 then
    UpdRollback('health_timeout')
  else
    // 10 = died before boot_ok; 12 / -1 = could not even be started: same verdict.
    UpdRollback('crash');
end;

// DeinitializeSetup body: any end of Setup that did not reach a terminal result.
procedure UpdDeinitialize();
var
  Root, Key: string;
begin
  if not UpdFinalized then
  begin
    if UpdBackupDone then
    begin
      Log('Setup ended after the backup without finishing (failed, cancelled or killed) -- restoring');
      UpdRollback('setup_failed');
    end
    else
    begin
      Root := UpdInstallRoot;
      if Root = '' then Root := ExistingInstallRoot;
      // Interactive Setup cancelled before PrepareToInstall never stopped the app: leave it.
      if (Root <> '') and PathHasInstalledPayload(Root) and (WizardSilent() or (UpdInstallRoot <> '')) then
      begin
        Log('Setup ended before changing anything -- making sure the installed app runs');
        if WizardSilent() then
          UpdWriteLastUpdate(Root, 'ABORTED', ExistingInstallVersion, '{#AppVersion}', 'setup_failed');
        UpdRelaunch(Root);
        UpdClearPauseSentinel(Root);
      end;
    end;
  end;

  if UpdRolledBackTo <> '' then
  begin
    // Inno recorded the new version in the uninstall entry; put the real one back.
    Key := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#UninstallKeyName}';
    if RegKeyExists(HKEY_CURRENT_USER, Key) then
    begin
      RegWriteStringValue(HKEY_CURRENT_USER, Key, 'DisplayVersion', UpdRolledBackTo);
      RegWriteStringValue(HKEY_CURRENT_USER, Key, 'DisplayName', '{#AppName} ' + UpdRolledBackTo);
      Log('Uninstall entry set back to ' + UpdRolledBackTo);
    end;
  end;
end;
