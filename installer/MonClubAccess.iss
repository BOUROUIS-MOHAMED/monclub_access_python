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

#define AppVersion ReleaseId
#define AppPublisher "MonClub"
#define MainExe "MonClubAccess.exe"
#define UpdaterExe "MonClubAccessUpdater.exe"

; Branding assets (relative to this .iss file)
#define SetupIcon "assets\setup.ico"
#define WizardImage "assets\wizard.bmp"
#define WizardSmall "assets\wizard_small.bmp"

[Setup]
AppId={{9B77A9C2-2B97-4F62-A9E8-4B4C65F3A9B1}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}

; NEW: Installer EXE icon (MonClubAccessSetup-*.exe)
SetupIconFile={#SetupIcon}

; NEW: Installer wizard branding images
WizardImageFile={#WizardImage}
WizardSmallImageFile={#WizardSmall}

; IMPORTANT:
; Install per-user (no admin) so future auto-updates can write without UAC.
DefaultDirName={localappdata}\MonClubAccess
PrivilegesRequired=lowest

DisableProgramGroupPage=yes
OutputDir=..\release
OutputBaseFilename=MonClubAccessSetup-{#ReleaseId}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a &Desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

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
; We install the staged folder content under {app}\current\...
Source: "{#StageDir}\*"; DestDir: "{app}\current"; Flags: ignoreversion recursesubdirs createallsubdirs

; NEW: ship updater EXE into {app}\updater
; The .iss file lives inside installer\, so the correct relative path is:
; installer\updater\MonClubAccessUpdater.exe  => "updater\{#UpdaterExe}"
Source: "updater\{#UpdaterExe}"; DestDir: "{app}\updater"; Flags: ignoreversion

; OPTIONAL: ship branding assets into the installed folder (not required for installer UI)
; If you don't want these installed, remove this section.
; Source: "assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{userprograms}\MonClubAccess"; Filename: "{app}\current\{#MainExe}"
Name: "{userdesktop}\MonClubAccess"; Filename: "{app}\current\{#MainExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\current\{#MainExe}"; Description: "Launch MonClubAccess"; Flags: nowait postinstall skipifsilent
