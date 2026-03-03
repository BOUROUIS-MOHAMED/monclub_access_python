from __future__ import annotations

import os
import zipfile
from pathlib import Path
from typing import List


PROJECT_ROOT_NAME = "monclub_access_wpf_skeleton"


FILES: List[str] = [
    # root
    "MonClubAccess.sln",
    ".gitignore",
    "README.md",
    "build_release.ps1",
    "build_installer.ps1",
    "verify_release.ps1",
    "publish_github_release.ps1",
    "theme_settings.json",
    "gym_access_secrets_cache.json",
    "totp_replay_state.json",

    # src/MonClubAccess.App
    "src/MonClubAccess.App/MonClubAccess.App.csproj",
    "src/MonClubAccess.App/App.xaml",
    "src/MonClubAccess.App/App.xaml.cs",
    "src/MonClubAccess.App/Program.cs",
    "src/MonClubAccess.App/appsettings.json",
    "src/MonClubAccess.App/appsettings.Development.json",

    # Assets (placeholders; you can replace later)
    "src/MonClubAccess.App/Assets/Icons/app.ico",
    "src/MonClubAccess.App/Assets/Icons/tray.ico",
    "src/MonClubAccess.App/Assets/Images/logo.png",
    "src/MonClubAccess.App/Assets/Images/empty_state.png",

    # Resources
    "src/MonClubAccess.App/Resources/Themes/Light.xaml",
    "src/MonClubAccess.App/Resources/Themes/Dark.xaml",
    "src/MonClubAccess.App/Resources/Themes/Clair.xaml",
    "src/MonClubAccess.App/Resources/Styles/Typography.xaml",
    "src/MonClubAccess.App/Resources/Styles/Buttons.xaml",
    "src/MonClubAccess.App/Resources/Styles/Inputs.xaml",
    "src/MonClubAccess.App/Resources/Styles/Cards.xaml",
    "src/MonClubAccess.App/Resources/Styles/Tables.xaml",
    "src/MonClubAccess.App/Resources/Styles/Dialogs.xaml",
    "src/MonClubAccess.App/Resources/Converters/BoolToVisibilityConverter.cs",
    "src/MonClubAccess.App/Resources/Converters/InverseBoolConverter.cs",
    "src/MonClubAccess.App/Resources/Converters/EnumToStringConverter.cs",

    # Shell + Tray
    "src/MonClubAccess.App/Shell/MainWindow.xaml",
    "src/MonClubAccess.App/Shell/MainWindow.xaml.cs",
    "src/MonClubAccess.App/Shell/Tray/TrayService.cs",
    "src/MonClubAccess.App/Shell/Tray/TrayMenu.xaml",

    # Views (Pages)
    "src/MonClubAccess.App/Views/Pages/LoginPage.xaml",
    "src/MonClubAccess.App/Views/Pages/ConfigurationPage.xaml",
    "src/MonClubAccess.App/Views/Pages/RestrictedPage.xaml",
    "src/MonClubAccess.App/Views/Pages/DevicePage.xaml",
    "src/MonClubAccess.App/Views/Pages/AgentRealtimePage.xaml",
    "src/MonClubAccess.App/Views/Pages/UsersPage.xaml",
    "src/MonClubAccess.App/Views/Pages/CardPage.xaml",
    "src/MonClubAccess.App/Views/Pages/DeviceInfoPage.xaml",
    "src/MonClubAccess.App/Views/Pages/LocalDbPage.xaml",
    "src/MonClubAccess.App/Views/Pages/LogsPage.xaml",

    # Views (Popups)
    "src/MonClubAccess.App/Views/Popups/EnrollFingerprintDialog.xaml",
    "src/MonClubAccess.App/Views/Popups/ConfirmDialog.xaml",
    "src/MonClubAccess.App/Views/Popups/ProgressDialog.xaml",
    "src/MonClubAccess.App/Views/Popups/ToastHost.xaml",

    # Controls
    "src/MonClubAccess.App/Controls/Cards/Card.xaml",
    "src/MonClubAccess.App/Controls/Cards/StatCard.xaml",
    "src/MonClubAccess.App/Controls/Cards/InfoBanner.xaml",
    "src/MonClubAccess.App/Controls/Tables/ModernDataGrid.xaml",
    "src/MonClubAccess.App/Controls/Tables/SearchableDataGrid.xaml",
    "src/MonClubAccess.App/Controls/Inputs/LabeledTextBox.xaml",
    "src/MonClubAccess.App/Controls/Inputs/LabeledComboBox.xaml",
    "src/MonClubAccess.App/Controls/Inputs/SearchBox.xaml",
    "src/MonClubAccess.App/Controls/Headers/PageHeader.xaml",
    "src/MonClubAccess.App/Controls/Headers/SectionHeader.xaml",
    "src/MonClubAccess.App/Controls/Status/StatusBar.xaml",
    "src/MonClubAccess.App/Controls/Status/LoadingIndicator.xaml",
    "src/MonClubAccess.App/Controls/Status/EmptyState.xaml",

    # ViewModels
    "src/MonClubAccess.App/ViewModels/Shell/MainWindowViewModel.cs",
    "src/MonClubAccess.App/ViewModels/Shell/NavigationViewModel.cs",
    "src/MonClubAccess.App/ViewModels/Pages/LoginViewModel.cs",
    "src/MonClubAccess.App/ViewModels/Pages/ConfigurationViewModel.cs",
    "src/MonClubAccess.App/ViewModels/Pages/RestrictedViewModel.cs",
    "src/MonClubAccess.App/ViewModels/Pages/DeviceViewModel.cs",
    "src/MonClubAccess.App/ViewModels/Pages/AgentRealtimeViewModel.cs",
    "src/MonClubAccess.App/ViewModels/Pages/UsersViewModel.cs",
    "src/MonClubAccess.App/ViewModels/Pages/CardViewModel.cs",
    "src/MonClubAccess.App/ViewModels/Pages/DeviceInfoViewModel.cs",
    "src/MonClubAccess.App/ViewModels/Pages/LocalDbViewModel.cs",
    "src/MonClubAccess.App/ViewModels/Pages/LogsViewModel.cs",

    # Composition (DI)
    "src/MonClubAccess.App/Composition/ServiceRegistration.cs",
    "src/MonClubAccess.App/Composition/AppBootstrapper.cs",

    # Native placeholder (no dll)
    "src/MonClubAccess.App/Native/x86/.keep",

    # Properties
    "src/MonClubAccess.App/Properties/AssemblyInfo.cs",
    "src/MonClubAccess.App/Properties/Settings.settings",

    # src/MonClubAccess.Core
    "src/MonClubAccess.Core/MonClubAccess.Core.csproj",
    "src/MonClubAccess.Core/Arch/PlatformSummary.cs",
    "src/MonClubAccess.Core/Arch/RequireX86Guard.cs",
    "src/MonClubAccess.Core/Config/AppConfig.cs",
    "src/MonClubAccess.Core/Config/ConfigStore.cs",
    "src/MonClubAccess.Core/Logging/Log.cs",
    "src/MonClubAccess.Core/Logging/FileLogger.cs",
    "src/MonClubAccess.Core/Security/SecureStore.cs",
    "src/MonClubAccess.Core/Security/TotpService.cs",
    "src/MonClubAccess.Core/Updates/UpdateManager.cs",
    "src/MonClubAccess.Core/Updates/UpdateModels.cs",
    "src/MonClubAccess.Core/Db/LocalDb.cs",
    "src/MonClubAccess.Core/Db/Repositories/SyncCacheRepository.cs",
    "src/MonClubAccess.Core/Db/Repositories/UsersRepository.cs",
    "src/MonClubAccess.Core/Db/Repositories/LogsRepository.cs",
    "src/MonClubAccess.Core/Db/Repositories/DeviceStateRepository.cs",
    "src/MonClubAccess.Core/Db/Models/SyncCacheEntry.cs",
    "src/MonClubAccess.Core/Db/Models/AgentRtlogState.cs",
    "src/MonClubAccess.Core/Db/Models/DeviceDoorPreset.cs",
    "src/MonClubAccess.Core/Db/Models/FingerprintTemplate.cs",
    "src/MonClubAccess.Core/Modes/AppMode.cs",
    "src/MonClubAccess.Core/Modes/ModeManager.cs",
    "src/MonClubAccess.Core/Engine/DeviceSyncEngine.cs",
    "src/MonClubAccess.Core/Engine/RealtimeAgentEngine.cs",
    "src/MonClubAccess.Core/Engine/WorkQueue.cs",
    "src/MonClubAccess.Core/Utils/Paths.cs",
    "src/MonClubAccess.Core/Utils/Json.cs",
    "src/MonClubAccess.Core/Utils/Net.cs",
    "src/MonClubAccess.Core/Utils/Time.cs",

    # src/MonClubAccess.Api
    "src/MonClubAccess.Api/MonClubAccess.Api.csproj",
    "src/MonClubAccess.Api/MonClub/MonClubApiClient.cs",
    "src/MonClubAccess.Api/MonClub/ApiEndpoints.cs",
    "src/MonClubAccess.Api/MonClub/Dtos/LoginResponse.cs",
    "src/MonClubAccess.Api/MonClub/Dtos/CredentialDto.cs",
    "src/MonClubAccess.Api/MonClub/Dtos/AccessUserDto.cs",
    "src/MonClubAccess.Api/MonClub/Dtos/RtLogDto.cs",
    "src/MonClubAccess.Api/LocalAccess/LocalAccessServer.cs",
    "src/MonClubAccess.Api/LocalAccess/Controllers/HealthController.cs",
    "src/MonClubAccess.Api/LocalAccess/Controllers/OpenDoorController.cs",
    "src/MonClubAccess.Api/LocalAccess/Controllers/ScanCardController.cs",
    "src/MonClubAccess.Api/LocalAccess/Controllers/SyncUsersController.cs",
    "src/MonClubAccess.Api/LocalAccess/Controllers/PushHistoryController.cs",
    "src/MonClubAccess.Api/Http/HttpClientFactory.cs",
    "src/MonClubAccess.Api/Http/AuthHandler.cs",

    # src/MonClubAccess.DeviceSdk
    "src/MonClubAccess.DeviceSdk/MonClubAccess.DeviceSdk.csproj",
    "src/MonClubAccess.DeviceSdk/PullSdk/PlcommproNative.cs",
    "src/MonClubAccess.DeviceSdk/PullSdk/PullSdkClient.cs",
    "src/MonClubAccess.DeviceSdk/PullSdk/PullSdkError.cs",
    "src/MonClubAccess.DeviceSdk/ZkFinger/ZkFpNative.cs",
    "src/MonClubAccess.DeviceSdk/ZkFinger/ZkFingerClient.cs",
    "src/MonClubAccess.DeviceSdk/ZkFinger/ZkFingerModels.cs",
    "src/MonClubAccess.DeviceSdk/Common/DeviceConnectionOptions.cs",
    "src/MonClubAccess.DeviceSdk/Common/DeviceModels.cs",
    "src/MonClubAccess.DeviceSdk/Common/DeviceExceptions.cs",

    # tests
    "src/MonClubAccess.Tests/MonClubAccess.Tests.csproj",
    "src/MonClubAccess.Tests/TotpServiceTests.cs",
    "src/MonClubAccess.Tests/UpdateManagerTests.cs",
    "src/MonClubAccess.Tests/PullSdkParsingTests.cs",

    # installer (no dlls; exe placeholder is empty)
    "installer/MonClubAccess.iss",
    "installer/updater/MonClubAccessUpdater.exe",
    "installer/assets/app.ico",
    "installer/assets/license.txt",

    # updater project kept as separate folder
    "updater/MonClubAccessUpdater.sln",
    "updater/MonClubAccessUpdater/MonClubAccessUpdater.csproj",
    "updater/MonClubAccessUpdater/Program.cs",
    "updater/MonClubAccessUpdater/UpdaterArgs.cs",
    "updater/MonClubAccessUpdater/ManifestModels.cs",
    "updater/MonClubAccessUpdater/HashUtil.cs",
    "updater/MonClubAccessUpdater/ZipUtil.cs",
    "updater/MonClubAccessUpdater/FileUtil.cs",
    "updater/MonClubAccessUpdater/SimpleLogger.cs",
    "updater/MonClubAccessUpdater/Properties/AssemblyInfo.cs",
]


def make_empty_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_bytes(b"")


def build_tree(out_dir: Path) -> Path:
    project_root = out_dir / PROJECT_ROOT_NAME
    if project_root.exists():
        # delete existing tree
        for p in sorted(project_root.rglob("*"), reverse=True):
            try:
                if p.is_file() or p.is_symlink():
                    p.unlink()
                else:
                    p.rmdir()
            except Exception:
                pass
        try:
            project_root.rmdir()
        except Exception:
            pass

    project_root.mkdir(parents=True, exist_ok=True)

    for rel in FILES:
        make_empty_file(project_root / rel)

    return project_root


def zip_tree(project_root: Path, zip_path: Path) -> None:
    if zip_path.exists():
        zip_path.unlink()

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in project_root.rglob("*"):
            if p.is_dir():
                continue
            arcname = p.relative_to(project_root.parent)  # include root folder
            z.write(p, arcname.as_posix())


def main() -> None:
    out_dir = Path.cwd()
    project_root = build_tree(out_dir)
    zip_path = out_dir / f"{PROJECT_ROOT_NAME}.zip"
    zip_tree(project_root, zip_path)

    print("✅ Generated skeleton folder:", project_root)
    print("✅ Generated zip:", zip_path)
    print("ℹ️ Note: all files are empty placeholders (no DLLs).")


if __name__ == "__main__":
    main()
