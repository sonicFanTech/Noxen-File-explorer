# Noxen File Explorer: Razer Native

<p align="center">
  <img width="160" height="160" alt="NoxenFE logo" src="docs/assets/nfe-logo.png">
</p>

<p align="center">
  <strong>A custom Windows file explorer rebuilt in native C++ / Qt.</strong><br>
  Tabs, This PC, Quick Access, preview/details, MTP support, archive tools, themes, updater packages, checksums, rollback folders, and a Win32 fallback repair mode.
</p>

<p align="center">
  <a href="https://github.com/sonicFanTech/Noxen-File-explorer/releases/tag/RN-R1.1"><img alt="Latest release" src="https://img.shields.io/badge/latest-v2.0.1%20R1.1-45b6ff?style=for-the-badge"></a>
  <img alt="Native line" src="https://img.shields.io/badge/line-Razer%20Native-65d8ff?style=for-the-badge">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%20x64-0078d7?style=for-the-badge">
  <img alt="Language" src="https://img.shields.io/badge/C%2B%2B-17-00599c?style=for-the-badge&logo=cplusplus">
  <img alt="Qt" src="https://img.shields.io/badge/Qt-6.10.2-41cd52?style=for-the-badge&logo=qt">
  <img alt="Updater" src="https://img.shields.io/badge/updater-SHA--256%20verified-222?style=for-the-badge">
</p>

<p align="center">
  <a href="https://github.com/sonicFanTech/Noxen-File-explorer/releases/tag/RN-R1.1">Latest Release</a>
  ·
  <a href="https://github.com/sonicFanTech/Noxen-File-explorer/releases">All Releases</a>
  ·
  <a href="https://sonicfantech.org/Site/DownloadNFE/">Download Center</a>
  ·
  <a href="#screenshots">Screenshots</a>
  ·
  <a href="#release-history">Release History</a>
</p>

---

## Screenshots

> Replace these slots with real screenshots after uploading images to the repo, GitHub attachments, or `docs/screenshots/`.

| Home / Quick Access | This PC |
|---|---|
| ![Home screenshot slot](docs/screenshots/home.png) | ![This PC screenshot slot](docs/screenshots/this-pc.png) |

| Folder View | Updater |
|---|---|
| ![Folder view screenshot slot](docs/screenshots/folder-view.png) | ![Updater screenshot slot](docs/screenshots/updater.png) |

| Settings / Updater Tab | Win32 Fallback Repair |
|---|---|
| ![Updater settings screenshot slot](docs/screenshots/settings-updater.png) | ![Win32 fallback screenshot slot](docs/screenshots/win32-fallback.png) |

---

## What is Noxen File Explorer?

**Noxen File Explorer** is a custom Windows file manager. The project started as a Python/PySide6 application and was later rebuilt as **Noxen File Explorer: Razer Native**, a native C++ / Qt version designed to be faster, cleaner, easier to package, and easier to extend.

The goal is not to perfectly clone every part of Windows Explorer. The goal is to make a custom file explorer with a strong desktop-app feel, custom workflow, tabbed browsing, modular feature DLLs, MTP tools, archive tools, and a controlled update system.

## Current Release

| Field | Value |
|---|---|
| Product line | Noxen File Explorer: Razer Native |
| Current version | **v2.0.1 R1.1** |
| GitHub release tag | [`RN-R1.1`](https://github.com/sonicFanTech/Noxen-File-explorer/releases/tag/RN-R1.1) |
| Recommended package | Normal folder build |
| Optional package | One-file wrapper build |
| Platform | Windows x64 |
| Framework | C++17 / Qt 6.10.2 / Win32 fallback updater |
| Website | https://sonicfantech.org/Site/DownloadNFE/ |

## Download

### Recommended: Normal Folder Build

Use the normal folder build for most cases. It keeps the app EXE, Qt runtime, FeatureDLLs, updater files, 7-Zip tools, themes, SaveData, and licenses as normal files/folders.

```txt
NoxenFE_RazerNative_v2_0_1_R1_1_NormalBuild.zip
```

### Optional: One-File Build

The one-file build is a wrapper around an extracted runtime. This is expected because Qt platform plugins, feature DLLs, updater files, helper EXEs, and 7-Zip files need to exist on disk at runtime.

```txt
NoxenFE_RazerNative_v2_0_1_R1_1_OneFileBuild.zip
```

When testing a fresh one-file build, clear the extracted runtime first:

```txt
%LOCALAPPDATA%\Noxen File Explorer\OneFileRuntime
```

## Key Features

### File Explorer Core

- Tabbed folder browsing
- This PC drive page
- Home / Quick Access page
- Sidebar navigation
- Address bar path entry
- Back / Forward / Up / Refresh
- Backspace-as-Up folder navigation
- View modes, including details/list/icon views
- Preview/details pane
- File/folder context menus
- Rename, delete, copy, paste, and file actions
- Settings saved under `resources/SaveData/`

### Native Razer Build

- Native C++ / Qt rebuild of the older Python version
- Windows x64 target
- Modular runtime layout
- Feature DLL architecture
- Bundled third-party tools where needed
- Normal folder build and one-file wrapper build

### MTP / Phone Support

NFE includes MTP support through modular helper DLLs:

```txt
Resources/FeatureDLLs/MTPsupport/NoxenMtpDeviceScan.dll
Resources/FeatureDLLs/MTPsupport/NoxenMtpFs.dll
Resources/FeatureDLLs/MTPsupport/NoxenMtpActions.dll
```

### Archive / ISO Support

NFE uses bundled 7-Zip files for archive tasks. Users do not need to install system 7-Zip for NFE archive operations.

Common actions include Open archive, Extract Here, Extract to folder, Test archive, Create ZIP / 7Z, Open in 7-Zip File Manager, and ISO mount/open/eject actions where supported.

### Themes

Built-in themes are stored here:

```txt
resources/Themes/built-in/
```

The custom theme folder is already reserved for later:

```txt
resources/Themes/custom/
```

### Updater System

v2.0.1 R1.1 adds the first updater-ready system:

```txt
resources/update/NFEUpdate.exe
resources/update/NFEUpdateQt.dll
```

Updater data folders:

```txt
resources/update/Logs/
resources/update/RoleBacks/
resources/update/cashes/
resources/update/Checksums/
resources/update/DownloadedUpdatePackage/
```

Update package verification uses server-side SHA-256 checksum files. The updater compares the downloaded package hash against the checksum file before installing.

Normal build update package layout:

```txt
update/
├─ latest.zip
├─ latest.7z
├─ latest.tar
├─ update.wim
└─ Checksums/
   ├─ latest.zip.sha256.txt
   ├─ latest.7z.sha256.txt
   ├─ latest.tar.sha256.txt
   └─ update.wim.sha256.txt
```

One-file build update package layout:

```txt
update/OF/
├─ update.zip
├─ update.7z
├─ update.tar
├─ update.wim
└─ Checksums/
   ├─ update.zip.sha256.txt
   ├─ update.7z.sha256.txt
   ├─ update.tar.sha256.txt
   └─ update.wim.sha256.txt
```

## Project Layout

```txt
NoxenFE_RazerNative/
├─ NoxenFE_RazerNative.exe
├─ Resources/
│  ├─ NoxenFE_RazerNative_App.exe
│  ├─ Qt/
│  ├─ FeatureDLLs/
│  ├─ Themes/
│  ├─ SaveData/
│  └─ update/
├─ dllsrc/
├─ update/
├─ tools/
└─ README.md
```

## Release History

| Release | Date | Era | Notes |
|---|---:|---|---|
| [`v2.0.1 R1.1`](https://github.com/sonicFanTech/Noxen-File-explorer/releases/tag/RN-R1.1) | 2026-06-27 | Razer Native C++ / Qt | Updater foundation, checksum validation, SaveData, themes, Backspace-as-Up, Win32 fallback repair. |
| [`v2.0 R1`](https://github.com/sonicFanTech/Noxen-File-explorer/releases/tag/RNR1) | 2026-06-23 | Razer Native C++ / Qt | Full native C++ rebuild of the original Python/PySide6 NFE line. |
| [`R3.1 / v1.4.1`](https://github.com/sonicFanTech/Noxen-File-explorer/releases/tag/R3.1) | 2026-01-07 | Original Python / PySide6 | Bug-fix and quality release with MTP companion workflow and stability fixes. |
| [`R3 / v1.4`](https://github.com/sonicFanTech/Noxen-File-explorer/releases/tag/R3) | 2025-12-31 | Original Python / PySide6 | Recent locations/files, context menu upgrades, copy/move progress UI, address bar commands. |
| [`R2`](https://github.com/sonicFanTech/Noxen-File-explorer/releases/tag/R2) | 2025-12-30 | Original Python / PySide6 | New submenu, archive actions, Notepad++, ISO actions, Delete/Shift+Delete behavior. |
| [`R1`](https://github.com/sonicFanTech/Noxen-File-explorer/releases/tag/R1) | 2025-12-28 | Original Python / PySide6 | First public Python/PySide6 release. |

## Known Notes

- The normal folder build is the safest package for most users.
- The one-file build extracts its runtime before launching.
- Normal updater mode skips `resources/Qt/`.
- Repair mode uses the Win32 fallback updater so Qt files can be repaired without Qt being loaded.
- NFE’s updater uses the bundled NFE 7-Zip files, not the system-installed 7-Zip context menu.
- Check updater logs under `resources/update/Logs/` when testing updates.

## Screenshot Checklist

Use these names if you want the README screenshot slots to work directly:

```txt
docs/screenshots/home.png
docs/screenshots/this-pc.png
docs/screenshots/folder-view.png
docs/screenshots/updater.png
docs/screenshots/settings-updater.png
docs/screenshots/win32-fallback.png
```
