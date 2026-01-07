# Noxen File Explorer

<img width="256" height="256" alt="NoxenFE" src="https://github.com/user-attachments/assets/8b355162-8358-40c2-a001-9a8c1eaf95d2" />

A tabbed, Windows‑Explorer‑style file manager built with **Python + PySide6** for **Windows 10/11**.

> This project was originally code‑named **pyFiles**.

## Features

- **Tabbed browsing** (auto‑updates tab titles to the current folder)
- **This PC** page with connected drives + space bars, auto‑updates on drive connect/disconnect
- Drive right‑click menu (Open, Open in New Tab, **Eject** where supported, Properties, etc.)
- File/folder context menu: Open, Rename, Delete (Recycle Bin), Copy/Cut/Paste, Open in Terminal Here, etc.
- Drag & drop move/copy
- **Info pane** (Preview + Details) on the right
- **Quick Access** pin/unpin (Favorites)
- **View modes** (Details/List + multiple icon sizes) and **Ctrl + Mouse Wheel** icon zoom
- **ZIP support**: browse a `.zip` like a folder + extract selected/all
- File operations with a **progress dialog + cancel**
- Optional: “default file manager / Win+E” workaround toggle (Settings → Advanced)

## Releases / Changelog

GitHub uses **R = Release** naming.

### R3 (v1.4) — “Big update”
**New / updated features**
- Updated file operations UI (Copy / Move / Delete) to show **more detailed progress** (more Explorer‑like) and support cancel.
- Drive handling improvements:
  - Better support for **ejecting removable drives** from the UI (where Windows allows).
- “This PC” drive context menu expanded / refined (Open, Open in new tab, Properties, etc.).

**Fixes**
- Multiple stability and UX improvements around file operations and drive refresh (connect/disconnect).

> Note: R3 is the base that later bug‑fix releases build on.

---

### R3.1 (v1.4.1) — Bug‑fix & quality update
This release is focused on fixes and reliability after the big R3 update.

**Fixes**
- **Copy / Paste / Cut / Paste** reliability fix:
  - Paste now correctly handles folder structures (including empty folders) and no longer “does nothing” after the progress‑UI update.
- **Disk Management** (drive context menu → “Open Disk Management”):
  - Now launches reliably (via MMC) instead of failing silently.
- **Ejected drive ghosting**:
  - Drives that were ejected and hidden no longer re‑appear unexpectedly while still plugged in.
- **Portable devices / phones**:
  - “Portable devices” list no longer incorrectly includes normal volumes/USB drives.
  - Phone/camera entries now open the **Noxen MTP Browser** companion app (true in‑app MTP browsing) instead of opening Explorer.
- **Startup performance / stability**:
  - Fixed a rapid, repeating background PowerShell/CMD spawn that caused lag/freezing/crashing.
  - Device scans are now cached/throttled to reduce CPU usage and UI hitching.
- Minor runtime fixes (startup crash + warnings):
  - Fixed missing helper method in the “This PC” view (`_drive_type_str`).
  - Fixed an escape‑sequence warning that could show up in logs.

**New**
- Companion‑app workflow for true MTP browsing:

<img width="256" height="256" alt="NFE_MTP-B_icon" src="https://github.com/user-attachments/assets/d0c79ef4-10b2-4207-9e1a-9e3e0b0d05c3" />

  - NoxenFE launches `NoxenMTPBrowser` when the user opens a detected phone/camera device.

## Download & Install

### Installer (recommended for most users)
1. Download the latest installer from **Releases**.
2. Run the installer and follow the prompts.

## IMPORTANT: program not working after install

Noxen File Explorer is designed to run as a non-admin program, However, the Run this program as Admin MUST be checked for the program to run, idk why, but, I'll fix it in an update

## Data / Settings location

Noxen stores user data in:

- `%APPDATA%\Noxen File Explorer\settings.json`
- `%APPDATA%\Noxen File Explorer\quick_access.json`
- (and any session/tab restore files you enabled)

## Run from source (dev)

```bash
pip install pySide6
python NoxenFileExplorer.py
```

## Build an EXE (optional)

```bash
pip install pyinstaller
pyinstaller --noconsole --onefile --name "Noxen File Explorer" NoxenFileExplorer.py
```

## Troubleshooting

### “Nothing happens” after install
- Verify the shortcut points to the correct EXE.
- Try running the EXE once directly from the install folder.
- Check Windows Defender / SmartScreen prompts.

### Win+E / default file manager toggle doesn’t apply
- The workaround sometimes needs an Explorer restart. Log out/in or restart Explorer.
- Windows updates may reset or break the workaround (it’s not an official Windows setting).
