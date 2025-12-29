# Noxen File Explorer

""NoxenFE.ico""

A tabbed, Windows‑Explorer‑style file manager built with **Python + PySide6** for **Windows 10/11**.

> This project was originally code‑named **Noxen File Explorer**.

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
