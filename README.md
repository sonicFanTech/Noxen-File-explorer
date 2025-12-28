# Noxen File Explorer

A tabbed, Windows-Explorer-inspired file manager built in **Python + PySide6** for **Windows 10/11**.

> This project was originally code-named **pyFiles**.

## Features

- **Tabbed browsing** (like Windows 11 Explorer) with auto-updating tab titles :contentReference[oaicite:5]{index=5}
- **“This PC”** start page showing connected drives, auto-refreshing as drives appear/disappear :contentReference[oaicite:6]{index=6}
- Drive **usage bars** (space used/free) similar to Windows Explorer :contentReference[oaicite:7]{index=7}
- Drive right-click menu (Open, Open in New Tab, **Eject** (where supported), Properties, etc.) :contentReference[oaicite:8]{index=8}
- File/folder context menu: Open, Open in New Tab, Rename, Delete (Recycle Bin on Windows), Copy/Cut/Paste, etc. :contentReference[oaicite:9]{index=9} :contentReference[oaicite:10]{index=10}
- **Drag & drop move/copy**
- **Preview + Details pane** (right side) :contentReference[oaicite:11]{index=11}
- **Quick Access pin/unpin** folders :contentReference[oaicite:12]{index=12} :contentReference[oaicite:13]{index=13}
- Built-in **ZIP browser** (double-click a `.zip` to view, then extract selected/all) :contentReference[oaicite:14]{index=14} :contentReference[oaicite:15]{index=15}
- File operations with a **progress dialog + cancel** for longer copy/move operations :contentReference[oaicite:16]{index=16}

## Requirements

- Windows 10 or Windows 11
- Python 3.x
- PySide6

Install dependency:

```bash
pip install pySide6

