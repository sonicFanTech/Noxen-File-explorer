import os
import sys
import json
import shutil
import subprocess
import hashlib
import zipfile
import mimetypes
import ctypes
import winreg
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import (
    Qt, QDir, QModelIndex, QSortFilterProxyModel, QUrl, QTimer, QSize, Signal, QFileInfo, QThread
)
from PySide6.QtGui import (
    QAction, QKeySequence, QIcon, QDesktopServices, QPixmap, QGuiApplication,
    QCursor
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QToolBar,
    QLineEdit, QSplitter, QTreeView, QHeaderView, QAbstractItemView,
    QFileSystemModel, QMenu, QMessageBox, QLabel, QTextEdit, QVBoxLayout,
    QStyle, QStatusBar, QCheckBox, QComboBox, QStackedWidget, QListView,
    QTreeWidget, QTreeWidgetItem, QListWidget, QListWidgetItem,
    QProgressBar, QHBoxLayout, QToolButton,
    QDialog, QFileIconProvider, QFormLayout, QDialogButtonBox, QSpinBox
)

THIS_PC_TOKEN = "::THISPC::"


# ----------------------------
# Config (Pinned / Quick Access)
# ----------------------------
def _config_dir() -> str:
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "Noxen File explorer")


def _pinned_json_path() -> str:
    return os.path.join(_config_dir(), "quick_access.json")


def load_pinned_paths() -> list[str]:
    try:
        p = _pinned_json_path()
        if not os.path.exists(p):
            return []
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        items = data.get("pinned", [])
        if not isinstance(items, list):
            return []
        out = []
        seen = set()
        for it in items:
            if isinstance(it, str) and it and it not in seen:
                out.append(it)
                seen.add(it)
        return out
    except Exception:
        return []


def save_pinned_paths(paths: list[str]) -> None:
    os.makedirs(_config_dir(), exist_ok=True)
    p = _pinned_json_path()
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"pinned": paths}, f, indent=2)




# ----------------------------
# Settings (persisted)
# ----------------------------
def _settings_json_path() -> str:
    return os.path.join(_config_dir(), "settings.json")


def load_settings() -> dict:
    defaults = {
        "preview_enabled": True,
        "show_hidden": False,
        "view_mode": "Details",          # Details / List / Small icons / Medium icons / Large icons / Extra large icons
        "icon_size": 48,                 # default icon size for icon-based views
        "restore_session": True,         # reopen tabs from last session
        "drive_poll_ms": 1500,           # drive connect/disconnect refresh
        "default_file_manager": False,   # registry workaround to replace File Explorer (Win+E)
    }
    out = dict(defaults)
    try:
        p = _settings_json_path()
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                out.update(data)
    except Exception:
        pass

    # sanitize
    allowed = {
        "Details", "List",
        "Small icons", "Medium icons", "Large icons", "Extra large icons",
    }
    if out.get("view_mode") not in allowed:
        out["view_mode"] = "Details"

    try:
        out["drive_poll_ms"] = int(out.get("drive_poll_ms", 1500))
    except Exception:
        out["drive_poll_ms"] = 1500
    out["drive_poll_ms"] = max(500, min(10000, out["drive_poll_ms"]))

    out["default_file_manager"] = bool(out.get("default_file_manager", False))

    try:
        out["icon_size"] = int(out.get("icon_size", 48))
    except Exception:
        out["icon_size"] = 48
    out["icon_size"] = max(16, min(256, out["icon_size"]))

    out["preview_enabled"] = bool(out.get("preview_enabled", True))
    out["show_hidden"] = bool(out.get("show_hidden", False))
    out["restore_session"] = bool(out.get("restore_session", True))
    return out


def save_settings(settings: dict) -> None:
    os.makedirs(_config_dir(), exist_ok=True)
    p = _settings_json_path()
    with open(p, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)


# ----------------------------
# Default file manager (registry workaround)
# ----------------------------
DEFAULT_MANAGER_VERB = "openinnoxen"
WIN_E_OVERRIDE_CLSID = "{52205fd8-5dfb-447d-801a-d0b52f2e83e1}"  # used by Files app workaround


def _self_launch_command(with_arg_placeholder: bool) -> str:
    """Returns the command string we write to the registry.

    - If frozen (compiled exe): "<exe>"
    - Else (python script): "<python>" "<script.py>"
    """
    if getattr(sys, "frozen", False):
        base = f'"{sys.executable}"'
    else:
        base = f'"{sys.executable}" "{Path(__file__).resolve()}"'
    if with_arg_placeholder:
        return base + ' "%1"'
    return base


def _reg_delete_tree(root, subkey: str) -> None:
    """Recursively delete a registry key tree. Ignores missing keys."""
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
            while True:
                try:
                    child = winreg.EnumKey(k, 0)
                except OSError:
                    break
                _reg_delete_tree(root, subkey + "\\" + child)
    except FileNotFoundError:
        return
    except OSError:
        # If we can't open it, try deleting anyway.
        pass

    try:
        winreg.DeleteKey(root, subkey)
    except FileNotFoundError:
        return
    except OSError:
        # Non-empty or in-use; best effort.
        return


def is_default_file_manager_enabled() -> bool:
    """Returns True if our registry workaround appears enabled for the current user."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\Directory\shell", 0, winreg.KEY_READ) as k:
            val, _ = winreg.QueryValueEx(k, "")
            return str(val).lower() == DEFAULT_MANAGER_VERB.lower()
    except FileNotFoundError:
        return False
    except OSError:
        return False


def set_default_file_manager_enabled(enabled: bool) -> None:
    """Enable/disable the 'default file manager' workaround (current user only)."""
    dir_shell = r"SOFTWARE\Classes\Directory\shell"
    verb_key = dir_shell + "\\" + DEFAULT_MANAGER_VERB
    cmd_key = verb_key + "\\command"

    clsid_base = r"SOFTWARE\Classes\CLSID\%s" % WIN_E_OVERRIDE_CLSID
    win_e_cmd = clsid_base + r"\shell\opennewwindow\command"

    if enabled:
        # Directory default verb
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, dir_shell) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, DEFAULT_MANAGER_VERB)

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, verb_key) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "Open in Noxen File Explorer")
            # Optional icon in context menus
            try:
                winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, sys.executable)
            except OSError:
                pass

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, cmd_key) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, _self_launch_command(with_arg_placeholder=True))

        # Win + E override
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, win_e_cmd) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, _self_launch_command(with_arg_placeholder=False))
            # Required by the known workaround: empty DelegateExecute value
            winreg.SetValueEx(k, "DelegateExecute", 0, winreg.REG_SZ, "")

    else:
        # Revert Directory default verb
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, dir_shell, 0, winreg.KEY_SET_VALUE) as k:
                try:
                    winreg.DeleteValue(k, "")
                except FileNotFoundError:
                    pass
        except FileNotFoundError:
            pass

        _reg_delete_tree(winreg.HKEY_CURRENT_USER, verb_key)
        _reg_delete_tree(winreg.HKEY_CURRENT_USER, clsid_base)


def restart_windows_explorer() -> None:
    """Restart explorer.exe (best effort)."""
    try:
        subprocess.run(["taskkill", "/f", "/im", "explorer.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass
    try:
        subprocess.Popen(["explorer.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


# ----------------------------
# Windows drive info + recycle bin + shell properties
# ----------------------------
@dataclass
class DriveInfo:
    root: str          # e.g. "C:\"
    label: str         # e.g. "Windows"
    fs: str            # e.g. "NTFS"
    drive_type: int    # GetDriveTypeW
    total: int
    free: int

    @property
    def used(self) -> int:
        return max(0, self.total - self.free)

    @property
    def used_pct(self) -> int:
        if self.total <= 0:
            return 0
        return int((self.used / self.total) * 100)

    @property
    def name(self) -> str:
        # Explorer-ish display name
        root_disp = self.root.rstrip("\\")
        if self.label:
            return f"{self.label} ({root_disp})"
        return f"{root_disp}"



# ----------------------------
# Session (open tabs restore)
# ----------------------------
def _session_json_path() -> str:
    return os.path.join(_config_dir(), "session.json")


def load_session() -> dict:
    # {"tabs":[{"path": str, "pinned": bool}], "current_index": int}
    try:
        p = _session_json_path()
        if not os.path.exists(p):
            return {}
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except Exception:
        return {}


def save_session(data: dict) -> None:
    try:
        os.makedirs(_config_dir(), exist_ok=True)
        with open(_session_json_path(), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def _get_volume_info(root: str) -> tuple[str, str]:
    # (label, filesystem)
    volume_name = ctypes.create_unicode_buffer(261)
    fs_name = ctypes.create_unicode_buffer(261)
    serial = wintypes.DWORD()
    max_comp_len = wintypes.DWORD()
    fs_flags = wintypes.DWORD()

    ok = ctypes.windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(root),
        volume_name, 261,
        ctypes.byref(serial),
        ctypes.byref(max_comp_len),
        ctypes.byref(fs_flags),
        fs_name, 261
    )
    if not ok:
        return ("", "")
    return (volume_name.value, fs_name.value)


def _get_disk_free(root: str) -> tuple[int, int]:
    # (free, total)
    free_bytes = ctypes.c_ulonglong()
    total_bytes = ctypes.c_ulonglong()
    total_free = ctypes.c_ulonglong()
    ok = ctypes.windll.kernel32.GetDiskFreeSpaceExW(
        ctypes.c_wchar_p(root),
        ctypes.byref(free_bytes),
        ctypes.byref(total_bytes),
        ctypes.byref(total_free)
    )
    if not ok:
        return (0, 0)
    return (int(free_bytes.value), int(total_bytes.value))


def list_drives_windows() -> list[DriveInfo]:
    drives = []
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if not (mask & (1 << i)):
            continue
        letter = chr(ord('A') + i)
        root = f"{letter}:\\"
        dtype = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
        # Skip unknown/no-root
        if dtype == 0:  # DRIVE_UNKNOWN
            continue
        label, fs = _get_volume_info(root)
        free, total = _get_disk_free(root)
        drives.append(DriveInfo(root=root, label=label, fs=fs, drive_type=dtype, total=total, free=free))
    # Sort: fixed first, then removable, then others; then letter
    def key(d: DriveInfo):
        # DRIVE_FIXED=3, DRIVE_REMOVABLE=2, DRIVE_CDROM=5, DRIVE_REMOTE=4
        priority = {3: 0, 2: 1, 5: 2, 4: 3}.get(d.drive_type, 9)
        return (priority, d.root)
    drives.sort(key=key)
    return drives


def _windows_send_to_recycle_bin(paths):
    FO_DELETE = 0x0003
    FOF_ALLOWUNDO = 0x0040
    FOF_NOCONFIRMATION = 0x0010
    FOF_SILENT = 0x0004
    FOF_NOERRORUI = 0x0400

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("wFunc", wintypes.UINT),
            ("pFrom", wintypes.LPCWSTR),
            ("pTo", wintypes.LPCWSTR),
            ("fFlags", ctypes.c_uint16),
            ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", wintypes.LPVOID),
            ("lpszProgressTitle", wintypes.LPCWSTR),
        ]

    shell32 = ctypes.windll.shell32
    pfrom = "\0".join(str(Path(p)) for p in paths) + "\0\0"
    op = SHFILEOPSTRUCTW()
    op.hwnd = None
    op.wFunc = FO_DELETE
    op.pFrom = pfrom
    op.pTo = None
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
    op.fAnyOperationsAborted = False
    op.hNameMappings = None
    op.lpszProgressTitle = None

    res = shell32.SHFileOperationW(ctypes.byref(op))
    return res == 0 and not op.fAnyOperationsAborted


def open_shell_properties(path: str) -> bool:
    """Open the real Windows Properties dialog (Explorer-style)."""
    if not sys.platform.startswith("win"):
        return False
    try:
        SEE_MASK_INVOKEIDLIST = 0x0000000C
        SW_SHOW = 5

        class SHELLEXECUTEINFOW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("fMask", wintypes.ULONG),
                ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR),
                ("lpFile", wintypes.LPCWSTR),
                ("lpParameters", wintypes.LPCWSTR),
                ("lpDirectory", wintypes.LPCWSTR),
                ("nShow", ctypes.c_int),
                ("hInstApp", wintypes.HINSTANCE),
                ("lpIDList", wintypes.LPVOID),
                ("lpClass", wintypes.LPCWSTR),
                ("hkeyClass", wintypes.HKEY),
                ("dwHotKey", wintypes.DWORD),
                ("hIcon", wintypes.HANDLE),
                ("hProcess", wintypes.HANDLE),
            ]

        sei = SHELLEXECUTEINFOW()
        sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
        sei.fMask = SEE_MASK_INVOKEIDLIST
        sei.hwnd = None
        sei.lpVerb = "properties"
        sei.lpFile = os.path.abspath(path)
        sei.lpParameters = None
        sei.lpDirectory = None
        sei.nShow = SW_SHOW
        ok = ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei))
        return bool(ok)
    except Exception:
        return False




def can_eject_drive(root: str) -> bool:
    """Best-effort: allow eject for removable + optical drives, but never for the system drive."""
    if not sys.platform.startswith("win"):
        return False
    if not root or len(root) < 2:
        return False
    letter = root[0].upper()
    sys_drive = (os.environ.get("SystemDrive") or "C:").replace("\\", "").upper()
    if f"{letter}:" == sys_drive:
        return False
    try:
        dtype = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
        return dtype in (2, 5)  # DRIVE_REMOVABLE, DRIVE_CDROM
    except Exception:
        return False


def eject_drive_windows(root: str) -> bool:
    """Attempt to eject a drive using Explorer verbs (works for many removable/optical drives)."""
    if not can_eject_drive(root):
        return False
    letter = root[0].upper()
    try:
        # Use Shell.Application COM to invoke the Explorer 'Eject' verb
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            f"$d=(New-Object -ComObject Shell.Application).NameSpace(17).ParseName('{letter}:');"
            "if($d){$d.InvokeVerb('Eject')}"
        ]
        p = subprocess.run(cmd, capture_output=True, text=True)
        return p.returncode == 0
    except Exception:
        return False

# ----------------------------
# Helpers
# ----------------------------
def view_mode_to_icon_size(mode: str, default_size: int = 48) -> tuple[str, int]:
    """Return (kind, icon_size) where kind is 'details' / 'list' / 'icons'."""
    mode = (mode or "Details").strip()
    if mode == "Details":
        return ("details", default_size)
    if mode == "List":
        return ("list", 24)
    sizes = {
        "Small icons": 32,
        "Medium icons": 48,
        "Large icons": 72,
        "Extra large icons": 96,
    }
    return ("icons", int(sizes.get(mode, default_size)))



def human_size(num_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    n = float(num_bytes)
    for u in units:
        if n < 1024.0 or u == units[-1]:
            return f"{n:.1f} {u}" if u != "B" else f"{int(n)} {u}"
        n /= 1024.0
    return f"{num_bytes} B"


def safe_read_text(path: str, max_chars: int = 200_000) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read(max_chars)
    except Exception:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read(max_chars)
        except Exception:
            return ""


def try_ffprobe_duration(path: str) -> str | None:
    try:
        out = subprocess.check_output(
            ["ffprobe", "-v", "error", "-show_entries", "format=duration",
             "-of", "default=noprint_wrappers=1:nokey=1", path],
            stderr=subprocess.STDOUT,
            text=True
        ).strip()
        if not out:
            return None
        secs = float(out)
        h = int(secs // 3600)
        m = int((secs % 3600) // 60)
        s = int(secs % 60)
        if h > 0:
            return f"{h:02d}:{m:02d}:{s:02d}"
        return f"{m:02d}:{s:02d}"
    except Exception:
        return None


def is_image_file(path: str) -> bool:
    ext = Path(path).suffix.lower()
    return ext in {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif", ".tiff"}


def is_text_file(path: str) -> bool:
    ext = Path(path).suffix.lower()
    return ext in {".txt", ".log", ".md", ".json", ".ini", ".cfg", ".xml", ".yaml", ".yml",
                   ".py", ".bat", ".cmd", ".ps1", ".ahk"}


def is_media_file(path: str) -> bool:
    ext = Path(path).suffix.lower()
    return ext in {
        ".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a",
        ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".mpeg", ".mpg"
    }


def basename_for_tab(path: str) -> str:
    if path == THIS_PC_TOKEN:
        return "This PC"
    p = Path(path)
    name = p.name
    if name:
        return name
    return str(p)


def open_in_terminal(path: str):
    path = os.path.abspath(path)
    if os.path.isfile(path):
        path = os.path.dirname(path)

    # Prefer Windows Terminal if available
    try:
        subprocess.Popen(["wt.exe", "-d", path], cwd=path)
        return
    except Exception:
        pass

    # Fallback to PowerShell
    try:
        subprocess.Popen(["powershell.exe", "-NoExit", "-Command", f"cd '{path}'"], cwd=path)
        return
    except Exception:
        pass

    # Fallback to CMD
    subprocess.Popen(["cmd.exe", "/K", "cd", "/d", path], cwd=path)


def compute_sha256(path: str, max_bytes: int = 64 * 1024 * 1024) -> str | None:
    # Safety: don’t hash gigantic files by default to avoid freezing.
    try:
        size = os.path.getsize(path)
        if size > max_bytes:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


# ----------------------------
# Breadcrumb address bar (Explorer-ish)
# ----------------------------
class BreadcrumbBar(QWidget):
    pathEntered = Signal(str)   # user typed a path / token
    pathSelected = Signal(str)  # user clicked a crumb

    def __init__(self):
        super().__init__()
        self._current = ""

        self.stack = QStackedWidget()

        # Crumbs view
        self.crumb_host = QWidget()
        self.crumb_layout = QHBoxLayout(self.crumb_host)
        self.crumb_layout.setContentsMargins(6, 2, 6, 2)
        self.crumb_layout.setSpacing(4)
        self.crumb_layout.addStretch(1)

        # Editor view
        self.editor = QLineEdit()
        self.editor.setPlaceholderText("Type a path, or 'This PC'")
        self.editor.returnPressed.connect(self._on_return)
        self.editor.editingFinished.connect(self._on_edit_done)

        self.stack.addWidget(self.crumb_host)  # 0
        self.stack.addWidget(self.editor)      # 1

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.stack)

        self.stack.setCurrentIndex(0)

        # Slight Explorer-like feel
        self.setStyleSheet(
            "BreadcrumbBar { border: 1px solid rgba(255,255,255,0.15); border-radius: 6px; }"
            "QToolButton { padding: 2px 6px; border-radius: 4px; }"
            "QToolButton:hover { background: rgba(255,255,255,0.08); }"
        )

    def set_path(self, token_or_path: str):
        self._current = token_or_path
        self.editor.setText("This PC" if token_or_path == THIS_PC_TOKEN else str(token_or_path))
        self._rebuild_crumbs()

    def activate_edit(self):
        self.stack.setCurrentIndex(1)
        self.editor.setFocus(Qt.ShortcutFocusReason)
        self.editor.selectAll()

    def _on_return(self):
        text = self.editor.text().strip()
        if text:
            self.pathEntered.emit(text)

    def _on_edit_done(self):
        # Go back to crumbs once editing finishes (even if empty)
        self.stack.setCurrentIndex(0)

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.activate_edit()
            event.accept()
            return
        super().mouseDoubleClickEvent(event)

    def _clear_layout(self, layout: QHBoxLayout):
        while layout.count():
            item = layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def _rebuild_crumbs(self):
        self._clear_layout(self.crumb_layout)

        def add_sep():
            sep = QLabel(">")
            sep.setStyleSheet("color: rgba(255,255,255,0.45); padding: 0 2px;")
            self.crumb_layout.addWidget(sep)

        def add_btn(text: str, target: str):
            b = QToolButton()
            b.setText(text)
            b.setCursor(Qt.PointingHandCursor)
            b.setAutoRaise(True)
            b.clicked.connect(lambda: self.pathSelected.emit(target))
            self.crumb_layout.addWidget(b)

        tok = self._current
        if tok == THIS_PC_TOKEN or str(tok).strip().lower() in {"this pc", "thispc"}:
            add_btn("This PC", THIS_PC_TOKEN)
            self.crumb_layout.addStretch(1)
            return

        path = os.path.abspath(str(tok))
        parts = Path(path).parts
        if not parts:
            add_btn(path, path)
            self.crumb_layout.addStretch(1)
            return

        # Windows: parts[0] is like "C:\"
        cum = parts[0]
        root_text = cum.rstrip("\\")
        add_btn(root_text, cum)

        for part in parts[1:]:
            add_sep()
            cum = os.path.join(cum, part)
            add_btn(part, cum)

        self.crumb_layout.addStretch(1)


# ----------------------------
# Proxy model for search filtering
# ----------------------------
class NameFilterProxy(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._needle = ""

    def set_filter_text(self, text: str):
        self._needle = (text or "").strip().lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        if not self._needle:
            return True
        idx = self.sourceModel().index(source_row, 0, source_parent)
        name = self.sourceModel().fileName(idx).lower()
        return self._needle in name


# ----------------------------
# Draggable views (Details + List/Icon)
# ----------------------------
class DropCapableTree(QTreeView):
    def __init__(self, tab_ref, parent=None):
        super().__init__(parent)
        self._tab = tab_ref
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.EditKeyPressed | QAbstractItemView.SelectedClicked)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setDefaultDropAction(Qt.MoveAction)
        self.setDragDropMode(QAbstractItemView.DragDrop)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        super().dragMoveEvent(event)

    def dropEvent(self, event):
        if not event.mimeData().hasUrls():
            super().dropEvent(event)
            return
        dest_folder = self._tab.current_path_real()
        idx = self.indexAt(event.position().toPoint())
        if idx.isValid():
            src_index = self._tab.map_to_source(idx)
            path = self._tab.fs_model.filePath(src_index)
            if os.path.isdir(path):
                dest_folder = path

        urls = event.mimeData().urls()
        src_paths = [u.toLocalFile() for u in urls if u.isLocalFile()]
        if not src_paths or not os.path.isdir(dest_folder):
            event.ignore()
            return

        is_copy = bool(event.keyboardModifiers() & Qt.ControlModifier)
        try:
            self._tab.copy_or_move_into(dest_folder, src_paths, move=not is_copy)
            event.acceptProposedAction()
        except Exception as e:
            QMessageBox.warning(self, "Drag/Drop failed", str(e))
            event.ignore()


class DropCapableList(QListView):
    def __init__(self, tab_ref, parent=None):
        super().__init__(parent)
        self._tab = tab_ref
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.EditKeyPressed | QAbstractItemView.SelectedClicked)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setDefaultDropAction(Qt.MoveAction)
        self.setDragDropMode(QAbstractItemView.DragDrop)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        super().dragMoveEvent(event)

    def dropEvent(self, event):
        if not event.mimeData().hasUrls():
            super().dropEvent(event)
            return
        dest_folder = self._tab.current_path_real()
        idx = self.indexAt(event.position().toPoint())
        if idx.isValid():
            src_index = self._tab.map_to_source(idx)
            path = self._tab.fs_model.filePath(src_index)
            if os.path.isdir(path):
                dest_folder = path

        urls = event.mimeData().urls()
        src_paths = [u.toLocalFile() for u in urls if u.isLocalFile()]
        if not src_paths or not os.path.isdir(dest_folder):
            event.ignore()
            return

        is_copy = bool(event.keyboardModifiers() & Qt.ControlModifier)
        try:
            self._tab.copy_or_move_into(dest_folder, src_paths, move=not is_copy)
            event.acceptProposedAction()
        except Exception as e:
            QMessageBox.warning(self, "Drag/Drop failed", str(e))
            event.ignore()


# ----------------------------
# Right side: Preview + Details panes
# ----------------------------
    def wheelEvent(self, event):
        # Ctrl + mouse wheel: zoom icons (Explorer-like)
        try:
            if event.modifiers() & Qt.ControlModifier:
                delta = event.angleDelta().y()
                if delta:
                    step = 8 if abs(delta) < 120 else 16
                    if delta > 0:
                        self._tab.adjust_icon_size(step)
                    else:
                        self._tab.adjust_icon_size(-step)
                    event.accept()
                    return
        except Exception:
            pass
        super().wheelEvent(event)


class PreviewPane(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        self.title = QLabel("Preview")
        self.title.setStyleSheet("font-weight: 600; font-size: 14px;")
        layout.addWidget(self.title)

        self.image = QLabel()
        self.image.setAlignment(Qt.AlignCenter)
        self.image.setMinimumHeight(180)
        self.image.setWordWrap(True)
        layout.addWidget(self.image, 1)

        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.text.setPlaceholderText("Select a file to preview.")
        layout.addWidget(self.text, 2)

        self.info = QLabel()
        self.info.setWordWrap(True)
        layout.addWidget(self.info)

        self.set_empty()

    def set_empty(self):
        self.title.setText("Preview")
        self.image.setText("No selection")
        self.image.setPixmap(QPixmap())
        self.text.setPlainText("")
        self.info.setText("")

    def show_single(self, path: str, icon: QIcon | None = None):
        p = Path(path)
        self.title.setText(p.name or str(p))

        try:
            st = p.stat()
            modified = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            size = human_size(st.st_size) if p.is_file() else ""
        except Exception:
            modified = "Unknown"
            size = ""

        if p.is_dir():
            self.image.setPixmap(QPixmap())
            self.image.setText("Folder")
            self.text.setPlainText("")
            self.info.setText(f"Type: Folder\nModified: {modified}\nPath: {p}")
            return

        if is_image_file(str(p)):
            pm = QPixmap(str(p))
            if not pm.isNull():
                scaled = pm.scaled(520, 320, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self.image.setPixmap(scaled)
                self.image.setText("")
                dims = f"{pm.width()} x {pm.height()}"
            else:
                self.image.setPixmap(QPixmap())
                self.image.setText("Image preview not available.")
                dims = ""
            self.text.setPlainText("")
            self.info.setText(f"Type: Image\nSize: {size}\nDimensions: {dims}\nModified: {modified}\nPath: {p}")
            return

        if is_text_file(str(p)):
            content = safe_read_text(str(p), max_chars=150_000)
            self.image.setPixmap(QPixmap())
            self.image.setText("")
            self.text.setPlainText(content if content else "(Could not read text preview.)")
            self.info.setText(f"Type: Text\nSize: {size}\nModified: {modified}\nPath: {p}")
            return

        if is_media_file(str(p)):
            dur = try_ffprobe_duration(str(p))
            self.image.setPixmap(QPixmap())
            self.image.setText("Media file")
            self.text.setPlainText("")
            extra = f"\nDuration: {dur}" if dur else ""
            self.info.setText(f"Type: Media\nSize: {size}\nModified: {modified}{extra}\nPath: {p}")
            return

        self.image.setPixmap(QPixmap())
        self.image.setText("No preview")
        self.text.setPlainText("")
        self.info.setText(f"Type: File\nSize: {size}\nModified: {modified}\nPath: {p}")

    def show_multi_summary(self, paths: list[str]):
        files = 0
        folders = 0
        total_size = 0
        for p in paths:
            try:
                if os.path.isdir(p):
                    folders += 1
                else:
                    files += 1
                    total_size += os.path.getsize(p)
            except Exception:
                pass

        self.title.setText("Selection")
        self.image.setPixmap(QPixmap())
        self.image.setText("")
        self.text.setPlainText("")
        self.info.setText(
            f"Selected: {len(paths)} item(s)\n"
            f"Folders: {folders}\n"
            f"Files: {files}\n"
            f"Total file size: {human_size(total_size)}"
        )


class DetailsPane(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        self.title = QLabel("Details")
        self.title.setStyleSheet("font-weight: 600; font-size: 14px;")
        layout.addWidget(self.title)

        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.text.setPlaceholderText("Select an item to view details.")
        layout.addWidget(self.text, 1)

        self.set_empty()

    def set_empty(self):
        self.title.setText("Details")
        self.text.setPlainText("")

    def show_multi_summary(self, paths: list[str]):
        files = 0
        folders = 0
        total_size = 0
        for p in paths:
            try:
                if os.path.isdir(p):
                    folders += 1
                else:
                    files += 1
                    total_size += os.path.getsize(p)
            except Exception:
                pass
        self.title.setText("Details (Selection)")
        self.text.setPlainText(
            f"Selected: {len(paths)} item(s)\n"
            f"Folders: {folders}\n"
            f"Files: {files}\n"
            f"Total file size (files only): {human_size(total_size)}\n"
        )

    def show_single(self, path: str):
        p = Path(path)
        kind = "Folder" if p.is_dir() else "File"
        mime, _ = mimetypes.guess_type(str(p))
        mime = mime or ""

        try:
            st = p.stat()
            created = datetime.fromtimestamp(st.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
            modified = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            size = human_size(st.st_size) if p.is_file() else ""
        except Exception:
            created = modified = "Unknown"
            size = ""

        extra = ""
        if p.is_file() and is_media_file(str(p)):
            dur = try_ffprobe_duration(str(p))
            if dur:
                extra += f"Duration: {dur}\n"
        if p.is_file() and is_image_file(str(p)):
            pm = QPixmap(str(p))
            if not pm.isNull():
                extra += f"Dimensions: {pm.width()} x {pm.height()}\n"

        sha = ""
        if p.is_file():
            h = compute_sha256(str(p), max_bytes=64 * 1024 * 1024)
            if h is None:
                sha = "SHA-256: (skipped — file too large)\n"
            else:
                sha = f"SHA-256: {h}\n"

        self.title.setText(f"Details — {p.name or str(p)}")
        self.text.setPlainText(
            f"Name: {p.name}\n"
            f"Type: {kind}\n"
            f"Size: {size}\n"
            f"MIME: {mime}\n"
            f"Created: {created}\n"
            f"Modified: {modified}\n"
            f"{extra}"
            f"{sha}"
            f"Path: {p}\n"
        )


# ----------------------------
# This PC widget (drives + bars + view modes)
# ----------------------------
class ThisPCWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack)

        # Tiles view (Icons/List-like)
        self.tiles = QListWidget()
        self.tiles.setViewMode(QListView.IconMode)
        self.tiles.setResizeMode(QListView.Adjust)
        self.tiles.setMovement(QListView.Static)
        self.tiles.setIconSize(QSize(48, 48))
        self.tiles.setSpacing(10)
        self.tiles.setUniformItemSizes(False)
        self.tiles.installEventFilter(self)

        # Details view (table-like)
        self.table = QTreeWidget()
        self.table.setColumnCount(4)
        self.table.setHeaderLabels(["Name", "Type", "Free", "Used"])
        self.table.header().setSectionResizeMode(0, QHeaderView.Stretch)
        for c in (1, 2, 3):
            self.table.header().setSectionResizeMode(c, QHeaderView.ResizeToContents)

        self.stack.addWidget(self.tiles)  # 0
        self.stack.addWidget(self.table)  # 1

        self._drive_items = {}  # root -> (tile_item, tile_widget, table_item)

        self.tiles.itemDoubleClicked.connect(self._on_tile_double)
        self.table.itemDoubleClicked.connect(self._on_table_double)
        # Context menu for drives
        self.tiles.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tiles.customContextMenuRequested.connect(self._on_context_menu_tiles)
        self.table.customContextMenuRequested.connect(self._on_context_menu_table)

        self._icon_provider = QFileIconProvider()

    def eventFilter(self, obj, event):
        try:
            if obj is self.tiles and event.type() == event.Type.Wheel:
                if event.modifiers() & Qt.ControlModifier:
                    delta = event.angleDelta().y()
                    if delta:
                        step = 8 if abs(delta) < 120 else 16
                        cur = int(getattr(self, "_icon_size", 48))
                        cur = cur + step if delta > 0 else cur - step
                        self._icon_size = max(16, min(256, cur))
                        self.tiles.setIconSize(QSize(self._icon_size, self._icon_size))
                        return True
        except Exception:
            pass
        return super().eventFilter(obj, event)


    def set_view_mode(self, mode: str):
        if mode == "Details":
            self.stack.setCurrentIndex(1)
            return

        self.stack.setCurrentIndex(0)

        kind, icon = view_mode_to_icon_size(mode, getattr(self, "_icon_size", 48))
        if kind == "list":
            self.tiles.setViewMode(QListView.ListMode)
        else:
            self.tiles.setViewMode(QListView.IconMode)
        self.tiles.setIconSize(QSize(icon, icon))

    def set_icon_size(self, size: int):
        try:
            self._icon_size = max(16, min(256, int(size)))
        except Exception:
            self._icon_size = 48
        if self.stack.currentIndex() == 0:
            self.tiles.setIconSize(QSize(self._icon_size, self._icon_size))


    def update_drives(self, drives: list[DriveInfo]):
        existing = set(self._drive_items.keys())
        incoming = set(d.root for d in drives)

        # Remove disconnected drives
        for root in sorted(existing - incoming):
            tile_item, tile_widget, table_item = self._drive_items.pop(root)
            row = self.tiles.row(tile_item)
            self.tiles.takeItem(row)
            idx = self.table.indexOfTopLevelItem(table_item)
            if idx >= 0:
                self.table.takeTopLevelItem(idx)

        # Add/update drives
        for d in drives:
            if d.root not in self._drive_items:
                # Tile item + custom widget
                item = QListWidgetItem()
                try:
                    item.setIcon(self._icon_provider.icon(QFileInfo(d.root)))
                except Exception:
                    pass
                item.setData(Qt.UserRole, d.root)
                item.setSizeHint(QSize(220, 90))
                self.tiles.addItem(item)

                widget = QWidget()
                wlay = QVBoxLayout(widget)
                wlay.setContentsMargins(8, 8, 8, 8)
                title = QLabel(d.name)
                title.setStyleSheet("font-weight: 600;")
                bar = QProgressBar()
                bar.setRange(0, 100)
                bar.setTextVisible(True)
                info = QLabel("")
                info.setWordWrap(True)
                wlay.addWidget(title)
                wlay.addWidget(bar)
                wlay.addWidget(info)

                self.tiles.setItemWidget(item, widget)

                # Table item
                titem = QTreeWidgetItem([d.name, self._drive_type_str(d), "", ""])
                try:
                    titem.setIcon(0, self._icon_provider.icon(QFileInfo(d.root)))
                except Exception:
                    pass
                self.table.addTopLevelItem(titem)
                pbar = QProgressBar()
                pbar.setRange(0, 100)
                self.table.setItemWidget(titem, 3, pbar)

                self._drive_items[d.root] = (item, widget, titem)

            # Update values
            tile_item, tile_widget, table_item = self._drive_items[d.root]
            title = tile_widget.layout().itemAt(0).widget()
            bar = tile_widget.layout().itemAt(1).widget()
            info = tile_widget.layout().itemAt(2).widget()

            title.setText(d.name)
            used_pct = d.used_pct
            bar.setValue(used_pct)
            bar.setFormat(f"{used_pct}% used")

            # Colored bar (green/yellow/red)
            color = "#2ecc71"  # green
            if used_pct >= 90:
                color = "#e74c3c"  # red
            elif used_pct >= 75:
                color = "#f1c40f"  # yellow
            bar.setStyleSheet(f"QProgressBar::chunk{{background:{color};}}")

            free_txt = human_size(d.free)
            total_txt = human_size(d.total)
            info.setText(f"{free_txt} free of {total_txt}")

            # Table columns
            table_item.setText(0, d.name)
            table_item.setText(1, self._drive_type_str(d))
            table_item.setText(2, free_txt)

            pbar = self.table.itemWidget(table_item, 3)
            if isinstance(pbar, QProgressBar):
                pbar.setValue(used_pct)
                pbar.setFormat(f"{used_pct}%")
                pbar.setStyleSheet(f"QProgressBar::chunk{{background:{color};}}")

    def _drive_type_str(self, d: DriveInfo) -> str:
        # DRIVE types: 2 removable, 3 fixed, 4 remote, 5 cdrom, 6 ramdisk
        return {
            2: "Removable",
            3: "Local Disk",
            4: "Network",
            5: "CD-ROM",
            6: "RAM Disk",
        }.get(d.drive_type, "Drive")

    def _on_tile_double(self, item: QListWidgetItem):
        root = item.data(Qt.UserRole)
        if root and hasattr(self.window(), "open_in_current_tab"):
            self.window().open_in_current_tab(root)

    def _on_table_double(self, item: QTreeWidgetItem, col: int):
        root = None
        # Find which drive root matches this row name
        for r, (_, _, titem) in self._drive_items.items():
            if titem is item:
                root = r
                break
        if root and hasattr(self.window(), "open_in_current_tab"):
            self.window().open_in_current_tab(root)




    def _drive_root_from_tile_item(self, item: QListWidgetItem) -> str | None:
        try:
            return item.data(Qt.UserRole)
        except Exception:
            return None

    def _drive_root_from_table_item(self, item: QTreeWidgetItem) -> str | None:
        for r, (_, _, titem) in self._drive_items.items():
            if titem is item:
                return r
        return None

    def _show_drive_menu(self, root: str, global_pos):
        if not root:
            return
        menu = QMenu(self)

        act_open = menu.addAction("Open")
        act_open_tab = menu.addAction("Open in New Tab")
        menu.addSeparator()

        act_eject = menu.addAction("Eject")
        act_eject.setEnabled(can_eject_drive(root))
        menu.addSeparator()

        act_terminal = menu.addAction("Open in Terminal Here")
        act_explorer = menu.addAction("Open in Windows Explorer")
        act_copy = menu.addAction("Copy Drive Path")
        menu.addSeparator()

        act_diskmgmt = menu.addAction("Open Disk Management")
        menu.addSeparator()

        act_props = menu.addAction("Properties")

        chosen = menu.exec(global_pos)
        if not chosen:
            return

        w = self.window()
        if chosen == act_open:
            if hasattr(w, "open_in_current_tab"):
                w.open_in_current_tab(root)
        elif chosen == act_open_tab:
            if hasattr(w, "open_in_new_tab"):
                w.open_in_new_tab(root)
        elif chosen == act_eject:
            ok = eject_drive_windows(root)
            if not ok:
                QMessageBox.information(self, "Eject", "Could not eject this drive.")
        elif chosen == act_terminal:
            open_in_terminal(root)
        elif chosen == act_explorer:
            try:
                subprocess.Popen(["explorer.exe", root])
            except Exception:
                pass
        elif chosen == act_copy:
            QGuiApplication.clipboard().setText(root.rstrip("\\"))
        elif chosen == act_diskmgmt:
            try:
                subprocess.Popen(["diskmgmt.msc"])
            except Exception:
                pass
        elif chosen == act_props:
            # Drive properties uses same Explorer properties dialog
            if not open_shell_properties(root):
                QMessageBox.information(self, "Properties", root)

    def _on_context_menu_tiles(self, pos):
        item = self.tiles.itemAt(pos)
        if not item:
            return
        root = self._drive_root_from_tile_item(item)
        if root:
            self._show_drive_menu(root, self.tiles.viewport().mapToGlobal(pos))

    def _on_context_menu_table(self, pos):
        item = self.table.itemAt(pos)
        if not item:
            return
        root = self._drive_root_from_table_item(item)
        if root:
            self._show_drive_menu(root, self.table.viewport().mapToGlobal(pos))

# ----------------------------
# Explorer tab (sidebar + file view + this PC)
# ----------------------------
class ExplorerTab(QWidget):
    statusChanged = Signal(str, str)

    def __init__(self, start_path: str, show_hidden: bool = False, preview_enabled: bool = True, pinned_paths: list[str] | None = None):
        super().__init__()
        self._show_hidden = show_hidden
        self._preview_enabled = preview_enabled
        self._current = str(Path.home())
        self._view_mode = "Details"
        self._pinned_paths = pinned_paths or []

        # Models
        self.fs_model = QFileSystemModel()
        self.fs_model.setRootPath(QDir.rootPath())
        self.fs_model.setReadOnly(False)

        self.dir_model = QFileSystemModel()
        self.dir_model.setRootPath(QDir.rootPath())
        self.dir_model.setReadOnly(False)

        self.apply_filters()

        self.proxy = NameFilterProxy(self)
        self.proxy.setSourceModel(self.fs_model)

        # Sidebar (Quick Access / This PC / Drives)
        self.sidebar = QTreeWidget()
        self.sidebar.setHeaderHidden(True)
        self._icon_provider = QFileIconProvider()
        self.sidebar.setIndentation(18)
        self.sidebar.setExpandsOnDoubleClick(True)

        self._build_sidebar_static()

        self.sidebar.itemClicked.connect(self._on_sidebar_clicked)

        # Center stack: normal file browser vs This PC
        self.center_stack = QStackedWidget()

        # Normal file browser views (Details + List/Icon)
        self.details_view = DropCapableTree(self)
        self.details_view.setModel(self.proxy)
        self.details_view.setRootIsDecorated(False)
        self.details_view.setAlternatingRowColors(True)
        self.details_view.setSortingEnabled(True)
        self.details_view.sortByColumn(0, Qt.AscendingOrder)
        self.details_view.header().setSectionResizeMode(0, QHeaderView.Stretch)
        for col in range(1, 4):
            self.details_view.header().setSectionResizeMode(col, QHeaderView.ResizeToContents)

        self.list_view = DropCapableList(self)
        self.list_view.setModel(self.proxy)
        self.list_view.setUniformItemSizes(False)

        self.browser_view_stack = QStackedWidget()
        self.browser_view_stack.addWidget(self.details_view)  # 0
        self.browser_view_stack.addWidget(self.list_view)     # 1

        browser_container = QWidget()
        blay = QVBoxLayout(browser_container)
        blay.setContentsMargins(0, 0, 0, 0)
        blay.addWidget(self.browser_view_stack)

        self.center_stack.addWidget(browser_container)  # 0
        self.this_pc = ThisPCWidget()
        self.center_stack.addWidget(self.this_pc)       # 1

        # Right pane: tabs Preview + Details
        self.right_tabs = QTabWidget()
        self.preview = PreviewPane()
        self.details = DetailsPane()
        self.right_tabs.addTab(self.preview, "Preview")
        self.right_tabs.addTab(self.details, "Details")

        # Splitter main layout
        self.splitter = QSplitter()
        self.splitter.addWidget(self.sidebar)
        self.splitter.addWidget(self.center_stack)
        self.splitter.addWidget(self.right_tabs)
        self.splitter.setStretchFactor(0, 0)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setStretchFactor(2, 0)
        self.splitter.setSizes([240, 780, 360])

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.splitter)

        self._icon_size = 48

        # History
        self.history = []
        self.history_index = -1

        # Context menu hooks
        for v in (self.details_view, self.list_view):
            v.setContextMenuPolicy(Qt.CustomContextMenu)
            v.customContextMenuRequested.connect(lambda pos, view=v: self._on_context_menu(view, pos))
            v.doubleClicked.connect(lambda idx, view=v: self._on_double_clicked(view, idx))

        # Selection updates
        self.details_view.selectionModel().selectionChanged.connect(lambda *_: self._on_selection_changed(self.details_view))
        self.list_view.selectionModel().selectionChanged.connect(lambda *_: self._on_selection_changed(self.list_view))

        self.set_preview_enabled(preview_enabled)
        self.set_view_mode("Details")

        # Start location
        if start_path == THIS_PC_TOKEN:
            self.set_path(THIS_PC_TOKEN, push_history=True)
        else:
            self.set_path(start_path, push_history=True)

    def set_pinned_paths(self, pinned_paths: list[str]):
        self._pinned_paths = pinned_paths or []
        self._refresh_pinned_items()

    # ---- sidebar ----
    def _build_sidebar_static(self):
        self.sidebar.clear()

        self.item_quick = QTreeWidgetItem(["Quick Access"])
        self.item_quick.setExpanded(True)

        def add_quick(name, path):
            it = QTreeWidgetItem([name])
            it.setData(0, Qt.UserRole, path)
            self.item_quick.addChild(it)

        home = str(Path.home())
        add_quick("Home", home)
        add_quick("Desktop", str(Path.home() / "Desktop"))
        add_quick("Downloads", str(Path.home() / "Downloads"))
        add_quick("Documents", str(Path.home() / "Documents"))
        add_quick("Pictures", str(Path.home() / "Pictures"))
        add_quick("Music", str(Path.home() / "Music"))
        add_quick("Videos", str(Path.home() / "Videos"))

        # Pinned section (stored in JSON)  <-- Idea #3
        self.item_pinned = QTreeWidgetItem(["Pinned"])
        self.item_pinned.setExpanded(True)
        self.item_quick.addChild(self.item_pinned)
        self._refresh_pinned_items()

        self.item_thispc = QTreeWidgetItem(["This PC"])
        self.item_thispc.setData(0, Qt.UserRole, THIS_PC_TOKEN)
        self.item_thispc.setExpanded(True)

        self.sidebar.addTopLevelItem(self.item_quick)
        self.sidebar.addTopLevelItem(self.item_thispc)

    def _refresh_pinned_items(self):
        if not hasattr(self, "item_pinned") or self.item_pinned is None:
            return
        self.item_pinned.takeChildren()
        for p in self._pinned_paths:
            name = Path(p).name or p
            it = QTreeWidgetItem([name])
            it.setData(0, Qt.UserRole, p)
            self.item_pinned.addChild(it)
        self.item_pinned.setExpanded(True)

    def update_drives(self, drives: list[DriveInfo]):
        # Update This PC page
        self.this_pc.update_drives(drives)

        # Update drive list in sidebar under This PC
        self.item_thispc.takeChildren()
        for d in drives:
            it = QTreeWidgetItem([d.name])
            it.setData(0, Qt.UserRole, d.root)
            try:
                it.setIcon(0, self._icon_provider.icon(QFileInfo(d.root)))
            except Exception:
                pass
            self.item_thispc.addChild(it)
        self.item_thispc.setExpanded(True)

    def _on_sidebar_clicked(self, item: QTreeWidgetItem, col: int):
        target = item.data(0, Qt.UserRole)
        if target:
            self.set_path(str(target), push_history=True)

    # ---- view modes ----
    def set_view_mode(self, mode: str):
        self._view_mode = mode

        # This PC respects same mode
        self.this_pc.set_view_mode(mode)

        kind, icon = view_mode_to_icon_size(mode, getattr(self, "_icon_size", 48))

        if kind == "details":
            self.browser_view_stack.setCurrentIndex(0)
        else:
            self.browser_view_stack.setCurrentIndex(1)
            if kind == "list":
                self.list_view.setViewMode(QListView.ListMode)
                self.list_view.setIconSize(QSize(icon, icon))
            else:
                self.list_view.setViewMode(QListView.IconMode)
                self.list_view.setResizeMode(QListView.Adjust)
                self.list_view.setMovement(QListView.Static)
                self.list_view.setIconSize(QSize(icon, icon))

        self.statusChanged.emit(self.display_path(), self.status_text())


    def set_icon_size(self, size: int):
        try:
            size = int(size)
        except Exception:
            size = 48
        size = max(16, min(256, size))
        self._icon_size = size

        kind, icon = view_mode_to_icon_size(self._view_mode, self._icon_size)
        if kind in {"icons", "list"}:
            self.list_view.setIconSize(QSize(icon, icon))
        self.this_pc.set_icon_size(icon)

        self.statusChanged.emit(self.display_path(), self.status_text())

    def adjust_icon_size(self, delta: int):
        self.set_icon_size(int(getattr(self, "_icon_size", 48)) + int(delta))

    def display_path(self) -> str:
        tok = self.current_token()
        if tok == THIS_PC_TOKEN:
            return "This PC"
        return str(tok)

    def status_text(self) -> str:
        tok = self.current_token()
        if tok == THIS_PC_TOKEN:
            return "Drives"
        if not os.path.isdir(tok):
            return ""
        # item count (respects current filter)
        try:
            root_idx = self.proxy.mapFromSource(self.fs_model.index(tok))
            items = self.proxy.rowCount(root_idx)
        except Exception:
            items = 0

        sel = self.selected_paths()
        sel_count = len(sel)
        sel_size = 0
        for p in sel:
            try:
                if os.path.isfile(p):
                    sel_size += os.path.getsize(p)
            except Exception:
                pass

        free = ""
        try:
            du = shutil.disk_usage(tok)
            free = f"Free: {human_size(du.free)}"
        except Exception:
            free = ""

        parts = [f"Items: {items}"]
        if sel_count:
            parts.append(f"Selected: {sel_count}")
            if sel_size:
                parts.append(f"Selected size: {human_size(sel_size)}")
        if free:
            parts.append(free)
        return "  |  ".join(parts)

    def set_search_text(self, text: str):
        self.proxy.set_filter_text(text)

    # ---- filters ----
    def apply_filters(self):
        file_filter = QDir.AllEntries | QDir.NoDotAndDotDot
        dir_filter = QDir.AllDirs | QDir.NoDotAndDotDot | QDir.Drives
        if self._show_hidden:
            file_filter |= QDir.Hidden
            dir_filter |= QDir.Hidden
        self.fs_model.setFilter(file_filter)
        self.dir_model.setFilter(dir_filter)

    def set_show_hidden(self, enabled: bool):
        self._show_hidden = enabled
        self.apply_filters()

    def set_preview_enabled(self, enabled: bool):
        self._preview_enabled = enabled
        self.right_tabs.setVisible(enabled)
        if not enabled:
            self.preview.set_empty()
            self.details.set_empty()

    # ---- path + history ----
    def current_token(self) -> str:
        if self.history_index >= 0 and self.history:
            return self.history[self.history_index]
        return str(Path.home())

    def current_path_real(self) -> str:
        tok = self.current_token()
        if tok == THIS_PC_TOKEN:
            return str(Path.home())
        return tok

    def can_back(self) -> bool:
        return self.history_index > 0

    def can_forward(self) -> bool:
        return self.history_index >= 0 and self.history_index < (len(self.history) - 1)

    def go_back(self):
        if self.can_back():
            self.history_index -= 1
            self._sync_to_history()

    def go_forward(self):
        if self.can_forward():
            self.history_index += 1
            self._sync_to_history()

    def go_up(self):
        tok = self.current_token()
        if tok == THIS_PC_TOKEN:
            return
        p = Path(tok)
        parent = str(p.parent) if p.parent != p else str(p)
        self.set_path(parent, push_history=True)

    def refresh(self):
        tok = self.current_token()
        self.set_path(tok, push_history=False)

    def set_path(self, path: str, push_history: bool = True):
        # Handle This PC
        if path == THIS_PC_TOKEN or str(path).strip().lower() in {"this pc", "thispc"}:
            self._current = THIS_PC_TOKEN
            self.center_stack.setCurrentIndex(1)
            self._update_right_panes_for_no_selection()
            if push_history:
                self._push_history(THIS_PC_TOKEN)
            return

        path = os.path.abspath(path)
        if not os.path.exists(path):
            QMessageBox.warning(self, "Path not found", f"That path doesn't exist:\n{path}")
            return

        if os.path.isfile(path):
            path = os.path.dirname(path)

        src_root = self.fs_model.index(path)
        if not src_root.isValid():
            QMessageBox.warning(self, "Invalid path", f"Can't open:\n{path}")
            return

        proxy_root = self.proxy.mapFromSource(src_root)

        # Update both views’ root
        self.details_view.setRootIndex(proxy_root)
        self.list_view.setRootIndex(proxy_root)

        self.center_stack.setCurrentIndex(0)
        self._current = path

        if push_history:
            self._push_history(path)

        self._update_right_panes_for_no_selection()
        self.statusChanged.emit(self.display_path(), self.status_text())


    def _push_history(self, tok: str):
        if self.history_index >= 0:
            self.history = self.history[: self.history_index + 1]
        self.history.append(tok)
        self.history_index = len(self.history) - 1

    def _sync_to_history(self):
        tok = self.current_token()
        self.set_path(tok, push_history=False)

    def _update_right_panes_for_no_selection(self):
        if not self._preview_enabled:
            return
        self.preview.set_empty()
        self.details.set_empty()

    # ---- selection helpers ----
    def active_view(self):
        if self.center_stack.currentIndex() != 0:
            return None
        return self.details_view if self.browser_view_stack.currentIndex() == 0 else self.list_view

    def map_to_source(self, idx: QModelIndex) -> QModelIndex:
        return self.proxy.mapToSource(idx)

    def selected_paths(self) -> list[str]:
        view = self.active_view()
        if view is None:
            return []
        paths = []
        if isinstance(view, QTreeView):
            indexes = view.selectionModel().selectedRows(0)
        else:
            indexes = view.selectionModel().selectedIndexes()
        for idx in indexes:
            if idx.column() != 0:
                continue
            src = self.map_to_source(idx)
            p = self.fs_model.filePath(src)
            if p:
                paths.append(p)
        seen = set()
        out = []
        for p in paths:
            if p not in seen:
                out.append(p)
                seen.add(p)
        return out

    # ---- clipboard ----
    def clipboard_set_paths(self, paths: list[str], cut: bool):
        from PySide6.QtCore import QMimeData
        md = QMimeData()
        md.setUrls([QUrl.fromLocalFile(p) for p in paths])
        md.setData("application/x-explorer-cut", b"1" if cut else b"0")
        QGuiApplication.clipboard().setMimeData(md)

    def clipboard_get_paths(self) -> tuple[list[str], bool]:
        md = QGuiApplication.clipboard().mimeData()
        if not md or not md.hasUrls():
            return [], False
        paths = [u.toLocalFile() for u in md.urls() if u.isLocalFile()]
        cut = False
        try:
            cut = bytes(md.data("application/x-explorer-cut")) == b"1"
        except Exception:
            cut = False
        return paths, cut

    def paste_into_current(self):
        tok = self.current_token()
        if tok == THIS_PC_TOKEN:
            return
        src_paths, cut = self.clipboard_get_paths()
        if not src_paths:
            return
        dest = tok
        try:
            self.copy_or_move_into(dest, src_paths, move=cut)
            if cut:
                self.clipboard_set_paths([], cut=False)
        except Exception as e:
            QMessageBox.warning(self, "Paste failed", str(e))

    # ---- filesystem actions ----
    def open_path_default(self, path: str):
        try:
            os.startfile(path)  # Windows default app
        except Exception:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))


    def open_with_dialog(self, path: str):
        # Windows "Open with..." dialog
        if not sys.platform.startswith("win"):
            self.open_path_default(path)
            return
        try:
            subprocess.Popen(["rundll32.exe", "shell32.dll,OpenAs_RunDLL", os.path.abspath(path)])
        except Exception:
            self.open_path_default(path)
    def copy_or_move_into(self, dest_folder: str, src_paths: list[str], move: bool):
        dest_folder = os.path.abspath(dest_folder)
        if not os.path.isdir(dest_folder):
            raise RuntimeError("Destination is not a folder.")

        plan: list[tuple[str, str]] = []

        def unique_top_level_dst(base_name: str) -> str:
            dst = os.path.join(dest_folder, base_name)
            if not os.path.exists(dst):
                return dst
            stem = Path(base_name).stem
            ext = Path(base_name).suffix
            n = 2
            while True:
                cand = os.path.join(dest_folder, f"{stem} ({n}){ext}")
                if not os.path.exists(cand):
                    return cand
                n += 1

        for src_path in src_paths:
            src_path = os.path.abspath(src_path)
            base = os.path.basename(src_path.rstrip("\/"))
            if not base:
                continue
            top_dst = unique_top_level_dst(base)

            if os.path.isdir(src_path):
                for root, _dirs, files in os.walk(src_path):
                    rel = os.path.relpath(root, src_path)
                    dst_dir = top_dst if rel == "." else os.path.join(top_dst, rel)
                    for fn in files:
                        s = os.path.join(root, fn)
                        d = os.path.join(dst_dir, fn)
                        plan.append((s, d))
            else:
                plan.append((src_path, top_dst))

        dlg = FileOpProgressDialog(self, "Moving..." if move else "Copying...")
        worker = FileOpWorker(plan, move=move, parent=dlg)
        dlg.start_worker(worker)
        dlg.exec()

        if move:
            for src_path in src_paths:
                try:
                    if os.path.isdir(src_path):
                        shutil.rmtree(src_path, ignore_errors=True)
                except Exception:
                    pass

        self.refresh()


    def delete_paths(self, paths: list[str]):
        if not paths:
            return
        msg = "Send selected item(s) to Recycle Bin?\n\n" + "\n".join(paths[:8])
        if len(paths) > 8:
            msg += f"\n... (+{len(paths)-8} more)"
        if QMessageBox.question(self, "Delete", msg, QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return

        if sys.platform.startswith("win"):
            ok = _windows_send_to_recycle_bin(paths)
            if not ok:
                QMessageBox.warning(self, "Delete failed", "Could not send to Recycle Bin.")
        else:
            for p in paths:
                if os.path.isdir(p):
                    shutil.rmtree(p)
                else:
                    os.remove(p)
        self.refresh()

    def new_folder(self):
        tok = self.current_token()
        if tok == THIS_PC_TOKEN:
            return
        base = "New folder"
        dest = os.path.join(tok, base)
        n = 2
        while os.path.exists(dest):
            dest = os.path.join(tok, f"{base} ({n})")
            n += 1
        try:
            os.makedirs(dest, exist_ok=False)
            self.refresh()
        except Exception as e:
            QMessageBox.warning(self, "New folder failed", str(e))

    def new_text_file(self):
        tok = self.current_token()
        if tok == THIS_PC_TOKEN:
            return
        base = "New Text Document.txt"
        dest = os.path.join(tok, base)
        n = 2
        while os.path.exists(dest):
            dest = os.path.join(tok, f"New Text Document ({n}).txt")
            n += 1
        try:
            with open(dest, "w", encoding="utf-8") as f:
                f.write("")
            self.refresh()
        except Exception as e:
            QMessageBox.warning(self, "New file failed", str(e))

    # ---- UI events ----
    def _on_double_clicked(self, view, idx: QModelIndex):
        if self.current_token() == THIS_PC_TOKEN:
            return
        src_idx = self.map_to_source(idx)
        path = self.fs_model.filePath(src_idx)
        if not path:
            return
        if os.path.isdir(path):
            self.set_path(path, push_history=True)
            return

        if os.path.isfile(path) and path.lower().endswith(".zip"):
            dlg = ZipBrowserDialog(self, path)
            dlg.exec()
            return

        self.open_path_default(path)

    def _on_selection_changed(self, view):
        if not self._preview_enabled:
            return
        if self.current_token() == THIS_PC_TOKEN:
            self.preview.set_empty()
            self.details.set_empty()
            return

        paths = self.selected_paths()
        if not paths:
            self.preview.set_empty()
            self.details.set_empty()
            return

        if len(paths) > 1:
            self.preview.show_multi_summary(paths)
            self.details.show_multi_summary(paths)
            return

        p = paths[0]
        icon = self.fs_model.fileIcon(self.fs_model.index(p))
        self.preview.show_single(p, icon=icon)
        self.details.show_single(p)
        self.statusChanged.emit(self.display_path(), self.status_text())


    def _on_context_menu(self, view, pos):
        tok = self.current_token()
        idx = view.indexAt(pos)
        paths = self.selected_paths()

        # Determine folder candidates (for pin/unpin)
        folder_targets = [p for p in paths if os.path.isdir(p)]
        can_pin_current = (not paths) and (tok != THIS_PC_TOKEN) and os.path.isdir(tok)

        menu = QMenu(self)

        act_open = menu.addAction("Open")
        act_open_tab = menu.addAction("Open in New Tab")
        act_open_with = menu.addAction("Open with...")
        act_browse_zip = menu.addAction("Browse ZIP...")
        act_extract_here = menu.addAction("Extract ZIP Here")

        # Idea #3: Pin / Unpin
        menu.addSeparator()
        act_pin = menu.addAction("Pin to Quick Access")
        act_unpin = menu.addAction("Unpin from Quick Access")

        menu.addSeparator()
        act_copy = menu.addAction("Copy")
        act_cut = menu.addAction("Cut")
        act_paste = menu.addAction("Paste")
        menu.addSeparator()

        act_rename = menu.addAction("Rename")
        act_delete = menu.addAction("Delete")
        menu.addSeparator()

        act_copy_path = menu.addAction("Copy Path")
        act_terminal = menu.addAction("Open in Terminal Here")
        act_winexplorer = menu.addAction("Open in Windows Explorer")
        menu.addSeparator()

        act_new_folder = menu.addAction("New Folder")
        act_new_text = menu.addAction("New Text Document")
        menu.addSeparator()

        act_props = menu.addAction("Properties")

        has_sel = len(paths) > 0
        act_open.setEnabled(has_sel)
        act_open_tab.setEnabled(has_sel)
        act_open_with.setEnabled(has_sel and len(paths) == 1 and os.path.isfile(paths[0]))
        is_zip = (has_sel and len(paths) == 1 and os.path.isfile(paths[0]) and paths[0].lower().endswith('.zip'))
        act_browse_zip.setEnabled(is_zip)
        act_extract_here.setEnabled(is_zip)
        act_copy.setEnabled(has_sel)
        act_cut.setEnabled(has_sel)
        act_rename.setEnabled(has_sel and len(paths) == 1 and tok != THIS_PC_TOKEN)
        act_delete.setEnabled(has_sel and tok != THIS_PC_TOKEN)

        clip_paths, _ = self.clipboard_get_paths()
        act_paste.setEnabled(bool(clip_paths) and tok != THIS_PC_TOKEN and os.path.isdir(tok))

        act_copy_path.setEnabled(has_sel)
        act_winexplorer.setEnabled(tok != THIS_PC_TOKEN)

        act_new_folder.setEnabled(tok != THIS_PC_TOKEN)
        act_new_text.setEnabled(tok != THIS_PC_TOKEN)

        # Pin/unpin enable logic
        to_pin = folder_targets[:] if folder_targets else ([tok] if can_pin_current else [])
        pinned_set = set(self._pinned_paths)
        act_pin.setEnabled(bool(to_pin))
        act_unpin.setEnabled(any(p in pinned_set for p in to_pin))

        chosen = menu.exec(QCursor.pos())
        if not chosen:
            return

        if chosen == act_open and paths:
            p = paths[0]
            if os.path.isdir(p):
                self.set_path(p, push_history=True)
            else:
                self.open_path_default(p)

        elif chosen == act_open_tab and paths:
            p = paths[0]
            w = self.window()
            if hasattr(w, "open_in_new_tab"):
                w.open_in_new_tab(p)

        elif chosen == act_pin:
            w = self.window()
            if hasattr(w, "pin_paths"):
                w.pin_paths(to_pin)

        elif chosen == act_unpin:
            w = self.window()
            if hasattr(w, "unpin_paths"):
                w.unpin_paths([p for p in to_pin if p in pinned_set])

        elif chosen == act_copy and paths:
            self.clipboard_set_paths(paths, cut=False)

        elif chosen == act_cut and paths:
            self.clipboard_set_paths(paths, cut=True)

        elif chosen == act_paste:
            self.paste_into_current()

        elif chosen == act_rename and idx.isValid():
            view.edit(idx.siblingAtColumn(0))

        elif chosen == act_delete and paths:
            self.delete_paths(paths)

        elif chosen == act_copy_path and paths:
            QGuiApplication.clipboard().setText("\n".join(paths))

        elif chosen == act_terminal:
            open_in_terminal(tok if tok != THIS_PC_TOKEN else str(Path.home()))

        elif chosen == act_winexplorer:
            try:
                subprocess.Popen(["explorer.exe", tok])
            except Exception:
                pass

        elif chosen == act_new_folder:
            self.new_folder()

        elif chosen == act_new_text:
            self.new_text_file()

        elif chosen == act_props and (paths or (tok != THIS_PC_TOKEN)):
            target = paths[0] if paths else tok
            self._show_properties(target)

    def _show_properties(self, path: str):
        # Idea #2: Real Explorer properties dialog
        if sys.platform.startswith("win"):
            if open_shell_properties(path):
                return

        # Fallback to previous simple dialog
        p = Path(path)
        try:
            st = p.stat()
            modified = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            created = datetime.fromtimestamp(st.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
            size = human_size(st.st_size) if p.is_file() else ""
        except Exception:
            modified = created = "Unknown"
            size = ""

        kind = "Folder" if p.is_dir() else "File"
        dur = try_ffprobe_duration(str(p)) if (p.is_file() and is_media_file(str(p))) else None
        extra = f"\nDuration: {dur}" if dur else ""
        QMessageBox.information(
            self,
            "Properties",
            f"Name: {p.name}\nType: {kind}\nSize: {size}\nCreated: {created}\nModified: {modified}{extra}\nPath: {p}"
        )




class SettingsDialog(QDialog):
    def __init__(self, parent, current: dict):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(520)

        self.tabs = QTabWidget()

        # --- General ---
        general = QWidget()
        gform = QFormLayout(general)

        self.chk_info_pane = QCheckBox("Enable Info pane (Preview/Details)")
        self.chk_info_pane.setChecked(bool(current.get("preview_enabled", True)))

        self.chk_hidden = QCheckBox("Show hidden files/folders")
        self.chk_hidden.setChecked(bool(current.get("show_hidden", False)))

        self.chk_restore = QCheckBox("Restore tabs on startup")
        self.chk_restore.setChecked(bool(current.get("restore_session", True)))

        self.spin_icon = QSpinBox()
        self.spin_icon.setRange(16, 256)
        self.spin_icon.setSingleStep(8)
        self.spin_icon.setValue(int(current.get("icon_size", 48)))

        self.cbo_view = QComboBox()
        self.cbo_view.addItems(["Details", "List", "Small icons", "Medium icons", "Large icons", "Extra large icons"])
        cur_view = current.get("view_mode", "Details")
        if cur_view in {"Details", "List", "Small icons", "Medium icons", "Large icons", "Extra large icons"}:
            self.cbo_view.setCurrentText(cur_view)

        gform.addRow(self.chk_info_pane)
        gform.addRow(self.chk_hidden)
        gform.addRow(self.chk_restore)
        gform.addRow("Default icon size:", self.spin_icon)
        gform.addRow("Default view mode:", self.cbo_view)

        # --- Advanced ---
        adv = QWidget()
        aform = QFormLayout(adv)

        self.spin_drive_poll = QSpinBox()
        self.spin_drive_poll.setRange(500, 10000)
        self.spin_drive_poll.setSingleStep(250)
        self.spin_drive_poll.setValue(int(current.get("drive_poll_ms", 1500)))
        self.spin_drive_poll.setSuffix(" ms")

        aform.addRow("Drive refresh interval:", self.spin_drive_poll)

        self.chk_default_mgr = QCheckBox("Set Noxen as the default file manager (Win + E)")
        self.chk_default_mgr.setChecked(is_default_file_manager_enabled())

        note = QLabel("This uses a registry workaround for the *current user*. You may need to restart Windows Explorer or sign out/in for it to apply everywhere.")
        note.setWordWrap(True)
        note.setStyleSheet("color: gray;")

        aform.addRow(self.chk_default_mgr)
        aform.addRow(note)

        self.tabs.addTab(general, "General")
        self.tabs.addTab(adv, "Advanced")

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        lay = QVBoxLayout(self)
        lay.addWidget(self.tabs)
        lay.addWidget(buttons)

    def get_settings(self) -> dict:
        return {
            "preview_enabled": self.chk_info_pane.isChecked(),
            "show_hidden": self.chk_hidden.isChecked(),
            "view_mode": self.cbo_view.currentText(),
            "drive_poll_ms": int(self.spin_drive_poll.value()),
            "default_file_manager": self.chk_default_mgr.isChecked(),
        }

# ----------------------------
# Main window
# ----------------------------
class MainWindow(QMainWindow):
    def __init__(self, start_path: str | None = None):
        super().__init__()
        self.setWindowTitle("Noxen File explorer (Tabbed File Explorer)")
        self.setMinimumSize(1100, 700)

        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.tabBar().setContextMenuPolicy(Qt.CustomContextMenu)
        self.tabs.tabBar().customContextMenuRequested.connect(self._on_tab_context_menu)
        self.tabs.currentChanged.connect(self._on_current_tab_changed)
        self.setCentralWidget(self.tabs)

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status_path = QLabel("")
        self.status_info = QLabel("")
        self.status.addPermanentWidget(self.status_path, 1)
        self.status.addPermanentWidget(self.status_info, 0)

        self.settings = load_settings()
        self._show_hidden = bool(self.settings.get("show_hidden", False))
        self._preview_enabled = bool(self.settings.get("preview_enabled", True))
        self._view_mode = str(self.settings.get("view_mode", "Details"))
        self._icon_size = int(self.settings.get("icon_size", 48))
        self._restore_session = bool(self.settings.get("restore_session", True))

        # Idea #3: load pinned paths (Quick Access)
        self.pinned_paths = load_pinned_paths()

        self._build_toolbar()
        self._build_shortcuts()

        # Drive watcher (auto-update connect/disconnect) — polling
        self._last_drive_roots = set()
        self.drive_timer = QTimer(self)
        self.drive_timer.timeout.connect(self.refresh_drives_all_tabs)
        self.drive_timer.start(int(self.settings.get("drive_poll_ms", 1500)))

        # First tab: This PC (or a startup path if launched via registry)
        if isinstance(start_path, str) and start_path.strip():
            self.new_tab(start_path)
        else:
            self.new_tab(THIS_PC_TOKEN)
        self.refresh_drives_all_tabs()
        self._refresh_pinned_all_tabs()

    def _build_toolbar(self):
        self.toolbar = QToolBar("Explorer")
        self.toolbar.setMovable(False)
        self.addToolBar(self.toolbar)

        self.act_back = QAction(self.style().standardIcon(QStyle.SP_ArrowBack), "Back", self)
        self.act_forward = QAction(self.style().standardIcon(QStyle.SP_ArrowForward), "Forward", self)
        self.act_up = QAction(self.style().standardIcon(QStyle.SP_ArrowUp), "Up", self)
        self.act_refresh = QAction(self.style().standardIcon(QStyle.SP_BrowserReload), "Refresh", self)
        self.act_new_tab = QAction("+", self)
        self.act_terminal = QAction("Terminal", self)

        self.act_back.triggered.connect(lambda: self._with_tab(lambda t: t.go_back()))
        self.act_forward.triggered.connect(lambda: self._with_tab(lambda t: t.go_forward()))
        self.act_up.triggered.connect(lambda: self._with_tab(lambda t: t.go_up()))
        self.act_refresh.triggered.connect(lambda: self._with_tab(lambda t: t.refresh()))
        self.act_new_tab.triggered.connect(lambda: self.new_tab(self.current_tab_token_or_home()))
        self.act_terminal.triggered.connect(lambda: open_in_terminal(self.current_tab_path_or_home()))

        self.toolbar.addAction(self.act_back)
        self.toolbar.addAction(self.act_forward)
        self.toolbar.addAction(self.act_up)
        self.toolbar.addAction(self.act_refresh)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.act_new_tab)
        self.toolbar.addSeparator()

        # Idea #1: Breadcrumb address bar
        self.address_bar = BreadcrumbBar()
        self.address_bar.setMinimumWidth(460)
        self.address_bar.pathEntered.connect(self._address_entered_text)
        self.address_bar.pathSelected.connect(self._address_selected_crumb)
        self.toolbar.addWidget(self.address_bar)

        self.toolbar.addSeparator()

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search (filters current folder)")
        self.search.textChanged.connect(self._search_changed)
        self.search.setMinimumWidth(240)
        self.toolbar.addWidget(self.search)

        self.toolbar.addSeparator()

        self.view_mode = QComboBox()
        self.view_mode.addItems(["Details", "List", "Icons"])
        if self._view_mode in {"Details", "List", "Icons"}:
            self.view_mode.setCurrentText(self._view_mode)
        self.view_mode.currentTextChanged.connect(self._view_mode_changed)
        self.toolbar.addWidget(self.view_mode)

        self.toolbar.addSeparator()
        self.toolbar.addAction(self.act_terminal)
        self.toolbar.addSeparator()
        self.act_settings = QAction("Settings", self)
        self.act_settings.triggered.connect(self.open_settings)
        self.toolbar.addAction(self.act_settings)
        self.toolbar.addSeparator()

        self.chk_preview = QCheckBox("Info pane")
        self.chk_preview.setChecked(self._preview_enabled)
        self.chk_preview.stateChanged.connect(self._toggle_preview)
        self.toolbar.addWidget(self.chk_preview)

        self.chk_hidden = QCheckBox("Hidden")
        self.chk_hidden.setChecked(self._show_hidden)
        self.chk_hidden.stateChanged.connect(self._toggle_hidden)
        self.toolbar.addWidget(self.chk_hidden)

    def _build_shortcuts(self):
        self.shortcut_new_tab = QAction(self)
        self.shortcut_new_tab.setShortcut(QKeySequence("Ctrl+T"))
        self.shortcut_new_tab.triggered.connect(lambda: self.new_tab(self.current_tab_token_or_home()))
        self.addAction(self.shortcut_new_tab)

        self.shortcut_close_tab = QAction(self)
        self.shortcut_close_tab.setShortcut(QKeySequence("Ctrl+W"))
        self.shortcut_close_tab.triggered.connect(lambda: self.close_tab(self.tabs.currentIndex()))
        self.addAction(self.shortcut_close_tab)

        self.shortcut_refresh = QAction(self)
        self.shortcut_refresh.setShortcut(QKeySequence("F5"))
        self.shortcut_refresh.triggered.connect(lambda: self._with_tab(lambda t: t.refresh()))
        self.addAction(self.shortcut_refresh)

        # Focus address bar (Explorer-ish)
        self.shortcut_focus_addr = QAction(self)
        self.shortcut_focus_addr.setShortcuts([QKeySequence("Ctrl+L"), QKeySequence("Alt+D")])
        self.shortcut_focus_addr.triggered.connect(lambda: self.address_bar.activate_edit())
        self.addAction(self.shortcut_focus_addr)

        self.shortcut_rename = QAction(self)
        self.shortcut_rename.setShortcut(QKeySequence("F2"))
        self.shortcut_rename.triggered.connect(self._rename_selected)
        self.addAction(self.shortcut_rename)

        self.shortcut_delete = QAction(self)
        self.shortcut_delete.setShortcut(QKeySequence.Delete)
        self.shortcut_delete.triggered.connect(self._delete_selected)
        self.addAction(self.shortcut_delete)

        self.shortcut_copy = QAction(self)
        self.shortcut_copy.setShortcut(QKeySequence.Copy)
        self.shortcut_copy.triggered.connect(self._copy_selected)
        self.addAction(self.shortcut_copy)

        self.shortcut_cut = QAction(self)
        self.shortcut_cut.setShortcut(QKeySequence.Cut)
        self.shortcut_cut.triggered.connect(self._cut_selected)
        self.addAction(self.shortcut_cut)

        self.shortcut_paste = QAction(self)
        self.shortcut_paste.setShortcut(QKeySequence.Paste)
        self.shortcut_paste.triggered.connect(lambda: self._with_tab(lambda t: t.paste_into_current()))
        self.addAction(self.shortcut_paste)


    def open_settings(self):
        dlg = SettingsDialog(self, {
            "preview_enabled": self._preview_enabled,
            "show_hidden": self._show_hidden,
            "view_mode": self._view_mode,
            "drive_poll_ms": int(self.settings.get("drive_poll_ms", 1500)),
            "default_file_manager": bool(self.settings.get("default_file_manager", False)),
        })
        if dlg.exec() != QDialog.Accepted:
            return

        new = dlg.get_settings()

        # Apply / revert "default file manager" registry workaround
        desired_default = bool(new.get("default_file_manager", False))
        current_default = is_default_file_manager_enabled()
        if desired_default != current_default:
            try:
                set_default_file_manager_enabled(desired_default)
                # Ask whether to restart Explorer for the change to take full effect
                res = QMessageBox.question(
                    self,
                    "Restart Explorer?",
                    "Default file manager setting updated.\n\nRestart Windows Explorer now to apply the change more reliably?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )
                if res == QMessageBox.Yes:
                    restart_windows_explorer()
            except Exception as e:
                QMessageBox.warning(self, "Default file manager", f"Couldn't update the registry.\n\n{e}")
                # keep settings consistent with reality
                new["default_file_manager"] = current_default
        # Apply + persist
        self._preview_enabled = bool(new["preview_enabled"])
        self._show_hidden = bool(new["show_hidden"])
        self._view_mode = str(new["view_mode"])
        self.settings.update(new)
        save_settings(self.settings)

        # Update UI controls
        self.chk_preview.blockSignals(True)
        self.chk_preview.setChecked(self._preview_enabled)
        self.chk_preview.blockSignals(False)

        self.chk_hidden.blockSignals(True)
        self.chk_hidden.setChecked(self._show_hidden)
        self.chk_hidden.blockSignals(False)

        self.view_mode.blockSignals(True)
        self.view_mode.setCurrentText(self._view_mode)
        self.view_mode.blockSignals(False)

        # Update drive refresh timer
        try:
            self.drive_timer.setInterval(int(self.settings.get("drive_poll_ms", 1500)))
        except Exception:
            pass

        # Apply to all tabs
        for i in range(self.tabs.count()):
            w = self.tabs.widget(i)
            if isinstance(w, ExplorerTab):
                w.set_preview_enabled(self._preview_enabled)
                w.set_show_hidden(self._show_hidden)
                w.set_view_mode(self._view_mode)

        self.status.showMessage("Settings updated", 1500)

    # ---- pinned manager ----
    def _refresh_pinned_all_tabs(self):
        for i in range(self.tabs.count()):
            w = self.tabs.widget(i)
            if isinstance(w, ExplorerTab):
                w.set_pinned_paths(self.pinned_paths)

    def pin_paths(self, paths: list[str]):
        changed = False
        for p in paths:
            if not isinstance(p, str) or not p:
                continue
            p = os.path.abspath(p)
            if p not in self.pinned_paths:
                self.pinned_paths.append(p)
                changed = True
        if changed:
            save_pinned_paths(self.pinned_paths)
            self._refresh_pinned_all_tabs()
            self.status.showMessage("Pinned to Quick Access", 1500)

    def unpin_paths(self, paths: list[str]):
        s = set(os.path.abspath(p) for p in paths if isinstance(p, str))
        if not s:
            return
        before = len(self.pinned_paths)
        self.pinned_paths = [p for p in self.pinned_paths if os.path.abspath(p) not in s]
        if len(self.pinned_paths) != before:
            save_pinned_paths(self.pinned_paths)
            self._refresh_pinned_all_tabs()
            self.status.showMessage("Unpinned from Quick Access", 1500)

    # ---- tabs helpers ----
    def current_tab(self) -> ExplorerTab | None:
        w = self.tabs.currentWidget()
        return w if isinstance(w, ExplorerTab) else None

    def current_tab_token_or_home(self) -> str:
        tab = self.current_tab()
        if tab is None:
            return str(Path.home())
        tok = tab.current_token()
        if tok == THIS_PC_TOKEN:
            return THIS_PC_TOKEN
        return tok

    def current_tab_path_or_home(self) -> str:
        tab = self.current_tab()
        if tab is None:
            return str(Path.home())
        return tab.current_path_real()

    def new_tab(self, path: str):
        tab = ExplorerTab(path, show_hidden=self._show_hidden, preview_enabled=self._preview_enabled, pinned_paths=self.pinned_paths)
        tab.set_view_mode(self._view_mode)
        tab.set_icon_size(self._icon_size)
        tab.statusChanged.connect(self._on_tab_status)

        idx = self.tabs.addTab(tab, "New Tab")
        self.tabs.setCurrentIndex(idx)
        self._update_tab_title(tab)
        self._sync_address_with_tab(tab)
        self._sync_nav_buttons(tab)

    def open_in_new_tab(self, path: str):
        if os.path.isfile(path):
            path = os.path.dirname(path)
        self.new_tab(path)

    def open_in_current_tab(self, path: str):
        tab = self.current_tab()
        if tab:
            tab.set_path(path, push_history=True)
            self._sync_address_with_tab(tab)
            self._update_tab_title(tab)


    def _is_tab_pinned(self, index: int) -> bool:
        try:
            return bool(self.tabs.tabBar().tabData(index) == "pinned")
        except Exception:
            return False

    def _set_tab_pinned(self, index: int, pinned: bool):
        try:
            self.tabs.tabBar().setTabData(index, "pinned" if pinned else None)
            w = self.tabs.widget(index)
            if w is not None:
                self._update_tab_title(w)
        except Exception:
            pass

    def _on_tab_context_menu(self, pos):
        bar = self.tabs.tabBar()
        idx = bar.tabAt(pos)
        if idx < 0:
            return
        menu = QMenu(self)
        act_pin = menu.addAction("Pin tab" if not self._is_tab_pinned(idx) else "Unpin tab")
        act_dup = menu.addAction("Duplicate tab")
        menu.addSeparator()
        act_close = menu.addAction("Close tab")
        chosen = menu.exec(QCursor.pos())
        if not chosen:
            return
        if chosen == act_pin:
            self._set_tab_pinned(idx, not self._is_tab_pinned(idx))
        elif chosen == act_dup:
            w = self.tabs.widget(idx)
            if w is not None:
                self.new_tab(w.current_token())
        elif chosen == act_close:
            self.close_tab(idx)

    def close_tab(self, index: int):
        if self._is_tab_pinned(index):
            return
        if index < 0 or index >= self.tabs.count():
            return
        if self.tabs.count() == 1:
            self.tabs.removeTab(index)
            self.new_tab(THIS_PC_TOKEN)
            return
        w = self.tabs.widget(index)
        self.tabs.removeTab(index)
        if w is not None:
            w.deleteLater()

    def _with_tab(self, fn):
        tab = self.current_tab()
        if tab is not None:
            fn(tab)
            self._sync_address_with_tab(tab)
            self._update_tab_title(tab)
            self._sync_nav_buttons(tab)

    def _sync_nav_buttons(self, tab: ExplorerTab):
        self.act_back.setEnabled(tab.can_back())
        self.act_forward.setEnabled(tab.can_forward())

    def _sync_address_with_tab(self, tab: ExplorerTab):
        tok = tab.current_token()
        self.address_bar.set_path(tok)

    def _update_tab_title(self, tab: ExplorerTab):
        i = self.tabs.indexOf(tab)
        if i >= 0:
            title = basename_for_tab(tab.current_token())
            if self._is_tab_pinned(i):
                title = '📌 ' + title
            self.tabs.setTabText(i, title)

    def _on_current_tab_changed(self, _):
        tab = self.current_tab()
        if tab is None:
            return
        self._sync_address_with_tab(tab)
        self.search.blockSignals(True)
        self.search.setText("")
        self.search.blockSignals(False)
        tab.set_search_text("")
        self._sync_nav_buttons(tab)

    # ---- breadcrumb handlers ----
    def _address_selected_crumb(self, target: str):
        if target == THIS_PC_TOKEN or str(target).strip().lower() in {"this pc", "thispc"}:
            self._with_tab(lambda t: t.set_path(THIS_PC_TOKEN, push_history=True))
        else:
            self._with_tab(lambda t: t.set_path(target, push_history=True))
        try:
            self._on_tab_status(tab.display_path(), tab.status_text())
        except Exception:
            pass


    def _on_tab_status(self, path_text: str, info_text: str):
        self.status_path.setText(path_text or "")
        self.status_info.setText(info_text or "")


    def _address_entered_text(self, text: str):
        text = (text or "").strip()
        if not text:
            return
        if text.lower() in {"this pc", "thispc"}:
            self._with_tab(lambda t: t.set_path(THIS_PC_TOKEN, push_history=True))
        else:
            self._with_tab(lambda t: t.set_path(text, push_history=True))

    def _search_changed(self, text: str):
        tab = self.current_tab()
        if tab:
            tab.set_search_text(text)

    def _view_mode_changed(self, mode: str):
        self._view_mode = mode
        self.settings["view_mode"] = self._view_mode
        save_settings(self.settings)
        tab = self.current_tab()
        if tab:
            tab.set_view_mode(mode)

    def _toggle_preview(self, state: int):
        self._preview_enabled = state == Qt.Checked
        self.settings["preview_enabled"] = self._preview_enabled
        save_settings(self.settings)
        tab = self.current_tab()
        if tab:
            tab.set_preview_enabled(self._preview_enabled)

    def _toggle_hidden(self, state: int):
        self._show_hidden = state == Qt.Checked
        self.settings["show_hidden"] = self._show_hidden
        save_settings(self.settings)
        tab = self.current_tab()
        if tab:
            tab.set_show_hidden(self._show_hidden)

    def _rename_selected(self):
        tab = self.current_tab()
        if not tab:
            return
        view = tab.active_view()
        if view is None:
            return
        idx = view.currentIndex()
        if idx.isValid():
            view.edit(idx.siblingAtColumn(0))

    def _delete_selected(self):
        tab = self.current_tab()
        if not tab:
            return
        paths = tab.selected_paths()
        if paths:
            tab.delete_paths(paths)

    def _copy_selected(self):
        tab = self.current_tab()
        if not tab:
            return
        paths = tab.selected_paths()
        if paths:
            tab.clipboard_set_paths(paths, cut=False)

    def _cut_selected(self):
        tab = self.current_tab()
        if not tab:
            return
        paths = tab.selected_paths()
        if paths:
            tab.clipboard_set_paths(paths, cut=True)

    def refresh_drives_all_tabs(self):
        if not sys.platform.startswith("win"):
            return
        drives = list_drives_windows()
        roots = set(d.root for d in drives)
        changed = roots != self._last_drive_roots
        self._last_drive_roots = roots

        for i in range(self.tabs.count()):
            w = self.tabs.widget(i)
            if isinstance(w, ExplorerTab):
                w.update_drives(drives)
        if changed:
            self.status.showMessage("Drives updated", 1500)



# ----------------------------
# File operations (copy/move/extract) with progress + cancel
# ----------------------------
    def closeEvent(self, event):
        # persist settings + session
        try:
            self.settings["preview_enabled"] = bool(self._preview_enabled)
            self.settings["show_hidden"] = bool(self._show_hidden)
            self.settings["view_mode"] = str(self._view_mode)
            self.settings["icon_size"] = int(self._icon_size)
            self.settings["restore_session"] = bool(self._restore_session)
            save_settings(self.settings)
        except Exception:
            pass

        try:
            tabs = []
            for i in range(self.tabs.count()):
                w = self.tabs.widget(i)
                if w is None:
                    continue
                tabs.append({"path": w.current_token(), "pinned": self._is_tab_pinned(i)})
            save_session({"tabs": tabs, "current_index": int(self.tabs.currentIndex())})
        except Exception:
            pass

        super().closeEvent(event)



class FileOpWorker(QThread):
    progress = Signal(int, str)       # percent, message
    finished_ok = Signal(bool, str)   # ok, message

    def __init__(self, plan: list[tuple[str, str]], move: bool = False, parent=None):
        super().__init__(parent)
        self.plan = plan
        self.move = move
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def _copy_file(self, src_path: str, dst_path: str, bytes_done: list[int], total_bytes: int):
        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        with open(src_path, "rb") as fsrc, open(dst_path, "wb") as fdst:
            while True:
                if self._cancel:
                    raise RuntimeError("Cancelled")
                chunk = fsrc.read(1024 * 1024)
                if not chunk:
                    break
                fdst.write(chunk)
                bytes_done[0] += len(chunk)
                if total_bytes > 0:
                    pct = int((bytes_done[0] / total_bytes) * 100)
                    self.progress.emit(min(100, max(0, pct)), os.path.basename(src_path))
        try:
            shutil.copystat(src_path, dst_path, follow_symlinks=True)
        except Exception:
            pass

    def run(self):
        try:
            total_bytes = 0
            for s, _d in self.plan:
                try:
                    total_bytes += os.path.getsize(s)
                except Exception:
                    pass
            bytes_done = [0]

            if not self.plan:
                self.progress.emit(100, "")
                self.finished_ok.emit(True, "Nothing to do.")
                return

            for i, (s, d) in enumerate(self.plan, 1):
                if self._cancel:
                    raise RuntimeError("Cancelled")
                # keep UI alive even if total_bytes is unknown
                self.progress.emit(int(((i - 1) / len(self.plan)) * 100), os.path.basename(s))
                self._copy_file(s, d, bytes_done, total_bytes)

            self.progress.emit(100, "Done")

            if self.move:
                # delete source files after successful copy
                for s, _d in self.plan:
                    try:
                        os.remove(s)
                    except Exception:
                        pass

            self.finished_ok.emit(True, "Completed.")
        except Exception as e:
            self.finished_ok.emit(False, str(e))


class FileOpProgressDialog(QDialog):
    def __init__(self, parent, title: str):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(460)
        self.worker = None

        lay = QVBoxLayout(self)
        self.lbl = QLabel("Working...")
        lay.addWidget(self.lbl)

        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        lay.addWidget(self.bar)

        btns = QDialogButtonBox()
        self.btn_cancel = btns.addButton("Cancel", QDialogButtonBox.RejectRole)
        self.btn_cancel.clicked.connect(self._on_cancel)
        lay.addWidget(btns)

    def start_worker(self, worker: FileOpWorker):
        self.worker = worker
        worker.progress.connect(self._on_progress)
        worker.finished_ok.connect(self._on_done)
        worker.start()

    def _on_cancel(self):
        if self.worker is not None:
            self.worker.cancel()
        self.btn_cancel.setEnabled(False)
        self.lbl.setText("Cancelling...")

    def _on_progress(self, pct: int, msg: str):
        self.bar.setValue(int(pct))
        if msg:
            self.lbl.setText(f"Working: {msg}")
        else:
            self.lbl.setText("Working...")

    def _on_done(self, ok: bool, msg: str):
        if ok:
            self.bar.setValue(100)
        self.btn_cancel.setEnabled(True)
        self.worker = None
        if not ok and msg and msg != "Cancelled":
            QMessageBox.warning(self, "Operation failed", msg)
        self.accept()


# ----------------------------
# ZIP browser (view + extract)
# ----------------------------
class ZipBrowserDialog(QDialog):
    def __init__(self, parent, zip_path: str):
        super().__init__(parent)
        self.zip_path = zip_path
        self.setWindowTitle(f"Archive: {os.path.basename(zip_path)}")
        self.setMinimumSize(700, 420)

        lay = QVBoxLayout(self)

        self.list = QTreeWidget()
        self.list.setHeaderLabels(["Name", "Size", "Modified"])
        self.list.header().setSectionResizeMode(0, QHeaderView.Stretch)
        for c in (1, 2):
            self.list.header().setSectionResizeMode(c, QHeaderView.ResizeToContents)
        lay.addWidget(self.list, 1)

        btns = QDialogButtonBox()
        self.btn_extract_sel = btns.addButton("Extract selected...", QDialogButtonBox.ActionRole)
        self.btn_extract_all = btns.addButton("Extract all...", QDialogButtonBox.ActionRole)
        self.btn_close = btns.addButton(QDialogButtonBox.Close)
        self.btn_close.clicked.connect(self.reject)
        self.btn_extract_sel.clicked.connect(self.extract_selected)
        self.btn_extract_all.clicked.connect(self.extract_all)
        lay.addWidget(btns)

        self._populate()

    def _populate(self):
        self.list.clear()
        try:
            with zipfile.ZipFile(self.zip_path, "r") as z:
                for info in z.infolist():
                    if info.filename.endswith("/"):
                        continue
                    name = info.filename
                    size = human_size(info.file_size)
                    try:
                        dt = datetime(*info.date_time).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        dt = ""
                    it = QTreeWidgetItem([name, size, dt])
                    it.setData(0, Qt.UserRole, info.filename)
                    self.list.addTopLevelItem(it)
        except Exception as e:
            QMessageBox.warning(self, "ZIP error", str(e))

    def extract_all(self):
        self._extract(None)

    def extract_selected(self):
        items = self.list.selectedItems()
        if not items:
            return
        names = [it.data(0, Qt.UserRole) for it in items if it.data(0, Qt.UserRole)]
        self._extract(names)

    def _extract(self, members: list[str] | None):
        out_dir = QFileDialog.getExistingDirectory(self, "Extract to...")
        if not out_dir:
            return
        out_dir = os.path.abspath(out_dir)
        try:
            with zipfile.ZipFile(self.zip_path, "r") as z:
                if members is None:
                    z.extractall(out_dir)
                else:
                    for m in members:
                        z.extract(m, out_dir)
            QMessageBox.information(self, "Extract", "Extraction completed.")
        except Exception as e:
            QMessageBox.warning(self, "Extract failed", str(e))



def main():
    app = QApplication(sys.argv)

    start_path = None
    if len(sys.argv) > 1:
        start_path = sys.argv[1]

        # If Windows passes a shell item (e.g. "::{GUID}"), forward to Explorer
        try:
            s = str(start_path)
            if s.startswith("::") or s.lower().startswith("shell:"):
                subprocess.Popen(["explorer.exe", s], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                start_path = None
        except Exception:
            pass

    w = MainWindow(start_path=start_path)
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
