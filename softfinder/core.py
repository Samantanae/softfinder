"""
SoftFinder - complete inventory of installed software (Windows) with real size and location.

Combined sources:
  1. Registry (Uninstall keys: HKLM 64/32-bit, HKCU, loaded user profiles)
  2. Microsoft Store / MSIX applications (Get-AppxPackage)
  3. Windows services (executables outside system folders)
  4. Registry "App Paths" keys
  5. Start menu shortcuts
  6. Disk scan: folders containing .exe files that are NOT registered
     (portable software, games, Steam/Epic, tools copied by hand, etc.)

The size is computed by actually walking the files (not the registry
"EstimatedSize" value, which is often wrong or missing).

General flow (see main()):
  1. Collect "known" software from the first sources.
  2. Merge duplicates: two entries with the same folder = a single software.
  3. Detect "invisible" software: folders containing .exe files that are not
     attached to any known entry, plus leftovers without executables.
  4. Compute the real size of each folder (in parallel).
  5. Print results grouped by drive + export to CSV (';' separator) and JSON.

Requirements: Windows, Python 3.8+, no external dependency. PowerShell is
used for Store applications and shortcuts.

Limits: without administrator rights, some folders/profiles are unreadable.
Software with an unknown location keeps the registry size (marked "~").

Usage (preferably as administrator):
    python softfinder.py
    python softfinder.py --csv inventory.csv --json inventory.json
    python softfinder.py --deep          # go one level deeper in container folders (e.g. D:\\Games\\...)
    python softfinder.py --workers 16    # more threads for size computation
"""
import argparse
import csv
import ctypes
import json
import os
import shutil
import string
import struct
import threading
import subprocess
import sys
try:
    import winreg
except ImportError:  # not on Windows: the module stays importable, scan() refuses to run
    winreg = None
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Windows attribute of symlinks/junctions: they are not followed, to avoid
# counting the same files twice or looping forever.
REPARSE = 0x400
# Folders at a drive root that never contain user software.
ROOT_EXCLUDES = {
    "windows", "$recycle.bin", "system volume information", "recovery",
    "$windows.~bt", "$windows.~ws", "config.msi", "documents and settings",
    "perflogs", "msocache", "$winreagent", "windows.old", "users", "found.000",
}
# Program Files/ProgramData folders never reported as "leftovers" (system/shared data).
LEFTOVER_EXCLUDES = {"microsoft", "microsoft shared", "common files", "package cache", "windowsapps",
                     "uninstall information", "modifiablewindowsapps", "windows", "ssh", "temp"}
# AppData / profile-root subfolders that only hold caches.
APPDATA_EXCLUDES = {"microsoft", "temp", "packages", "cache", "crashdumps",
                    "d3dscache", "history", "comms", "connecteddevicesplatform"}
# Windows folder(s): executables there (e.g. system services) are not third-party software.
SYSTEM_FOLDERS = tuple(
    p.lower() for p in (os.environ.get("WINDIR", r"C:\Windows"),)
)


# ------------------------------------------------------------------- utilities
class Progress:
    """Console progress bar (no dependency), thread-safe. Set Progress.enabled = False to silence it."""

    enabled = True

    def __init__(self, title, total):
        """title: displayed label; total: expected number of steps."""
        self.title, self.total, self.n, self.info = title, max(total, 1), 0, ""
        self.lock = threading.Lock()
        self.draw()

    def draw(self):
        """Redraw the line (\\r = back to line start, no line break)."""
        if not Progress.enabled:
            return
        w = 30
        fill = int(w * self.n / self.total)
        cols = shutil.get_terminal_size((100, 20)).columns
        txt = f"\r{self.title:<22} [{'#' * fill}{'.' * (w - fill)}] {self.n}/{self.total} " \
              f"{100 * self.n // self.total:3d}%  {self.info}"
        sys.stderr.write(txt[: cols - 1].ljust(cols - 1))
        sys.stderr.flush()

    def step(self, info="", inc=1):
        """Advance by `inc` steps (0 = only change the text); locked because called from several threads."""
        with self.lock:
            self.n += inc
            self.info = info
            self.draw()

    def close(self):
        """Force 100% and move to the next line."""
        with self.lock:
            self.n, self.info = self.total, "done"
            self.draw()
            if Progress.enabled:
                sys.stderr.write("\n")


def norm(p):
    """Normalize a path (lowercase, no trailing '\\') to compare Windows paths."""
    return os.path.normpath(p).rstrip("\\/").lower() if p else ""


def clean_path(raw):
    """Extract a file/folder path from a registry value."""
    # E.g. '"C:\\App\\x.exe" /uninstall' -> 'C:\\App\\x.exe' ; 'C:\\App\\x.exe,0' -> 'C:\\App\\x.exe'
    if not raw:
        return ""
    raw = os.path.expandvars(raw.strip())
    if raw.startswith('"'):
        raw = raw[1:].split('"')[0]
    else:
        # Without quotes: cut after the first known extension to drop the arguments.
        low = raw.lower()
        for ext in (".exe", ".ico", ".dll"):
            i = low.find(ext)
            if i != -1:
                raw = raw[: i + len(ext)]
                break
    raw = raw.split(",")[0].strip().strip('"')
    return raw if len(raw) > 2 and raw[1] == ":" else ""


def folder_of(path):
    """Return the folder of a path (the path itself if it is already a folder)."""
    if not path:
        return ""
    return path if os.path.isdir(path) else os.path.dirname(path)


def dir_size(root):
    """Real size (bytes) and file count; ignores links/junctions, de-duplicates hard links."""
    total = count = 0
    seen = set()  # (device, inode) of hard-linked files already counted
    stack = [root]  # iterative walk (no recursion: avoids depth limits)
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                        if getattr(st, "st_file_attributes", 0) & REPARSE:
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            if st.st_nlink > 1:
                                key = (st.st_dev, st.st_ino)
                                if key in seen:
                                    continue
                                seen.add(key)
                            total += st.st_size
                            count += 1
                    except OSError:
                        pass
        except OSError:
            pass
    return total, count


def has_exe(root, max_depth=3):
    """True if `root` contains an .exe up to `max_depth` levels (criterion for "this is software")."""
    stack = [(root, 0)]
    while stack:
        d, lvl = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_file(follow_symlinks=False) and e.name.lower().endswith(".exe"):
                            return True
                        if lvl < max_depth and e.is_dir(follow_symlinks=False):
                            stack.append((e.path, lvl + 1))
                    except OSError:
                        pass
        except OSError:
            pass
    return False


def exe_description(folder):
    """Description ("FileDescription" field) read from the metadata of an .exe in the folder.

    The .exe files at the root of the folder are tried first; the first one with
    a usable description is kept. Returns "" if nothing is found.
    """
    try:
        exes = [e.path for e in os.scandir(folder) if e.is_file() and e.name.lower().endswith(".exe")]
    except OSError:
        return ""
    # Uninstallers/updaters are avoided: they are not representative of the software.
    exes.sort(key=lambda p: (any(w in os.path.basename(p).lower() for w in ("unins", "update", "setup", "crash")),
                             os.path.basename(p).lower()))
    for path in exes[:5]:
        d = file_description(path)
        if d:
            return d
    return ""


def file_description(path):
    """Read FileDescription (or ProductName) of an executable through the Windows version.dll API."""
    try:
        ver = ctypes.windll.version
        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return ""
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return ""
        ptr, ln = ctypes.c_void_p(), ctypes.c_uint()
        # Language/code page table, needed to build the path of the value
        if not ver.VerQueryValueW(buf, "\\VarFileInfo\\Translation", ctypes.byref(ptr), ctypes.byref(ln)) or not ln.value:
            return ""
        lang, cp = struct.unpack("<HH", ctypes.string_at(ptr, 4))
        for field in ("FileDescription", "ProductName"):
            sub = f"\\StringFileInfo\\{lang:04x}{cp:04x}\\{field}"
            if ver.VerQueryValueW(buf, sub, ctypes.byref(ptr), ctypes.byref(ln)) and ln.value:
                txt = ctypes.wstring_at(ptr.value, ln.value).strip("\x00 ").strip()
                if txt:
                    return txt
    except Exception:
        pass
    return ""


def short(txt, n=120):
    """Clean a text (single line) and truncate it to keep it short."""
    txt = " ".join(str(txt or "").split())
    if txt.startswith("@"):  # unresolved resource reference (e.g. @%SystemRoot%\\...)
        return ""
    return txt if len(txt) <= n else txt[: n - 1] + "…"


# Folders (outside C:\Windows) that are part of Windows itself
WINDOWS_FOLDERS = ("windows defender", "windows nt", "windows security", "windowspowershell",
                   "windows portable devices", "microsoft update health tools", "windows defender advanced threat protection")


def is_windows(e):
    """True if the component is REQUIRED for Windows to work (not just a Microsoft app).

    Criteria (optional apps such as Xbox, Photos, Paint, Edge are excluded):
      - system folder (C:\\Windows, ...) or system component (Defender, PowerShell, ...);
      - publisher "Microsoft Windows" in the registry;
      - Store package flagged NonRemovable by Windows (Shell, Start menu, Search, ...).
    """
    pub = (e.get("publisher") or "").lower()
    loc = norm(e.get("location", ""))
    if e.get("system_appx") or "microsoft windows" in pub:
        return True
    if loc.startswith(SYSTEM_FOLDERS):
        return True
    return any(f"\\{d}" in loc for d in WINDOWS_FOLDERS)


def windows_core_entries():
    """Entries for the core Windows folders (C:\\Windows, Defender, ...) which have no uninstaller."""
    cand = [os.environ.get("WINDIR", r"C:\Windows")]
    for k in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData"):
        base = os.environ.get(k)
        if base:
            cand += [os.path.join(base, d) for d in ("Windows Defender", "Windows NT", "Windows Security",
                                                      "WindowsPowerShell", "Windows Portable Devices")]
            cand.append(os.path.join(base, "Microsoft", "Windows Defender"))
    items, seen = [], set()
    for p in cand:
        if os.path.isdir(p) and norm(p) not in seen:
            seen.add(norm(p))
            name = "Windows (operating system)" if norm(p) == norm(cand[0]) else os.path.basename(p)
            items.append({"name": name, "publisher": "Microsoft Corporation", "version": "", "location": p,
                          "registry_size": 0, "source": "System"})
    return items


def has_files(root, max_depth=2):
    """True if `root` contains at least one file (up to `max_depth` levels)."""
    stack = [(root, 0)]
    while stack:
        d, lvl = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_file(follow_symlinks=False):
                            return True
                        if lvl < max_depth and e.is_dir(follow_symlinks=False):
                            stack.append((e.path, lvl + 1))
                    except OSError:
                        pass
        except OSError:
            pass
    return False


def human(n):
    """Format bytes into a readable unit (B, KB, MB, GB, TB)."""
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.2f} {u}"
        n /= 1024


def drives():
    """List the existing drives (C:\\, D:\\, ...)."""
    return [f"{c}:\\" for c in string.ascii_uppercase if os.path.exists(f"{c}:\\")]


# --------------------------------------------------------------------- sources
def reg_values(key):
    """Read all values of an open registry key and return them as a dict."""
    out = {}
    i = 0
    while True:
        try:
            n, v, _ = winreg.EnumValue(key, i)
            out[n] = v
            i += 1
        except OSError:
            return out


def from_registry():
    """Source 1: Uninstall keys (what "Installed apps" shows).

    Each subkey = one software. The location comes from InstallLocation, or
    otherwise is deduced from DisplayIcon / UninstallString (often filled in).
    """
    items = []
    roots_patch = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, roots_patch, winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, roots_patch, winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, roots_patch, winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_CURRENT_USER, roots_patch, winreg.KEY_WOW64_32KEY),
    ]
    # other loaded profiles (mostly require admin)
    try:
        i = 0
        while True:
            sid = winreg.EnumKey(winreg.HKEY_USERS, i)
            i += 1
            if sid.startswith("S-1-5-21") and not sid.endswith("_Classes"):
                roots.append((winreg.HKEY_USERS, sid + "\\"+ roots_patch, 0))
    except OSError: # likely no more user profiles to enumerate
        pass
    for hive, path, flag in roots:
        try:
            base = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | flag)
        except OSError:  # likely cannot open this registry key
            continue
        j = 0
        while True:
            try:
                sub = winreg.EnumKey(base, j)
                j += 1
            except OSError:  # likely no more subkeys in this uninstall key
                break
            try:
                v = reg_values(winreg.OpenKey(base, sub))
            except OSError:  # likely cannot open this subkey
                continue
            name = v.get("DisplayName")
            if not name or v.get("SystemComponent") == 1 and not v.get("InstallLocation"):
                if not name:
                    continue
            loc, declared = resolve_location(sub, v)
            items.append({
                "name": name, "publisher": v.get("Publisher", ""), "version": v.get("DisplayVersion", ""),
                "location": loc, "declared_location": declared,
                "registry_size": int(v.get("EstimatedSize", 0) or 0) * 1024
                if isinstance(v.get("EstimatedSize", 0), int) else 0,
                "description": short(v.get("Comments", "")),
                "source": "Registry",
            })
    return items


# Registry values that may reveal the install folder (in order of reliability)
LOCATION_KEYS = ("InstallLocation", "InstallDir", "InstallPath", "Inno Setup: App Path", "Path",
                 "DisplayIcon", "UninstallString", "QuietUninstallString", "ModifyPath")
# Generic folders that do not designate the software's own folder
GENERIC_FOLDERS = ("\\installer", "\\package cache", "\\common files", "\\temp", "\\downloaded installations")


def msi_install_location(guid):
    """Ask Windows Installer for the folder of an MSI product (uninstall key = {GUID})."""
    if not (guid.startswith("{") and guid.endswith("}")):
        return ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = ctypes.c_uint(1024)
        if ctypes.windll.msi.MsiGetProductInfoW(guid, "InstallLocation", buf, ctypes.byref(size)) == 0:
            return buf.value
    except Exception:  # likely failed to query MSI for this product
        pass
    return ""


def resolve_location(sub, v):
    """Look for the folder of a registry software.

    Returns (existing_location, declared_but_missing_location).
    All the values of LOCATION_KEYS are tried, then the MSI API. The first
    folder that really exists wins; otherwise the first declared path is kept
    so that we can say "declared here but files missing".
    """
    candidates = [msi_install_location(sub)] if sub.startswith("{") else []
    candidates += [str(v.get(k, "")) for k in LOCATION_KEYS]
    declared = ""
    for raw in candidates:
        p = clean_path(raw)
        if not p:
            continue
        p = folder_of(p) if not os.path.isdir(p) else p
        n = norm(p)
        if n.startswith(SYSTEM_FOLDERS) or any(g in n + "\\" for g in GENERIC_FOLDERS):
            continue
        if os.path.isdir(p) and os.path.dirname(n) != os.path.splitdrive(n)[0]:
            return p, ""
        declared = declared or p
    return "", declared


# Folder names too common to identify a software (avoids false matches)
GENERIC_WORDS = {"windows", "microsoft", "common", "shared", "commonfiles", "tools", "runtime", "update",
                 "installer", "framework", "data", "microsoftsdks", "package", "packages", "programs",
                 "windowsapps", "reference", "assemblies", "netframework"}


def alnum(s):
    """Lowercase letters and digits only (to compare software and folder names)."""
    return "".join(c for c in str(s).lower() if c.isalnum())


def guess_location(name, publisher, program_folders):
    """Guess the folder of a software whose registry entry gives no location.

    Looks, in Program Files/ProgramData/AppData..., for a folder (or Publisher\\Product)
    whose name matches the software name. Returns "" if there is no clear candidate.
    """
    target = alnum(name)
    pub = alnum(str(publisher).split(",")[0].replace("Inc.", "").replace("Corporation", ""))
    if len(target) < 3:
        return ""

    # The product name must START with the folder name (with or without the publisher prefix)
    targets = {target, alnum(" ".join(str(name).split()[1:]))} - {""}

    def match(folder):
        d = alnum(folder)
        if len(d) < 6 or d in GENERIC_WORDS:
            return False
        return any(c == d or c.startswith(d) or (len(c) >= 5 and d.startswith(c)) for c in targets)

    for root in program_folders:
        try:
            for e in os.scandir(root):
                if not e.is_dir(follow_symlinks=False):
                    continue
                d = alnum(e.name)
                # Publisher folder (Google, Microsoft, NVIDIA...): never kept as is because
                # it is shared between products; only the product inside is searched.
                if pub and len(d) >= 3 and (d in pub or pub in d):
                    for s in os.scandir(e.path):
                        if s.is_dir(follow_symlinks=False) and match(s.name):
                            return s.path
                elif match(e.name):
                    return e.path
        except OSError:
            continue
    return ""


def from_appx():
    """Source 2: Store/MSIX applications, absent from the Uninstall keys (via PowerShell)."""
    # NonRemovable: packages that Windows refuses to uninstall (essential to the system)
    # -AllUsers requires admin rights; without them, fall back to the current user.
    cmd = ("$p = try { Get-AppxPackage -AllUsers -ErrorAction Stop } catch { Get-AppxPackage }; "
           "$p | Where-Object {$_.InstallLocation} | "
           "Select-Object Name,Publisher,Version,InstallLocation,SignatureKind,NonRemovable | "
           "ConvertTo-Json -Compress")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=120)
        data = json.loads(r.stdout) if r.stdout.strip() else []
    except Exception:
        return []
    if isinstance(data, dict):
        data = [data]
    return [{"name": d["Name"], "publisher": d.get("Publisher", ""), "version": d.get("Version", ""),
             "location": d["InstallLocation"], "registry_size": 0, "source": "Store/MSIX",
             "system_appx": bool(d.get("NonRemovable"))}
            for d in data]


def from_services():
    """Source 3: services whose executable is outside Windows (reveals software without an uninstaller)."""
    items = []
    try:
        base = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
    except OSError:
        return items
    i = 0
    while True:
        try:
            sub = winreg.EnumKey(base, i)
            i += 1
        except OSError:
            break
        try:
            v = reg_values(winreg.OpenKey(base, sub))
        except OSError:
            continue
        folder = folder_of(clean_path(str(v.get("ImagePath", ""))))
        if folder and not norm(folder).startswith(SYSTEM_FOLDERS) and os.path.isdir(folder) \
                and "driverstore" not in norm(folder):
            items.append({"name": v.get("DisplayName", sub) if not str(v.get("DisplayName", "")).startswith("@") else sub,
                          "publisher": "", "version": "", "location": folder, "registry_size": 0,
                          "description": short(v.get("Description", "")),
                          "source": "Service"})
    return items


def from_app_paths():
    """Source 4: "App Paths" keys, where programs declare their .exe (Run command)."""
    items = []
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            base = winreg.OpenKey(hive, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths")
        except OSError:
            continue
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(base, i)
                i += 1
            except OSError:
                break
            try:
                v = reg_values(winreg.OpenKey(base, sub))
            except OSError:
                continue
            folder = folder_of(clean_path(str(v.get("", ""))))
            if folder and not norm(folder).startswith(SYSTEM_FOLDERS):
                items.append({"name": os.path.splitext(sub)[0], "publisher": "", "version": "",
                              "location": folder, "registry_size": 0, "source": "App Paths"})
    return items


def from_shortcuts():
    """Source 5: targets of the Start menu shortcuts (current user + all users)."""
    ps = (
        "$s=New-Object -ComObject WScript.Shell;"
        "$d=@($env:ProgramData+'\\Microsoft\\Windows\\Start Menu\\Programs',$env:APPDATA+'\\Microsoft\\Windows\\Start Menu\\Programs');"
        "Get-ChildItem $d -Recurse -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {"
        "$t=$s.CreateShortcut($_.FullName).TargetPath; if($t){[pscustomobject]@{N=$_.BaseName;T=$t}}} | ConvertTo-Json -Compress"
    )
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=180)
        data = json.loads(r.stdout) if r.stdout.strip() else []
    except Exception:
        return []
    if isinstance(data, dict):
        data = [data]
    items = []
    for d in data:
        folder = folder_of(d["T"])
        if folder and os.path.isdir(folder) and not norm(folder).startswith(SYSTEM_FOLDERS):
            items.append({"name": d["N"], "publisher": "", "version": "", "location": folder,
                          "registry_size": 0, "source": "Shortcut"})
    return items


# ------------------------------------------------- detection of unregistered software
def candidate_roots(deep):
    """Folders to explore to find undeclared software.

    Returns tuples (path, filter_appdata, look_for_leftovers). The 2nd boolean
    skips cache subfolders (APPDATA_EXCLUDES); the 3rd enables the detection
    of folders without executables (Program Files, ProgramData only).
    """
    roots = []
    env = os.environ
    for k in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData"):
        if env.get(k):
            roots.append((env[k], False, True))
    local = env.get("LOCALAPPDATA", "")
    if local:
        roots.append((os.path.join(local, "Programs"), False, True))
        roots.append((local, True, False))
    if env.get("APPDATA"):
        roots.append((env["APPDATA"], True, False))
    users = Path(env.get("SystemDrive", "C:") + "\\Users")
    for u in (users.iterdir() if users.exists() else []):
        for sub, flt, res in ((r"AppData\Local\Programs", False, True), (r"AppData\Local", True, False),
                              (r"AppData\Roaming", True, False), (r"AppData\LocalLow", True, False),
                              ("", True, False)):  # "" = profile root (.vscode, .cargo, .nvm, ...)
            roots.append((str(u / sub) if sub else str(u), flt, res))
        # Places where portable software is often dropped or installed per user
        for sub in ("Desktop", "Downloads", "Documents", "Games", "scoop\\apps", "OneDrive\\Desktop",
                    "OneDrive\\Documents"):
            roots.append((str(u / sub), False, False))
    roots.append((os.path.join(env.get("PUBLIC", env.get("SystemDrive", "C:") + "\\Users\\Public"), "Desktop"),
                  False, False))
    # Package managers installing outside Program Files
    roots.append((os.path.join(env.get("ProgramData", r"C:\ProgramData"), "chocolatey", "lib"), False, False))
    roots.append((os.path.join(env.get("ProgramData", r"C:\ProgramData"), "scoop", "apps"), False, False))
    for d in drives():
        try:
            for e in os.scandir(d):
                if e.is_dir(follow_symlinks=False) and e.name.lower() not in ROOT_EXCLUDES:
                    roots.append((e.path, False, False))
        except OSError:
            pass
    # De-duplication + removal of non-existent paths
    seen, out = set(), []
    for r, f, res in roots:
        n = norm(r)
        if n not in seen and os.path.isdir(r):
            seen.add(n)
            out.append((r, f, res))
    return out


def find_unregistered(known, deep):
    """Find software present on disk but without an uninstall entry.

    `known`: paths already identified. Returns {path: kind} where kind is:
      - "exe"      : folder containing executables (software/portable/game without uninstaller);
      - "leftover" : Program Files/ProgramData/... folder with files but no executable
                     (remains of an uninstalled software, or software files whose uninstaller is gone).

    A "publisher" folder that contains known software (e.g. Adobe\\Reader) is not skipped:
    its other subfolders are inspected, as they may be orphan software.
    """
    known_n = [norm(k) for k in known if k]

    def inside_known(n):
        return any(n == k or n.startswith(k + "\\") for k in known_n)

    def contains_known(n):
        return any(k.startswith(n + "\\") for k in known_n)

    def subdirs(path):
        try:
            return [e.path for e in os.scandir(path) if e.is_dir(follow_symlinks=False)]
        except OSError:
            return []

    found = {}

    def examine(path, leftovers, level, is_drive_root):
        n = norm(path)
        if n.startswith(SYSTEM_FOLDERS) or inside_known(n):
            return
        if contains_known(n):
            for s in subdirs(path):
                examine(s, leftovers, level + 1, False)
            return
        if has_exe(path, 4):
            found[path] = "exe"
        elif level == 0 and (is_drive_root or deep):
            # container such as "D:\Games": one level deeper
            for s in subdirs(path):
                examine(s, leftovers, level + 1, False)
        elif leftovers and level == 0 and os.path.basename(n) not in LEFTOVER_EXCLUDES and has_files(path):
            found[path] = "leftover"

    roots = candidate_roots(deep)
    bar = Progress("Scanning drives", len(roots))
    for root, filt, leftovers in roots:
        bar.step(root[-45:])
        drive_root = os.path.dirname(norm(root)) == os.path.splitdrive(norm(root))[0]
        for s in subdirs(root):
            if filt and os.path.basename(norm(s)) in APPDATA_EXCLUDES:
                continue
            examine(s, leftovers, 0, drive_root)
    bar.close()

    # Folders listed in PATH that hold executables (command-line tools installed by hand)
    for p in os.environ.get("PATH", "").split(os.pathsep):
        n = norm(p.strip().strip('"'))
        if (n and os.path.isdir(n) and not n.startswith(SYSTEM_FOLDERS) and not inside_known(n)
                and not any(n == norm(f) or n.startswith(norm(f) + "\\") for f in found) and has_exe(n, 0)):
            found[n] = "exe"
    return dict(sorted(found.items(), key=lambda kv: kv[0].lower()))


# ------------------------------------------------------------------- public API
# Columns (in order) of the CSV/JSON exports
COLUMNS = ["drive", "name", "description", "windows", "status", "publisher", "version", "size", "size_human",
           "files", "approx_size", "source", "location", "declared_location"]


def is_admin():
    """True if the process has administrator rights (False if unknown or not on Windows)."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def scan(deep=False, workers=8, progress=True, log=None):
    """Run the whole inventory and return a list of dicts (one per software), sorted by drive then size.

    deep:     go one extra level deeper in container folders.
    workers:  threads used to compute sizes.
    progress: show the progress bars on stderr.
    log:      optional callable receiving status messages (e.g. `print`).
    Each dict has the keys listed in COLUMNS ("size" is in bytes, "size_human" is the same value through human()).
    """
    if os.name != "nt" or winreg is None:
        raise OSError("SoftFinder only works on Windows.")
    log = log or (lambda msg: None)
    previous, Progress.enabled = Progress.enabled, progress
    try:
        return _scan(deep, workers, log)
    finally:
        Progress.enabled = previous


def _scan(deep, workers, log):
    """Implementation of scan() (progress/log already configured)."""
    log("Collecting sources (registry, Store, services, shortcuts, system)...")
    items = []
    fns = (from_registry, from_appx, from_services, from_app_paths, from_shortcuts, windows_core_entries)
    bar = Progress("Sources", len(fns))
    for fn in fns:
        bar.step(f"{fn.__name__}...", inc=0)
        r = fn()
        items += r
        bar.step(f"{fn.__name__}: {len(r)} entries")
    bar.close()

    # merge by location: keep the best name, accumulate the sources
    merged = {}
    no_loc = []
    for it in items:
        if it["location"]:
            k = norm(it["location"])
            m = merged.get(k)
            if not m:
                merged[k] = dict(it, sources={it["source"]})
            else:
                m["sources"].add(it["source"])
                if it["source"] == "Registry" and m["source"] != "Registry":
                    for f in ("name", "publisher", "version"):
                        m[f] = it[f] or m[f]
                    m["source"] = "Registry"
                m["registry_size"] = m["registry_size"] or it["registry_size"]
                m["system_appx"] = m.get("system_appx") or it.get("system_appx", False)
                m["description"] = m.get("description") or it.get("description", "")
        elif it["source"] == "Registry":
            no_loc.append(dict(it, sources={"Registry"}))

    # Software identified but whose folder was not found: try to deduce it from the name
    program_dirs = [r for r, _, res in candidate_roots(False) if res]
    for e in no_loc:
        g = guess_location(e["name"], e["publisher"], program_dirs)
        if g:
            e["location"], e["deduced"] = g, True
    deduced = [e for e in no_loc if e["location"]]
    no_loc = [e for e in no_loc if not e["location"]]
    for e in deduced:
        k = norm(e["location"])
        if k in merged:
            merged[k]["sources"].add("Registry")
        else:
            merged[k] = e

    log("Looking for software without an uninstaller (scanning drives)...")
    known = list(merged.keys())
    labels = {"exe": "Unregistered (no uninstaller)", "leftover": "Leftover without executable"}
    for p, kind in find_unregistered(known, deep).items():
        merged[norm(p)] = {"name": os.path.basename(p), "publisher": "", "version": "", "location": p,
                           "registry_size": 0, "source": labels[kind], "sources": {labels[kind]}}

    entries = list(merged.values()) + no_loc
    bar = Progress("Computing sizes", len(entries))

    def work(e):
        """Compute size, status, drive, description and Windows flag of one entry (runs in a thread)."""
        if e["location"]:
            e["size"], e["files"] = dir_size(e["location"])
            e["approx_size"] = False
            if e["files"] == 0:
                e["status"] = "Empty folder or access denied"
            else:
                e["status"] = "Location deduced from name" if e.get("deduced") else "OK"
        else:
            e["size"], e["files"], e["approx_size"] = e["registry_size"], 0, True
            e["status"] = ("Files not found (declared folder missing)" if e.get("declared_location")
                           else "Files not found (unknown location)")
            e["location"] = ""
        e["drive"] = os.path.splitdrive(e["location"])[0].upper() + "\\" if e["location"] else "?"
        e["source"] = ", ".join(sorted(e["sources"]))
        # Description: the declared one if any, otherwise the .exe metadata
        if not e.get("description") and e["location"]:
            e["description"] = short(exe_description(e["location"]))
        e["description"] = e.get("description", "")
        e["windows"] = "Yes" if is_windows(e) else "No"
        e["size_human"] = human(e["size"])
        bar.step(f"{e['name'][:30]} ({human(e['size'])})")
        return e

    with ThreadPoolExecutor(workers) as ex:
        entries = list(ex.map(work, entries))
    bar.close()

    # Display: by drive, biggest first; the "?" group (no location) comes last
    entries.sort(key=lambda e: (e["drive"], -e["size"]))
    for e in entries:
        e.setdefault("declared_location", "")
    return entries
