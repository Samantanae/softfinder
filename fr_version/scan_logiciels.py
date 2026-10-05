# VERSION IN FRENCH. FOR THE ENGLISH VERSION, SEE scan_logiciels.py
"""
Inventaire complet des logiciels installés (Windows) avec taille réelle et emplacement.

Sources combinées :
  1. Registre (Uninstall HKLM 64/32 bits, HKCU, profils utilisateurs chargés)
  2. Applications Microsoft Store / MSIX (Get-AppxPackage)
  3. Services Windows (exécutables hors dossiers système)
  4. Clés "App Paths" du registre
  5. Raccourcis du menu Démarrer
  6. Analyse disque : dossiers contenant des .exe qui ne sont PAS enregistrés
     (logiciels portables, jeux, Steam/Epic, outils copiés à la main, etc.)

La taille est calculée en parcourant réellement les fichiers (et non la valeur
"EstimatedSize" du registre, souvent fausse ou absente).

Fonctionnement général (voir main()) :
  1. Collecte des logiciels "connus" depuis les 5 premières sources.
  2. Fusion des doublons : deux entrées ayant le même dossier = un seul logiciel.
  3. Détection des logiciels "invisibles" : dossiers contenant des .exe qui ne
     sont rattachés à aucune entrée connue.
  4. Calcul de la taille réelle de chaque dossier (en parallèle).
  5. Affichage groupé par lecteur + export CSV (séparateur ';') et JSON.

Prérequis : Windows, Python 3.8+, aucune dépendance externe. PowerShell est
utilisé pour les applications Store et les raccourcis.

Limites : sans droits administrateur, certains dossiers/profils sont illisibles.
Un logiciel sans emplacement connu garde la taille du registre (marquée "~").

Usage (idéalement en administrateur) :
    python scan_logiciels.py
    python scan_logiciels.py --csv inventaire.csv --json inventaire.json
    python scan_logiciels.py --deep          # descend un niveau de plus dans les dossiers conteneurs (ex: D:\Jeux\...)
    python scan_logiciels.py --workers 16    # plus de threads pour le calcul des tailles
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
import winreg
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Attribut Windows des liens symboliques/jonctions : on ne les suit pas pour
# éviter de compter deux fois les mêmes fichiers ou de boucler.
REPARSE = 0x400
# Dossiers à la racine d'un lecteur qui ne contiennent jamais de logiciels utilisateur.
EXCLUS_RACINE = {
    "windows", "$recycle.bin", "system volume information", "recovery",
    "$windows.~bt", "$windows.~ws", "config.msi", "documents and settings",
    "perflogs", "msocache", "$winreagent", "windows.old", "users", "found.000",
}
# Dossiers de Program Files/ProgramData jamais signalés comme "résidus" (données système/partagées).
EXCLUS_RESIDU = {"microsoft", "microsoft shared", "common files", "package cache", "windowsapps",
                 "uninstall information", "modifiablewindowsapps", "windows", "ssh", "temp"}
# Sous-dossiers d'AppData qui ne contiennent que des caches/données, pas des logiciels.
EXCLUS_APPDATA = {"microsoft", "temp", "packages", "cache", "crashdumps",
                  "d3dscache", "history", "comms", "connecteddevicesplatform"}
DOSSIERS_SYSTEME = tuple(
    p.lower() for p in (os.environ.get("WINDIR", r"C:\Windows"),)
)


# ----------------------------------------------------------------- utilitaires
class Progress:
    """Barre de progression console (sans dépendance), thread-safe."""

    def __init__(self, titre, total):
        """titre : libellé affiché ; total : nombre d'étapes attendues."""
        self.titre, self.total, self.n, self.info = titre, max(total, 1), 0, ""
        self.lock = threading.Lock()
        self.draw()

    def draw(self):
        """Redessine la ligne (\\r = retour en début de ligne, sans saut)."""
        w = 30
        fill = int(w * self.n / self.total)
        cols = shutil.get_terminal_size((100, 20)).columns
        txt = f"\r{self.titre:<22} [{'#' * fill}{'.' * (w - fill)}] {self.n}/{self.total} " \
              f"{100 * self.n // self.total:3d}%  {self.info}"
        sys.stderr.write(txt[: cols - 1].ljust(cols - 1))
        sys.stderr.flush()

    def step(self, info="", inc=1):
        """Avance de `inc` étapes (0 = juste changer le texte) ; verrou car appelée par plusieurs threads."""
        with self.lock:
            self.n += inc
            self.info = info
            self.draw()

    def close(self):
        """Force 100 % et passe à la ligne."""
        with self.lock:
            self.n, self.info = self.total, "terminé"
            self.draw()
            sys.stderr.write("\n")


def norm(p):
    """Normalise un chemin (minuscules, sans '\\' final) pour comparer des chemins Windows."""
    return os.path.normpath(p).rstrip("\\/").lower() if p else ""


def clean_path(raw):
    """Extrait un chemin de fichier/dossier depuis une valeur de registre."""
    # Ex: '"C:\\App\\x.exe" /uninstall' -> 'C:\\App\\x.exe' ; 'C:\\App\\x.exe,0' -> 'C:\\App\\x.exe'
    if not raw:
        return ""
    raw = os.path.expandvars(raw.strip())
    if raw.startswith('"'):
        raw = raw[1:].split('"')[0]
    else:
        # Sans guillemets : on coupe après la première extension connue pour retirer les arguments.
        low = raw.lower()
        for ext in (".exe", ".ico", ".dll"):
            i = low.find(ext)
            if i != -1:
                raw = raw[: i + len(ext)]
                break
    raw = raw.split(",")[0].strip().strip('"')
    return raw if len(raw) > 2 and raw[1] == ":" else ""


def folder_of(path):
    """Retourne le dossier d'un chemin (le chemin lui-même s'il est déjà un dossier)."""
    if not path:
        return ""
    return path if os.path.isdir(path) else os.path.dirname(path)


def dir_size(root):
    """Taille réelle (octets) et nombre de fichiers ; ignore liens/jonctions, dédoublonne hardlinks."""
    total = count = 0
    seen = set()  # (périphérique, inode) des fichiers à liens physiques déjà comptés
    stack = [root]  # parcours itératif (pas de récursion : évite les limites de profondeur)
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
    """True si `root` contient un .exe jusqu'à `max_depth` niveaux (critère de "c'est un logiciel")."""
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
    """Description (champ "FileDescription") lue dans les métadonnées d'un .exe du dossier.

    On teste d'abord les .exe à la racine du dossier ; le premier qui a une
    description exploitable est retenu. Retourne "" si rien n'est trouvé.
    """
    try:
        exes = [e.path for e in os.scandir(folder) if e.is_file() and e.name.lower().endswith(".exe")]
    except OSError:
        return ""
    # On évite les désinstallateurs/mises à jour, peu représentatifs du logiciel.
    exes.sort(key=lambda p: (any(w in os.path.basename(p).lower() for w in ("unins", "update", "setup", "crash")),
                             os.path.basename(p).lower()))
    for path in exes[:5]:
        d = file_description(path)
        if d:
            return d
    return ""


def file_description(path):
    """Lit FileDescription (ou ProductName) d'un exécutable via l'API Windows version.dll."""
    try:
        ver = ctypes.windll.version
        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return ""
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return ""
        ptr, ln = ctypes.c_void_p(), ctypes.c_uint()
        # Table langue/code page, nécessaire pour construire le chemin de la valeur
        if not ver.VerQueryValueW(buf, "\\VarFileInfo\\Translation", ctypes.byref(ptr), ctypes.byref(ln)) or not ln.value:
            return ""
        lang, cp = struct.unpack("<HH", ctypes.string_at(ptr, 4))
        for champ in ("FileDescription", "ProductName"):
            sub = f"\\StringFileInfo\\{lang:04x}{cp:04x}\\{champ}"
            if ver.VerQueryValueW(buf, sub, ctypes.byref(ptr), ctypes.byref(ln)) and ln.value:
                txt = ctypes.wstring_at(ptr.value, ln.value).strip("\x00 ").strip()
                if txt:
                    return txt
    except Exception:
        pass
    return ""


def short(txt, n=120):
    """Nettoie un texte (une seule ligne) et le tronque pour qu'il reste court."""
    txt = " ".join(str(txt or "").split())
    if txt.startswith("@"):  # référence de ressource non résolue (ex: @%SystemRoot%\\...)
        return ""
    return txt if len(txt) <= n else txt[: n - 1] + "…"


# Dossiers (hors C:\Windows) qui font partie du fonctionnement même de Windows
WINDOWS_DOSSIERS = ("windows defender", "windows nt", "windows security", "windowspowershell",
                    "windows portable devices", "microsoft update health tools", "windows defender advanced threat protection")


def is_windows(e):
    """True si le composant est NÉCESSAIRE au fonctionnement de Windows (pas une simple appli Microsoft).

    Critères (les applis facultatives comme Xbox, Photos, Paint, Edge sont exclues) :
      - dossier système (C:\\Windows, ...) ou composant du système (Defender, PowerShell, ...) ;
      - éditeur "Microsoft Windows" dans le registre ;
      - paquet Store marqué NonRemovable par Windows (Shell, Menu Démarrer, Recherche, ...).
    """
    ed = (e.get("editeur") or "").lower()
    loc = norm(e.get("emplacement", ""))
    if e.get("systeme_appx") or "microsoft windows" in ed:
        return True
    if loc.startswith(DOSSIERS_SYSTEME):
        return True
    return any(f"\\{d}" in loc for d in WINDOWS_DOSSIERS)


def windows_core_entries():
    """Entrées pour les dossiers cœur de Windows (C:\\Windows, Defender, ...) qui n'ont aucun désinstalleur."""
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
            nom = "Windows (système d'exploitation)" if norm(p) == norm(cand[0]) else os.path.basename(p)
            items.append({"nom": nom, "editeur": "Microsoft Corporation", "version": "", "emplacement": p,
                          "taille_registre": 0, "source": "Système"})
    return items


def has_files(root, max_depth=2):
    """True si `root` contient au moins un fichier (jusqu'à `max_depth` niveaux)."""
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
    """Formate des octets en unité lisible (o, Ko, Mo, Go, To)."""
    n = float(n)
    for u in ("o", "Ko", "Mo", "Go", "To"):
        if n < 1024 or u == "To":
            return f"{n:.0f} {u}" if u == "o" else f"{n:.2f} {u}"
        n /= 1024


def drives():
    """Liste les lecteurs existants (C:\\, D:\\, ...)."""
    return [f"{c}:\\" for c in string.ascii_uppercase if os.path.exists(f"{c}:\\")]


# ------------------------------------------------------------------- sources
def reg_values(key):
    """Lit toutes les valeurs d'une clé de registre ouverte et les retourne sous forme de dict."""
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
    """Source 1 : clés Uninstall (ce que montre "Applications installées").

    Chaque sous-clé = un logiciel. L'emplacement vient de InstallLocation, ou à
    défaut est déduit de DisplayIcon / UninstallString (souvent renseignés).
    """
    items = []
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY),
    ]
    # autres profils chargés (nécessite admin pour la plupart)
    try:
        i = 0
        while True:
            sid = winreg.EnumKey(winreg.HKEY_USERS, i)
            i += 1
            if sid.startswith("S-1-5-21") and not sid.endswith("_Classes"):
                roots.append((winreg.HKEY_USERS, sid + r"\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0))
    except OSError:
        pass
    for hive, path, flag in roots:
        try:
            base = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | flag)
        except OSError:
            continue
        j = 0
        while True:
            try:
                sub = winreg.EnumKey(base, j)
                j += 1
            except OSError:
                break
            try:
                v = reg_values(winreg.OpenKey(base, sub))
            except OSError:
                continue
            name = v.get("DisplayName")
            if not name or v.get("SystemComponent") == 1 and not v.get("InstallLocation"):
                if not name:
                    continue
            loc, declare = resolve_location(sub, v)
            items.append({
                "nom": name, "editeur": v.get("Publisher", ""), "version": v.get("DisplayVersion", ""),
                "emplacement": loc, "emplacement_declare": declare,
                "taille_registre": int(v.get("EstimatedSize", 0) or 0) * 1024
                if isinstance(v.get("EstimatedSize", 0), int) else 0,
                "description": short(v.get("Comments", "")),
                "source": "Registre",
            })
    return items


# Valeurs du registre pouvant révéler le dossier d'installation (par ordre de fiabilité)
CLES_EMPLACEMENT = ("InstallLocation", "InstallDir", "InstallPath", "Inno Setup: App Path", "Path",
                    "DisplayIcon", "UninstallString", "QuietUninstallString", "ModifyPath")
# Dossiers génériques qui ne désignent pas le dossier du logiciel
DOSSIERS_GENERIQUES = ("\\installer", "\\package cache", "\\common files", "\\temp", "\\downloaded installations")


def msi_install_location(guid):
    """Demande à Windows Installer le dossier d'un produit MSI (clé de désinstallation = {GUID})."""
    if not (guid.startswith("{") and guid.endswith("}")):
        return ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = ctypes.c_uint(1024)
        if ctypes.windll.msi.MsiGetProductInfoW(guid, "InstallLocation", buf, ctypes.byref(size)) == 0:
            return buf.value
    except Exception:
        pass
    return ""


def resolve_location(sub, v):
    """Cherche le dossier d'un logiciel du registre.

    Retourne (emplacement_existant, emplacement_declare_mais_absent).
    On essaie toutes les valeurs de CLES_EMPLACEMENT, puis l'API MSI. Le premier
    dossier réellement existant gagne ; sinon on garde le dernier chemin déclaré
    pour pouvoir dire "déclaré ici mais fichiers absents".
    """
    candidats = [msi_install_location(sub)] if sub.startswith("{") else []
    candidats += [str(v.get(k, "")) for k in CLES_EMPLACEMENT]
    declare = ""
    for raw in candidats:
        p = clean_path(raw)
        if not p:
            continue
        p = folder_of(p) if not os.path.isdir(p) else p
        n = norm(p)
        if n.startswith(DOSSIERS_SYSTEME) or any(g in n + "\\" for g in DOSSIERS_GENERIQUES):
            continue
        if os.path.isdir(p) and os.path.dirname(n) != os.path.splitdrive(n)[0]:
            return p, ""
        declare = declare or p
    return "", declare


# Noms de dossiers trop courants pour identifier un logiciel (évite les faux rapprochements)
MOTS_GENERIQUES = {"windows", "microsoft", "common", "shared", "commonfiles", "tools", "runtime", "update",
                   "installer", "framework", "data", "microsoftsdks", "package", "packages", "programs",
                   "windowsapps", "reference", "assemblies", "netframework"}


def alnum(s):
    """Minuscules, lettres et chiffres seulement (pour comparer des noms de logiciel et de dossier)."""
    return "".join(c for c in str(s).lower() if c.isalnum())


def guess_location(nom, editeur, dossiers_programmes):
    """Devine le dossier d'un logiciel dont le registre ne donne pas l'emplacement.

    Cherche, dans Program Files/ProgramData/AppData..., un dossier (ou Editeur\\Produit)
    dont le nom correspond au nom du logiciel. Retourne "" si aucun candidat clair.
    """
    cible = alnum(nom)
    ed = alnum(str(editeur).split(",")[0].replace("Inc.", "").replace("Corporation", ""))
    if len(cible) < 3:
        return ""

    # Le nom du produit doit COMMENCER par le nom du dossier (avec ou sans le préfixe éditeur)
    cibles = {cible, alnum(" ".join(str(nom).split()[1:]))} - {""}

    def match(dossier):
        d = alnum(dossier)
        if len(d) < 6 or d in MOTS_GENERIQUES:
            return False
        return any(c == d or c.startswith(d) or (len(c) >= 5 and d.startswith(c)) for c in cibles)

    for racine in dossiers_programmes:
        try:
            for e in os.scandir(racine):
                if not e.is_dir(follow_symlinks=False):
                    continue
                d = alnum(e.name)
                # Dossier de l'éditeur (Google, Microsoft, NVIDIA...) : jamais retenu tel quel
                # car partagé entre produits ; on cherche seulement le produit à l'intérieur.
                if ed and len(d) >= 3 and (d in ed or ed in d):
                    for s in os.scandir(e.path):
                        if s.is_dir(follow_symlinks=False) and match(s.name):
                            return s.path
                elif match(e.name):
                    return e.path
        except OSError:
            continue
    return ""


def from_appx():
    """Source 2 : applications Store/MSIX, absentes des clés Uninstall (via PowerShell)."""
    # NonRemovable : paquets que Windows refuse de désinstaller (indispensables au système)
    # -AllUsers exige les droits admin ; sans eux, repli sur l'utilisateur courant.
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
    return [{"nom": d["Name"], "editeur": d.get("Publisher", ""), "version": d.get("Version", ""),
             "emplacement": d["InstallLocation"], "taille_registre": 0, "source": "Store/MSIX",
             "systeme_appx": bool(d.get("NonRemovable"))}
            for d in data]


def from_services():
    """Source 3 : services dont l'exécutable est hors de Windows (révèle des logiciels sans désinstallateur)."""
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
        if folder and not norm(folder).startswith(DOSSIERS_SYSTEME) and os.path.isdir(folder) \
                and "driverstore" not in norm(folder):
            items.append({"nom": v.get("DisplayName", sub) if not str(v.get("DisplayName", "")).startswith("@") else sub,
                          "editeur": "", "version": "", "emplacement": folder, "taille_registre": 0,
                          "description": short(v.get("Description", "")),
                          "source": "Service"})
    return items


def from_app_paths():
    """Source 4 : clés "App Paths", où les programmes déclarent leur .exe (commande Exécuter)."""
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
            if folder and not norm(folder).startswith(DOSSIERS_SYSTEME):
                items.append({"nom": os.path.splitext(sub)[0], "editeur": "", "version": "",
                              "emplacement": folder, "taille_registre": 0, "source": "App Paths"})
    return items


def from_shortcuts():
    """Source 5 : cibles des raccourcis du menu Démarrer (utilisateur + tous les utilisateurs)."""
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
        if folder and os.path.isdir(folder) and not norm(folder).startswith(DOSSIERS_SYSTEME):
            items.append({"nom": d["N"], "editeur": "", "version": "", "emplacement": folder,
                          "taille_registre": 0, "source": "Raccourci"})
    return items


# ------------------------------------------------- détection non enregistrés
def candidate_roots(deep):
    """Dossiers à explorer pour trouver des logiciels non déclarés.

    Retourne des tuples (chemin, filtrer_appdata, chercher_residus). Le 2e booléen
    ignore les sous-dossiers de cache (EXCLUS_APPDATA) ; le 3e active la détection
    des dossiers sans exécutable (Program Files, ProgramData uniquement).
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
                              (r"AppData\Roaming", True, False)):
            roots.append((str(u / sub), flt, res))
    for d in drives():
        try:
            for e in os.scandir(d):
                if e.is_dir(follow_symlinks=False) and e.name.lower() not in EXCLUS_RACINE:
                    roots.append((e.path, False, False))
        except OSError:
            pass
    # Dédoublonnage + suppression des chemins inexistants
    seen, out = set(), []
    for r, f, res in roots:
        n = norm(r)
        if n not in seen and os.path.isdir(r):
            seen.add(n)
            out.append((r, f, res))
    return out


def find_unregistered(known, deep):
    """Trouve les logiciels présents sur disque mais sans entrée de désinstallation.

    `known` : chemins déjà identifiés. Retourne {chemin: type} où type vaut :
      - "exe"    : dossier contenant des exécutables (logiciel/portable/jeu sans désinstalleur) ;
      - "residu" : dossier de Program Files/ProgramData/... avec des fichiers mais sans exécutable
                   (reste d'un logiciel désinstallé, ou fichiers de logiciel dont le désinstalleur a disparu).

    Un dossier "éditeur" qui contient des logiciels connus (ex: Adobe\\Reader) n'est pas ignoré :
    on inspecte ses autres sous-dossiers, qui peuvent être des logiciels orphelins.
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

    def examine(path, residu, level, is_drive_root):
        n = norm(path)
        if n.startswith(DOSSIERS_SYSTEME) or inside_known(n):
            return
        if contains_known(n):
            for s in subdirs(path):
                examine(s, residu, level + 1, False)
            return
        if has_exe(path, 4):
            found[path] = "exe"
        elif level == 0 and (is_drive_root or deep):
            # conteneur type "D:\Jeux" : un niveau plus bas
            for s in subdirs(path):
                examine(s, residu, level + 1, False)
        elif residu and level == 0 and os.path.basename(n) not in EXCLUS_RESIDU and has_files(path):
            found[path] = "residu"

    roots = candidate_roots(deep)
    bar = Progress("Analyse des lecteurs", len(roots))
    for root, filtre, residu in roots:
        bar.step(root[-45:])
        drive_root = os.path.dirname(norm(root)) == os.path.splitdrive(norm(root))[0]
        for s in subdirs(root):
            if filtre and os.path.basename(norm(s)) in EXCLUS_APPDATA:
                continue
            examine(s, residu, 0, drive_root)
    bar.close()
    return dict(sorted(found.items(), key=lambda kv: kv[0].lower()))


# ----------------------------------------------------------------------- main
def main():
    """Point d'entrée : collecte, fusion, détection, calcul des tailles, affichage et export."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="inventaire_logiciels.csv")
    ap.add_argument("--json", default="inventaire_logiciels.json")
    ap.add_argument("--deep", action="store_true", help="descend un niveau supplémentaire dans les conteneurs")
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()

    if os.name != "nt":
        sys.exit("Ce script ne fonctionne que sous Windows.")
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[!] Non administrateur : certains dossiers/profils seront inaccessibles.\n")
    except Exception:
        pass

    print("Collecte des sources (registre, Store, services, raccourcis, système)...")
    items = []
    fns = (from_registry, from_appx, from_services, from_app_paths, from_shortcuts, windows_core_entries)
    bar = Progress("Sources", len(fns))
    for fn in fns:
        bar.step(f"{fn.__name__}...", inc=0)
        r = fn()
        items += r
        bar.step(f"{fn.__name__}: {len(r)} entrées")
    bar.close()

    # fusion par emplacement : on garde le meilleur nom, on cumule les sources
    merged = {}
    sans_loc = []
    for it in items:
        if it["emplacement"]:
            k = norm(it["emplacement"])
            m = merged.get(k)
            if not m:
                merged[k] = dict(it, sources={it["source"]})
            else:
                m["sources"].add(it["source"])
                if it["source"] == "Registre" and m["source"] != "Registre":
                    for f in ("nom", "editeur", "version"):
                        m[f] = it[f] or m[f]
                    m["source"] = "Registre"
                m["taille_registre"] = m["taille_registre"] or it["taille_registre"]
                m["systeme_appx"] = m.get("systeme_appx") or it.get("systeme_appx", False)
                m["description"] = m.get("description") or it.get("description", "")
        elif it["source"] == "Registre":
            sans_loc.append(dict(it, sources={"Registre"}))

    # Logiciels identifiés mais dont le dossier n'a pas été trouvé : on tente de le déduire par le nom
    dossiers_prog = [r for r, _, res in candidate_roots(False) if res]
    for e in sans_loc:
        g = guess_location(e["nom"], e["editeur"], dossiers_prog)
        if g:
            e["emplacement"], e["deduit"] = g, True
    deduits = [e for e in sans_loc if e["emplacement"]]
    sans_loc = [e for e in sans_loc if not e["emplacement"]]
    for e in deduits:
        k = norm(e["emplacement"])
        if k in merged:
            merged[k]["sources"].add("Registre")
        else:
            merged[k] = e

    print("Recherche des logiciels sans désinstalleur (analyse des lecteurs)...")
    known = list(merged.keys())
    libelles = {"exe": "Non enregistré (sans désinstalleur)", "residu": "Résidu sans exécutable"}
    for p, kind in find_unregistered(known, a.deep).items():
        merged[norm(p)] = {"nom": os.path.basename(p), "editeur": "", "version": "", "emplacement": p,
                           "taille_registre": 0, "source": libelles[kind], "sources": {libelles[kind]}}

    entries = list(merged.values()) + sans_loc
    bar = Progress("Calcul des tailles", len(entries))

    def work(e):
        if e["emplacement"]:
            e["taille"], e["fichiers"] = dir_size(e["emplacement"])
            e["taille_approx"] = False
            if e["fichiers"] == 0:
                e["statut"] = "Dossier vide ou accès refusé"
            else:
                e["statut"] = "Emplacement déduit du nom" if e.get("deduit") else "OK"
        else:
            e["taille"], e["fichiers"], e["taille_approx"] = e["taille_registre"], 0, True
            e["statut"] = ("Fichiers introuvables (dossier déclaré absent)" if e.get("emplacement_declare")
                           else "Fichiers introuvables (emplacement inconnu)")
            e["emplacement"] = ""
        e["lecteur"] = os.path.splitdrive(e["emplacement"])[0].upper() + "\\" if e["emplacement"] else "?"
        e["source"] = ", ".join(sorted(e["sources"]))
        # Description : celle déclarée si elle existe, sinon métadonnées de l'.exe
        if not e.get("description") and e["emplacement"]:
            e["description"] = short(exe_description(e["emplacement"]))
        e["description"] = e.get("description", "")
        e["windows"] = "Oui" if is_windows(e) else "Non"
        bar.step(f"{e['nom'][:30]} ({human(e['taille'])})")
        return e

    with ThreadPoolExecutor(a.workers) as ex:
        entries = list(ex.map(work, entries))
    bar.close()

    entries.sort(key=lambda e: (e["lecteur"], -e["taille"]))
    for lec in sorted({e["lecteur"] for e in entries}):
        grp = [e for e in entries if e["lecteur"] == lec]
        label = "Fichiers introuvables (taille = valeur du registre)" if lec == "?" else f"Lecteur {lec}"
        print(f"\n===== {label} — {len(grp)} logiciels — total {human(sum(e['taille'] for e in grp))} =====")
        for e in grp:
            tag = "~" if e["taille_approx"] else " "
            win = "[WIN] " if e["windows"] == "Oui" else ""
            lieu = e["emplacement"] or (f"(déclaré : {e['emplacement_declare']})" if e.get("emplacement_declare") else "-")
            print(f"{tag}{human(e['taille']):>10}  {win}{e['nom'][:45]:<45} [{e['source']}]  {lieu}")
            if e["statut"] != "OK":
                print(f"{'':>13}! {e['statut']}")
            if e["description"]:
                print(f"{'':>13}-> {e['description']}")

    nb_win = sum(e["windows"] == "Oui" for e in entries)
    print(f"\n{nb_win} composant(s) nécessaire(s) au fonctionnement de Windows sur {len(entries)} (marqués [WIN]).")

    # Exports : utf-8-sig pour que Excel lise correctement les accents
    cols = ["lecteur", "nom", "description", "windows", "statut", "editeur", "version", "taille", "fichiers",
            "taille_approx", "source", "emplacement", "emplacement_declare"]
    for e in entries:
        e.setdefault("emplacement_declare", "")
    with open(a.csv, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore", delimiter=";")
        w.writeheader()
        w.writerows(entries)
    with open(a.json, "w", encoding="utf-8") as f:
        json.dump([{c: e[c] for c in cols} for e in entries], f, ensure_ascii=False, indent=2)
    print(f"\nExporté : {a.csv} et {a.json}  (~ = taille estimée par le registre, emplacement inconnu)")


if __name__ == "__main__":
    main()

