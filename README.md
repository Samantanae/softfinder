# Software inventory (Windows)

`scan_logiciels.py` lists **all** the software installed on every drive, with its
**real size on disk** and its **location**, including software that a normal
scan misses (no uninstaller, portable, games, leftovers of removed software).

## Requirements

- Windows, Python 3.8+
- No external dependency (PowerShell is used for Store apps and shortcuts)
- Run as **administrator** for the most complete result (otherwise some
  folders/profiles are unreadable and a warning is shown)

## Usage

```powershell
python -X utf8 scan_logiciels.py
python -X utf8 scan_logiciels.py --csv inventory.csv --json inventory.json
python -X utf8 scan_logiciels.py --deep        # one extra level in container folders (e.g. D:\Games\...)
python -X utf8 scan_logiciels.py --workers 16  # more threads for size computation
```

| Option      | Default                   | Description                                   |
|-------------|---------------------------|-----------------------------------------------|
| `--csv`     | `software_inventory.csv`  | CSV output (`;` separator, UTF-8 with BOM)    |
| `--json`    | `software_inventory.json` | JSON output                                   |
| `--deep`    | off                       | Scan one extra level in container folders     |
| `--workers` | `8`                       | Threads used to compute sizes                 |

A full scan can take several minutes. Progress bars (stderr) show the
progress of the three phases: sources, drive scan, size computation.

## How it works

1. **Sources**: registry Uninstall keys, Microsoft Store/MSIX apps, services,
   registry App Paths, Start menu shortcuts, Windows core components.
2. **Merge**: entries pointing to the same folder become one software.
3. **Location recovery**: if the registry gives no folder, it is searched in
   several registry keys and the MSI API, then deduced from the software name.
4. **Hidden software**: drives are scanned for folders containing `.exe` files
   not attached to any known entry, and for folders with files but no `.exe`
   (leftovers).
5. **Sizes**: files are actually walked (not the registry `EstimatedSize`);
   junctions/symlinks are skipped and hard links counted once.
6. **Description**: registry comment, service description, or the `.exe` file
   description.
7. **Output**: console (grouped by drive), CSV and JSON.

## Reading the results

- `[WIN]` / `windows = Yes`: component required for Windows to work.
- `~` before a size: estimated from the registry (files not found).
- Group `?`: software identified but whose files were not found.

### Source

`Registry`, `Store/MSIX`, `Service`, `App Paths`, `Shortcut`, `System`,
`Unregistered (no uninstaller)`, `Leftover without executable`.

### Status

`OK`, `Location deduced from name`, `Empty folder or access denied`,
`Files not found (declared folder missing)`, `Files not found (unknown location)`.

### CSV / JSON columns

`drive, name, description, windows, status, publisher, version, size, files,
approx_size, source, location, declared_location` (`size` in bytes).

## Limitations

- Without administrator rights, other users' profiles and the all-users Store
  app list are inaccessible.
- Location deduced from the name can occasionally be a false match.
- The "Windows" flag is a heuristic (Windows folders, Microsoft Windows
  publisher, non-removable Store packages).
