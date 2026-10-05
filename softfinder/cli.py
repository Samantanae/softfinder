"""Command-line interface: python -m softfinder [options]  (or the `softfinder` command)."""
import argparse
import csv
import json
import sys

from .core import COLUMNS, human, is_admin, scan


def print_report(entries):
    """Print the entries grouped by drive, with a total per drive."""
    for drv in sorted({e["drive"] for e in entries}):
        grp = [e for e in entries if e["drive"] == drv]
        # Separator between drives
        label = "Files not found (size = registry value)" if drv == "?" else f"Drive {drv}"
        # Print the header for this drive
        print(f"\n===== {label} — {len(grp)} software — total {human(sum(e['size'] for e in grp))} =====")
        for e in grp:
            # Print each software entry within the drive
            tag = "~" if e["approx_size"] else " "
            # Mark entries with approximate size from the registry
            win = "[WIN] " if e["windows"] == "Yes" else ""
            # Determine the display location for this software entry
            place = e["location"] or (f"(declared: {e['declared_location']})" if e.get("declared_location") else "-")
            # Print the software entry with its size, name, source, and location
            print(f"{tag}{human(e['size']):>10}  {win}{e['name'][:45]:<45} [{e['source']}]  {place}")
            # Print the status and description if available
            if e["status"] != "OK":
                print(f"{'':>13}! {e['status']}")
            if e["description"]:
                print(f"{'':>13}-> {e['description']}")
    # Print the summary of Windows-required components
    nb_win = sum(e["windows"] == "Yes" for e in entries)
    print(f"\n{nb_win} component(s) required for Windows to work out of {len(entries)} (marked [WIN]).")


def export_csv(entries, path):
    """Write the entries to a CSV file (';' separator, utf-8-sig so that Excel reads accents correctly)."""
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore", delimiter=";")
        w.writeheader()
        w.writerows(entries)


def export_json(entries, path):
    """Write the entries to a JSON file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump([{c: e[c] for c in COLUMNS} for e in entries], f, ensure_ascii=False, indent=2)


def main(argv=None):
    """CLI entry point; argv defaults to sys.argv[1:]. Returns the process exit code."""
    ap = argparse.ArgumentParser(prog="softfinder", description="Complete inventory of installed software (Windows).")
    ap.add_argument("--csv", default="software_inventory.csv", help="CSV output file")
    ap.add_argument("--json", default="software_inventory.json", help="JSON output file")
    ap.add_argument("--deep", action="store_true", help="go one extra level deeper in container folders")
    ap.add_argument("--workers", type=int, default=8, help="threads used to compute sizes")
    a = ap.parse_args(argv)

    if not is_admin():
        print("[!] Not running as administrator: some folders/profiles will be inaccessible.\n")
    try:
        entries = scan(deep=a.deep, workers=a.workers, log=print)
    except OSError as err:
        print(err, file=sys.stderr)
        return 1
    print_report(entries)
    export_csv(entries, a.csv)
    export_json(entries, a.json)
    print(f"\nExported: {a.csv} and {a.json}  (~ = size estimated from the registry, unknown location)")
    return 0
