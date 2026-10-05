"""SoftFinder - complete inventory of installed software (Windows) with real size and location.

Example:
    import softfinder
    for e in softfinder.scan(progress=False):
        print(e["name"], softfinder.human(e["size"]), e["location"])

See softfinder.core for the entry format; the command line is `python -m softfinder --help`.
"""
from .core import COLUMNS, human, is_admin, scan

__all__ = ["scan", "human", "is_admin", "COLUMNS"]
__version__ = "1.0.0"
