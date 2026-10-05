"""Short launcher: `py softfinder.py [options]` (same as `python -m softfinder`)."""
import sys

# Importing "softfinder" resolves to the package folder next to this file, not to this script.
from softfinder.cli import main

sys.exit(main())
