import sys
from pathlib import Path

# Add the superlink package to path so tests can import it
sys.path.insert(0, str(Path(__file__).parent.parent / "tools" / "sx1302"))
