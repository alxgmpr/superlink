import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent

# Add the superlink package to path so tests can `import superlink.*`
sys.path.insert(0, str(_REPO_ROOT / "tools" / "sx1302"))
# Add the repo root so tests can `from tests.fixtures.captured_frames import ...`
sys.path.insert(0, str(_REPO_ROOT))
