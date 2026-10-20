import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(ROOT / "crypto"))
os.environ.setdefault("ORG_ROOT_PUB_FILE", str(ROOT / "infra" / "keys" / "org_root.pub.json"))
os.environ.setdefault("SERVER_KEYS_DIR", str(ROOT / "infra" / "keys" / "server"))
