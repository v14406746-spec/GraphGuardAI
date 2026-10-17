"""
ingestion/load_data.py — Root proxy forwarding to backend.ingestion.load_data
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_BACKEND = _ROOT / "backend"
for _p in [str(_ROOT), str(_BACKEND)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backend.ingestion.load_data import *
from backend.ingestion.load_data import load_and_verify_graph

if __name__ == "__main__":
    load_and_verify_graph()
