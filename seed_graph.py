"""
ingestion/seed_graph.py — Root proxy forwarding to backend.ingestion.seed_graph
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_BACKEND = _ROOT / "backend"
for _p in [str(_ROOT), str(_BACKEND)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backend.ingestion.seed_graph import *
from backend.ingestion.seed_graph import (
    get_all_seed_data,
    get_synthetic_nodes,
    get_synthetic_relationships,
)
