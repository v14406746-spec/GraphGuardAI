"""
mcp_server/server.py — Root proxy forwarding to backend.mcp_server.server
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_BACKEND = _ROOT / "backend"
for _p in [str(_ROOT), str(_BACKEND)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backend.mcp_server.server import app, main

if __name__ == "__main__":
    main()
