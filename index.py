"""
api/index.py — Vercel Serverless Function Entrypoint for FastAPI Backend.
Track 1: Agents That Act on Connected Data (FalkorDB Hackathon)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Add project root and backend to sys.path
_ROOT = Path(__file__).resolve().parent.parent
_BACKEND = _ROOT / "backend"
for _p in [str(_ROOT), str(_BACKEND)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Import the initialized FastAPI app
from backend.main import app
