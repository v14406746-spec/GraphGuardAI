"""
mcp_server/__init__.py — Root proxy forwarding to backend.mcp_server
"""
try:
    from backend.mcp_server.server import app
except Exception:
    app = None

__all__ = ["app"]
