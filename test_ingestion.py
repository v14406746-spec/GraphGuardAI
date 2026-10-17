"""
tests/test_ingestion.py — Verification of Phase 1 Graph Ingestion Pipeline.
Track 1: Agents That Act on Connected Data (FalkorDB Hackathon)

Verifies:
  1. schema.cypher structure and syntax.
  2. Synthetic enterprise nodes and relationships generation.
  3. FalkorDBClient connectivity and in-memory mock store preloading.
  4. CSV telemetry ingestion (accounts.csv, transactions.csv, devices.csv, login_events.csv).
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_BACKEND = _ROOT / "backend"
for _p in [str(_BACKEND), str(_ROOT)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backend.graph_client import get_graph_client
try:
    from backend.ingestion.seed_graph import get_synthetic_nodes, get_synthetic_relationships
except ImportError:
    from ingestion.seed_graph import get_synthetic_nodes, get_synthetic_relationships


def test_schema_file_exists():
    root = Path(__file__).resolve().parent.parent
    schema_path = root / "backend" / "ingestion" / "schema.cypher"
    if not schema_path.exists():
        schema_path = root / "ingestion" / "schema.cypher"
    assert schema_path.exists(), f"schema.cypher not found at {schema_path}"
    content = schema_path.read_text(encoding="utf-8")
    assert "CREATE INDEX ON" in content
    assert ":User" in content
    assert ":LoginEvent" in content
    assert ":IPAddress" in content
    assert ":Server" in content
    print("  [PASS] schema.cypher validated.")


def test_synthetic_nodes_and_relationships():
    nodes = get_synthetic_nodes()
    assert "User" in nodes and len(nodes["User"]) >= 5
    assert "Device" in nodes and len(nodes["Device"]) >= 5
    assert "IPAddress" in nodes and len(nodes["IPAddress"]) >= 5
    assert "Server" in nodes and len(nodes["Server"]) >= 5
    assert "Alert" in nodes and len(nodes["Alert"]) >= 6

    rels = get_synthetic_relationships()
    assert len(rels) >= 40, f"Expected at least 40 relationships, found {len(rels)}"
    print(f"  [PASS] Synthetic seed graph validated ({sum(len(v) for v in nodes.values())} nodes, {len(rels)} edges).")


def test_csv_data_files():
    root = Path(__file__).resolve().parent.parent
    data_dir = root / "backend" / "data"
    assert data_dir.exists(), f"backend/data directory not found at {data_dir}"

    for csv_name in ["accounts.csv", "transactions.csv", "devices.csv", "login_events.csv"]:
        csv_file = data_dir / csv_name
        assert csv_file.exists(), f"Required CSV {csv_name} not found in {data_dir}"
        lines = [line.strip() for line in csv_file.read_text(encoding="utf-8").split("\n") if line.strip()]
        assert len(lines) >= 5, f"{csv_name} has insufficient rows ({len(lines)})"
    print("  [PASS] Synthetic CSV data files validated in backend/data/.")


def test_graph_client_query_execution():
    db = get_graph_client()
    alerts = db.query("MATCH (a:Alert) RETURN a")
    assert len(alerts) >= 6, f"Expected >= 6 seeded alerts, found {len(alerts)}"
    
    users = db.query("MATCH (u:User) RETURN u")
    assert len(users) >= 5, f"Expected >= 5 seeded users, found {len(users)}"
    print(f"  [PASS] FalkorDBClient query execution verified ({len(alerts)} alerts, {len(users)} users).")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  PHASE 1: GRAPH INGESTION TEST SUITE")
    print("=" * 60)
    test_schema_file_exists()
    test_synthetic_nodes_and_relationships()
    test_csv_data_files()
    test_graph_client_query_execution()
    print("=" * 60)
    print("  ALL INGESTION TESTS PASSED SUCCESSFULLY!")
    print("=" * 60 + "\n")
