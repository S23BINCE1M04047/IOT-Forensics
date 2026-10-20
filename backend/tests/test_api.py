from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from tests.helpers import ESP, EXT, Cap, tcp


def test_upload_analyze_findings_override_and_reanalysis(tmp_path: Path) -> None:
    cap = Cap()
    for k in range(6):
        cap.add(tcp(ESP, EXT, 8443, sport=50200), k * 30)
    pcap = cap.write(tmp_path / "t.pcap")

    with TestClient(app) as client:
        up = client.post("/api/upload", files={"file": ("t.pcap", pcap.read_bytes(), "application/octet-stream")})
        fid = up.json()["data"]["file_id"]
        assert client.post(f"/api/analyze/{fid}").json()["ok"]
        st = client.get(f"/api/status/{fid}").json()["data"]
        assert st["status"] == "done" and st["integrity_ok"] is True

        p2 = client.get(f"/api/findings/{fid}?priority=P2").json()["data"]
        assert p2["total"] == 2  # R-EXT-DEST-01 + R-BEACON-01 (no baseline loaded)
        item = p2["items"][0]

        patched = client.patch(f"/api/findings/{item['finding_id']}", json={
            "priority": "P1", "analyst_note": "confirmed against device log", "analyst": "tester"})
        assert patched.json()["data"]["priority"] == "P1"
        detail = client.get(f"/api/findings/{item['finding_id']}").json()["data"]
        assert detail["original_priority"] == "P2" and detail["overridden"] and detail["packets"]
        assert detail["wireshark_filter"].startswith("frame.number in {")

        assert client.post(f"/api/analyze/{fid}").json()["ok"]  # re-analysis keeps the override
        assert client.get(f"/api/findings/{fid}?priority=P1").json()["data"]["total"] == 1
        assert client.get(f"/api/summary/{fid}").json()["data"]["priority_counts"]["P1"] == 1