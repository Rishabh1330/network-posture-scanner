import json

from dashboard import api


def test_dashboard_reads_local_scan_reports_when_selected(monkeypatch, tmp_path):
    (tmp_path / "scan_results.json").write_text(json.dumps({"devices": [{"ip": "192.168.1.10"}]}), encoding="utf-8")
    (tmp_path / "firewall_rules.json").write_text(json.dumps({"rules": []}), encoding="utf-8")
    (tmp_path / "cis_results.json").write_text(json.dumps([{"status": "PASS"}]), encoding="utf-8")
    monkeypatch.setattr(api, "DATA_SOURCE", "local")
    monkeypatch.setattr(api, "REPORT_DIRECTORY", tmp_path)

    devices, firewall, results, source, error = api.get_dashboard_data()

    assert devices == [{"ip": "192.168.1.10"}]
    assert firewall == {"rules": []}
    assert results == [{"status": "PASS"}]
    assert source == "Local scan reports"
    assert error is None
