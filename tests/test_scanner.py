from scanner.benchmark_checks import run_all_checks
from scanner.config_parser import parse_firewall_config
from scanner.main import targets_from_argument


def test_sample_firewall_produces_seven_mapped_checks():
    results = run_all_checks([], parse_firewall_config("config/sample_firewall.conf"))
    assert len(results) == 8
    assert all(result["cis_control"].startswith("CIS Controls v8") for result in results)
    assert any(result["check"] == "Weak SNMP community strings not used" and result["status"] == "FAIL" for result in results)


def test_targets_support_ip_list_and_small_cidr():
    assert targets_from_argument("127.0.0.1,127.0.0.2") == ["127.0.0.1", "127.0.0.2"]
    assert targets_from_argument("127.0.0.0/30") == ["127.0.0.1", "127.0.0.2"]
