"""CIS Controls v8-inspired network posture checks (not a certification)."""
SENSITIVE_PORTS = {22, 23, 3389, 445, 3306, 5432}
INSECURE_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 161: "SNMP"}
PUBLIC_SOURCES = {"ANY", "0.0.0.0/0", "::/0"}


def _result(check, status, severity, evidence, recommendation, cis_control):
    return {"check": check, "status": status, "severity": severity, "evidence": evidence,
            "recommendation": recommendation, "cis_control": cis_control}


def _allowed(firewall, ports):
    return [r for r in firewall["rules"] if r["action"] == "ALLOW" and r["port"] in ports]


def check_insecure_protocols(firewall):
    offenders = _allowed(firewall, INSECURE_PORTS)
    return _result("Insecure management protocols disabled", "FAIL" if offenders else "PASS", "HIGH",
                   offenders or "No FTP, Telnet, HTTP, or SNMP allow rule.",
                   "Remove insecure management access; use SSH/HTTPS/SNMPv3.", "CIS Controls v8 4.8")


def check_discovered_insecure_services(devices):
    """Use the live discovery results as evidence, not only the firewall policy."""
    offenders = []
    for device in devices:
        for port in device.get("ports", []):
            if port.get("port") in INSECURE_PORTS:
                offenders.append({"ip": device.get("ip"), "hostname": device.get("hostname"),
                                  "port": port.get("port"), "service": port.get("service"),
                                  "banner": port.get("banner")})
    return _result("No insecure services discovered on scanned hosts", "FAIL" if offenders else "PASS", "HIGH",
                   offenders or "No FTP, Telnet, HTTP, or SNMP services were detected on reachable hosts.",
                   "Disable insecure services or replace them with SSH, HTTPS, or SNMPv3.", "CIS Controls v8 4.8")


def check_ssh_restricted(firewall):
    ssh = _allowed(firewall, {22})
    public = [r for r in ssh if r["source"].upper() in PUBLIC_SOURCES]
    return _result("SSH restricted to management subnet", "PASS" if ssh and not public else "FAIL", "HIGH",
                   public or ssh or "No SSH allow rule.", "Allow SSH only from a named management subnet.", "CIS Controls v8 6.3")


def check_sensitive_ingress(firewall):
    offenders = [r for r in _allowed(firewall, SENSITIVE_PORTS) if r["source"].upper() in PUBLIC_SOURCES]
    return _result("Sensitive ports not publicly exposed", "FAIL" if offenders else "PASS", "HIGH",
                   offenders or "No public sensitive-port allow rules.", "Restrict sensitive services to trusted source networks.", "CIS Controls v8 12.6")


def check_snmp_community(firewall):
    weak = [c for c in firewall.get("snmp_communities", []) if c.lower() in {"public", "private"}]
    return _result("Weak SNMP community strings not used", "FAIL" if weak else "PASS", "HIGH",
                   weak or "No default SNMP community strings found.", "Use SNMPv3 or a strong community.", "CIS Controls v8 4.8")


def check_default_inbound(firewall):
    value = firewall.get("default_inbound")
    return _result("Default inbound policy is deny", "PASS" if value == "DENY" else "FAIL", "HIGH", value,
                   "Set the default inbound policy to DENY.", "CIS Controls v8 12.6")


def check_egress_filtering(firewall):
    value = firewall.get("default_outbound")
    return _result("Egress traffic is filtered", "PASS" if value == "DENY" else "FAIL", "MEDIUM", value,
                   "Use a default-deny outbound policy with explicit exceptions.", "CIS Controls v8 12.6")


def check_remote_logging(firewall):
    good = firewall.get("logging") and firewall.get("syslog")
    return _result("Remote firewall logging configured", "PASS" if good else "FAIL", "MEDIUM",
                   {"logging": firewall.get("logging"), "syslog": firewall.get("syslog")},
                   "Enable logging and forward it to a remote syslog collector.", "CIS Controls v8 8.11")


def run_all_checks(devices, firewall):
    return [check_insecure_protocols(firewall), check_discovered_insecure_services(devices), check_ssh_restricted(firewall),
            check_sensitive_ingress(firewall), check_snmp_community(firewall),
            check_default_inbound(firewall), check_egress_filtering(firewall), check_remote_logging(firewall)]
