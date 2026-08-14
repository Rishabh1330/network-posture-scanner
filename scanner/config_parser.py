"""Parser for the included, documented simulated firewall configuration format."""
from pathlib import Path


def parse_firewall_config(filename):
    firewall = {"source": {"type": "simulated_config", "path": str(Path(filename))},
                "rules": [], "logging": False, "syslog": None,
                "default_inbound": None, "default_outbound": None,
                "snmp_communities": []}
    for line_number, raw_line in enumerate(Path(filename).read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts, directive = line.split(), line.split()[0].upper()
        if directive in {"ALLOW", "DENY"}:
            if len(parts) != 4 or not parts[3].isdigit():
                raise ValueError(f"Invalid rule at line {line_number}: {raw_line}")
            firewall["rules"].append({"action": directive, "source": parts[1],
                                      "destination": parts[2], "port": int(parts[3])})
        elif directive == "LOGGING" and len(parts) == 2:
            firewall["logging"] = parts[1].upper() == "ENABLED"
        elif directive == "SYSLOG" and len(parts) == 2:
            firewall["syslog"] = parts[1]
        elif directive in {"DEFAULT_INBOUND", "DEFAULT_OUTBOUND"} and len(parts) == 2:
            firewall[directive.lower()] = parts[1].upper()
        elif directive == "SNMP_COMMUNITY" and len(parts) == 2:
            firewall["snmp_communities"].append(parts[1])
        else:
            raise ValueError(f"Unknown or malformed directive at line {line_number}: {raw_line}")
    return firewall
