def parse_firewall_config(filename):
    """
    Parse a simple firewall configuration file.

    Returns:
        {
            "rules": [...],
            "logging": True/False,
            "syslog": "...",
            "default_inbound": "...",
            "default_outbound": "..."
        }
    """

    firewall = {
        "rules": [],
        "logging": False,
        "syslog": None,
        "default_inbound": None,
        "default_outbound": None
    }

    with open(filename, "r") as file:

        for line in file:

            line = line.strip()

            # Ignore empty lines and comments
            if not line or line.startswith("#"):
                continue

            parts = line.split()

            if parts[0] in ("ALLOW", "DENY"):

                firewall["rules"].append({
                    "action": parts[0],
                    "source": parts[1],
                    "destination": parts[2],
                    "port": int(parts[3])
                })

            elif parts[0] == "LOGGING":

                firewall["logging"] = (parts[1] == "ENABLED")

            elif parts[0] == "SYSLOG":

                firewall["syslog"] = parts[1]

            elif parts[0] == "DEFAULT_INBOUND":

                firewall["default_inbound"] = parts[1]

            elif parts[0] == "DEFAULT_OUTBOUND":

                firewall["default_outbound"] = parts[1]

    return firewall