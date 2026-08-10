"""
CIS Benchmark Checks
"""


# --------------------------------------------------
# Generic Helper
# --------------------------------------------------

def check_port_not_allowed(firewall, port, service):
    """
    Generic check for insecure services.
    PASS if the port is not explicitly allowed.
    """

    for rule in firewall["rules"]:

        if rule["port"] == port and rule["action"] == "ALLOW":

            return {
                "check": f"{service} Disabled",
                "status": "FAIL",
                "severity": "HIGH",
                "evidence": rule,
                "recommendation": f"Disable {service} or replace it with a secure alternative."
            }

    return {
        "check": f"{service} Disabled",
        "status": "PASS",
        "severity": "HIGH",
        "evidence": f"No ALLOW rule found for port {port}.",
        "recommendation": "No action required."
    }


# --------------------------------------------------
# SSH Restriction
# --------------------------------------------------

def check_ssh_restricted(firewall):
    """
    SSH should only be accessible from the management subnet.
    """

    for rule in firewall["rules"]:

        if rule["port"] == 22 and rule["action"] == "ALLOW":

            if rule["source"] == "ANY":

                return {
                    "check": "SSH Restricted",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "evidence": rule,
                    "recommendation": "Restrict SSH access to a management subnet."
                }

            return {
                "check": "SSH Restricted",
                "status": "PASS",
                "severity": "HIGH",
                "evidence": rule,
                "recommendation": "No action required."
            }

    return {
        "check": "SSH Restricted",
        "status": "FAIL",
        "severity": "HIGH",
        "evidence": "No SSH rule found.",
        "recommendation": "Create a secure SSH rule."
    }


# --------------------------------------------------
# Sensitive Ports
# --------------------------------------------------

def check_sensitive_ports(firewall):

    sensitive_ports = [22, 23, 3389, 445, 3306, 5432]

    offending = []

    for rule in firewall["rules"]:

        if (
            rule["action"] == "ALLOW"
            and rule["source"] == "ANY"
            and rule["port"] in sensitive_ports
        ):

            offending.append(rule)

    if offending:

        return {
            "check": "Sensitive Ports Protected",
            "status": "FAIL",
            "severity": "HIGH",
            "evidence": offending,
            "recommendation": "Restrict sensitive ports to trusted networks."
        }

    return {
        "check": "Sensitive Ports Protected",
        "status": "PASS",
        "severity": "HIGH",
        "evidence": "No sensitive ports exposed.",
        "recommendation": "No action required."
    }


# --------------------------------------------------
# Logging
# --------------------------------------------------

def check_logging_enabled(firewall):

    if firewall["logging"]:

        return {
            "check": "Logging Enabled",
            "status": "PASS",
            "severity": "MEDIUM",
            "evidence": "Logging is enabled.",
            "recommendation": "No action required."
        }

    return {
        "check": "Logging Enabled",
        "status": "FAIL",
        "severity": "MEDIUM",
        "evidence": "Logging is disabled.",
        "recommendation": "Enable firewall logging."
    }


# --------------------------------------------------
# Default Outbound
# --------------------------------------------------

def check_default_outbound(firewall):

    if firewall["default_outbound"] == "DENY":

        return {
            "check": "Default Outbound Policy",
            "status": "PASS",
            "severity": "MEDIUM",
            "evidence": firewall["default_outbound"],
            "recommendation": "No action required."
        }

    return {
        "check": "Default Outbound Policy",
        "status": "FAIL",
        "severity": "MEDIUM",
        "evidence": firewall["default_outbound"],
        "recommendation": "Use a default DENY outbound policy."
    }


# --------------------------------------------------
# Run Everything
# --------------------------------------------------

def run_all_checks(devices, firewall):

    results = [

        check_port_not_allowed(firewall, 23, "Telnet"),

        check_port_not_allowed(firewall, 21, "FTP"),

        check_ssh_restricted(firewall),

        check_sensitive_ports(firewall),

        check_logging_enabled(firewall),

        check_default_outbound(firewall)

    ]

    return results