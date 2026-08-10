import streamlit as st
import pandas as pd
from datetime import datetime

from api import (
    get_devices,
    get_firewall,
    get_cis_results
)

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Network Posture Scanner",
    page_icon="🛡️",
    layout="wide"
)

# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown("""
<style>

    .main-title {
        font-size: 32px;
        font-weight: 700;
        margin-bottom: 0px;
    }

    .subtitle {
        color: #9ca3af;
        font-size: 16px;
        margin-bottom: 25px;
    }

    .section-title {
        font-size: 22px;
        font-weight: 600;
        margin-top: 15px;
    }

    .pass-box {
        padding: 12px 16px;
        border-radius: 8px;
        background-color: rgba(34, 197, 94, 0.12);
        border-left: 5px solid #22c55e;
        margin-bottom: 10px;
    }

    .fail-box {
        padding: 12px 16px;
        border-radius: 8px;
        background-color: rgba(239, 68, 68, 0.12);
        border-left: 5px solid #ef4444;
        margin-bottom: 10px;
    }

    .evidence-box {
        padding: 10px 14px;
        border-radius: 6px;
        background-color: rgba(148, 163, 184, 0.08);
        margin-top: 8px;
        margin-bottom: 8px;
    }

</style>
""", unsafe_allow_html=True)

# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ Network Posture Scanner</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Network security posture and CIS benchmark dashboard'
    '</div>',
    unsafe_allow_html=True
)

# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header("Dashboard")

    if st.button(
        "🔄 Refresh Data",
        use_container_width=True
    ):
        st.rerun()

    st.divider()

    st.subheader("System")

    st.success("API Gateway")
    st.success("AWS Lambda")
    st.success("DynamoDB")

    st.divider()

    st.caption(
        "Network Posture Scanner v1.0"
    )

# ============================================================
# FETCH DATA
# ============================================================

try:

    devices = get_devices()
    firewall = get_firewall()
    cis = get_cis_results()

except Exception as e:

    st.error(
        "❌ Unable to fetch data from AWS."
    )

    st.code(str(e))

    st.stop()

# ============================================================
# NORMALIZE API RESPONSES
# ============================================================

# /devices API returns:
#
# {
#     "success": true,
#     "count": 1,
#     "data": [...]
# }

if isinstance(devices, dict):

    devices = devices.get("data", [])

elif not isinstance(devices, list):

    devices = []


# /cis-results API may return:
#
# {
#     "success": true,
#     "count": 6,
#     "data": [...]
# }

if isinstance(cis, dict):

    cis = cis.get("data", [])

elif not isinstance(cis, list):

    cis = []


# Firewall API

if not isinstance(firewall, dict):

    firewall = {}

# ============================================================
# SUMMARY CALCULATIONS
# ============================================================

total_devices = len(devices)

open_ports = sum(
    len(device.get("ports", []))
    for device in devices
    if isinstance(device, dict)
)

pass_checks = sum(
    1
    for result in cis
    if isinstance(result, dict)
    and result.get("status") == "PASS"
)

fail_checks = sum(
    1
    for result in cis
    if isinstance(result, dict)
    and result.get("status") == "FAIL"
)

total_checks = pass_checks + fail_checks

if total_checks > 0:

    compliance = round(
        (pass_checks / total_checks) * 100,
        1
    )

else:

    compliance = 0

# ============================================================
# SUMMARY
# ============================================================

st.markdown(
    '<div class="section-title">📊 Security Summary</div>',
    unsafe_allow_html=True
)

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric(
    "🖥️ Devices",
    total_devices
)

col2.metric(
    "🔓 Open Ports",
    open_ports
)

col3.metric(
    "✅ PASS",
    pass_checks
)

col4.metric(
    "❌ FAIL",
    fail_checks
)

col5.metric(
    "🛡️ Compliance",
    f"{compliance}%"
)

st.progress(
    compliance / 100
)

st.divider()

# ============================================================
# DEVICES
# ============================================================

st.markdown(
    '<div class="section-title">🖥️ Discovered Devices</div>',
    unsafe_allow_html=True
)

if not devices:

    st.info(
        "No devices discovered."
    )

else:

    device_rows = []

    for device in devices:

        if not isinstance(device, dict):
            continue

        ports = device.get(
            "ports",
            []
        )

        port_numbers = ", ".join(
            str(port.get("port", "-"))
            for port in ports
            if isinstance(port, dict)
        )

        services = ", ".join(
            port.get("service", "Unknown")
            for port in ports
            if isinstance(port, dict)
        )

        device_rows.append({

            "IP Address":
                device.get("ip", "-"),

            "Hostname":
                device.get("hostname", "-"),

            "Status":
                device.get("state", "-"),

            "Open Ports":
                port_numbers,

            "Services":
                services

        })

    if device_rows:

        st.dataframe(
            pd.DataFrame(device_rows),
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No valid device records found."
        )

st.divider()

# ============================================================
# FIREWALL
# ============================================================

st.markdown(
    '<div class="section-title">🔥 Firewall Configuration</div>',
    unsafe_allow_html=True
)

rules = firewall.get(
    "rules",
    []
)

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Firewall Rules",
    len(rules)
)

col2.metric(
    "Default Inbound",
    firewall.get(
        "default_inbound",
        "-"
    )
)

col3.metric(
    "Default Outbound",
    firewall.get(
        "default_outbound",
        "-"
    )
)

col4.metric(
    "Logging",
    str(
        firewall.get(
            "logging",
            "-"
        )
    )
)

# ============================================================
# FIREWALL WARNINGS
# ============================================================

if firewall.get("default_inbound") == "DENY":

    st.success(
        "🟢 Default inbound policy is DENY."
    )

elif firewall.get("default_inbound"):

    st.warning(
        "🟠 Default inbound policy is not DENY."
    )


if firewall.get("default_outbound") == "ALLOW":

    st.warning(
        "🔴 Default outbound policy is ALLOW. "
        "Consider restricting outbound traffic."
    )

elif firewall.get("default_outbound"):

    st.success(
        "🟢 Default outbound policy is DENY."
    )


syslog = firewall.get(
    "syslog"
)

if syslog:

    st.info(
        f"📡 Syslog Server: {syslog}"
    )

# ============================================================
# FIREWALL RULE TABLE
# ============================================================

if rules:

    st.markdown(
        "### Firewall Rules"
    )

    firewall_rows = []

    for rule in rules:

        if not isinstance(rule, dict):
            continue

        firewall_rows.append({

            "Action":
                rule.get(
                    "action",
                    "-"
                ),

            "Source":
                rule.get(
                    "source",
                    "-"
                ),

            "Destination":
                rule.get(
                    "destination",
                    "-"
                ),

            "Port":
                rule.get(
                    "port",
                    "-"
                )

        })

    if firewall_rows:

        st.dataframe(
            pd.DataFrame(firewall_rows),
            use_container_width=True,
            hide_index=True
        )

else:

    st.info(
        "No firewall rules found."
    )

st.divider()

# ============================================================
# CIS RESULTS
# ============================================================

st.markdown(
    '<div class="section-title">✅ CIS Benchmark Results</div>',
    unsafe_allow_html=True
)

if not cis:

    st.info(
        "No CIS benchmark results available."
    )

else:

    for result in cis:

        if not isinstance(result, dict):
            continue

        check = result.get(
            "check",
            "Unknown Check"
        )

        status = result.get(
            "status",
            "UNKNOWN"
        )

        severity = result.get(
            "severity",
            "UNKNOWN"
        )

        evidence = result.get(
            "evidence",
            "No evidence available"
        )

        recommendation = result.get(
            "recommendation",
            "No recommendation available"
        )

        # ==================================================
        # PASS RESULT
        # ==================================================

        if status == "PASS":

            with st.expander(
                f"🟢 {check}  —  PASS"
            ):

                st.write(
                    f"**Severity:** {severity}"
                )

                st.markdown(
                    f"""
                    <div class="evidence-box">
                    <b>Evidence:</b><br>
                    {evidence}
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                st.write(
                    f"**Recommendation:** "
                    f"{recommendation}"
                )

        # ==================================================
        # FAIL RESULT
        # ==================================================

        elif status == "FAIL":

            with st.expander(
                f"🔴 {check}  —  FAIL"
            ):

                st.error(
                    f"Severity: {severity}"
                )

                # ------------------------------------------
                # Format evidence
                # ------------------------------------------

                if isinstance(evidence, list):

                    st.write(
                        "**Offending Rule(s):**"
                    )

                    for rule in evidence:

                        if isinstance(rule, dict):

                            source = rule.get(
                                "source",
                                "-"
                            )

                            destination = rule.get(
                                "destination",
                                "-"
                            )

                            port = rule.get(
                                "port",
                                "-"
                            )

                            action = rule.get(
                                "action",
                                "-"
                            )

                            st.code(
                                f"Action      : {action}\n"
                                f"Source      : {source}\n"
                                f"Destination : {destination}\n"
                                f"Port        : {port}"
                            )

                        else:

                            st.write(
                                str(rule)
                            )

                elif isinstance(evidence, dict):

                    st.code(
                        "\n".join(
                            f"{key}: {value}"
                            for key, value
                            in evidence.items()
                        )
                    )

                else:

                    st.write(
                        f"**Evidence:** {evidence}"
                    )

                st.warning(
                    f"💡 Recommendation: "
                    f"{recommendation}"
                )

        # ==================================================
        # UNKNOWN
        # ==================================================

        else:

            with st.expander(
                f"⚪ {check}  —  {status}"
            ):

                st.write(
                    f"**Severity:** {severity}"
                )

                st.write(
                    f"**Evidence:** {evidence}"
                )

                st.write(
                    f"**Recommendation:** "
                    f"{recommendation}"
                )

# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "Network Posture Scanner v1.0  •  "
    "Python + Nmap + AWS API Gateway + "
    "AWS Lambda + DynamoDB + Streamlit"
)

st.caption(
    f"Last refreshed: "
    f"{datetime.now().strftime('%d %b %Y, %H:%M:%S')}"
)