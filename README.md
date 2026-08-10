# 🛡️ Network Posture Scanner

A lightweight network security posture assessment tool that discovers network devices, identifies open ports and services, analyzes firewall configurations, performs CIS-inspired security checks, stores scan results in AWS, and presents the results through a Streamlit dashboard.

This project demonstrates an end-to-end security assessment workflow using Python, Nmap, AWS Lambda, API Gateway, DynamoDB, REST APIs, and Streamlit.

---

## 📌 Features

- Network device discovery using Nmap
- IP address and hostname detection
- Open port and service detection
- Service banner and version detection
- Firewall configuration parsing
- Firewall rule analysis
- CIS-inspired security benchmark checks
- PASS / FAIL security assessment
- Evidence and recommendations for failed checks
- JSON report generation
- AWS cloud integration
- REST API endpoints
- DynamoDB scan result storage
- API key authentication
- Streamlit security dashboard
- Latest scan retrieval through backend APIs

---

## 🏗️ Architecture

```text
                  Network Posture Scanner
                           │
                           │ POST /scan
                           ▼
                    Amazon API Gateway
                           │
                           ▼
              NetworkPostureScannerAPI
                     AWS Lambda
                           │
                           ▼
                       DynamoDB
                NetworkPostureScanner
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
         /devices    /firewall-rules  /cis-results
              │            │            │
              ▼            ▼            ▼
       GetDevices      GetFirewall    GetCISResults
         Lambda          Lambda          Lambda
              │            │            │
              └────────────┼────────────┘
                           │
                           ▼
                  Streamlit Dashboard
```

---

## 🔍 Network Discovery

The scanner uses Nmap to discover devices and identify:

- IP address
- Hostname
- Device state
- Open ports
- Running services
- Service banners
- Product information
- Version information

Example scan result:

```text
IP Address : 127.0.0.1
Hostname   : kubernetes.docker.internal
Status     : up

Open Ports:
135   msrpc          Microsoft Windows RPC
445   microsoft-ds   Unknown
1029  msrpc          Microsoft Windows RPC
3306  mysql          MySQL 8.0.40
```

---

## 🔥 Firewall Analysis

The scanner analyzes firewall configuration and extracts:

- Firewall rules
- Source
- Destination
- Port
- Action
- Logging status
- Syslog server
- Default inbound policy
- Default outbound policy

Example:

```text
Firewall Rules   : 7
Logging Enabled  : True
Syslog Server    : 192.168.1.100
Default Inbound  : DENY
Default Outbound : ALLOW
```

---

## 🛡️ CIS-Inspired Security Checks

The scanner currently performs the following security checks:

| Check | Severity |
|---|---|
| Telnet Disabled | HIGH |
| FTP Disabled | HIGH |
| SSH Restricted | HIGH |
| Sensitive Ports Protected | HIGH |
| Logging Enabled | MEDIUM |
| Default Outbound Policy | MEDIUM |

Each check provides:

- Check name
- Status
- Severity
- Evidence
- Recommendation

Example:

```text
Check          : Sensitive Ports Protected
Status         : FAIL
Severity       : HIGH

Evidence       : ALLOW rule for port 3306 from ANY

Recommendation : Restrict sensitive ports to trusted networks.
```

---

## ☁️ AWS Integration

The project uses AWS services to store and retrieve scan results.

### AWS Services

- Amazon API Gateway
- AWS Lambda
- Amazon DynamoDB

### Data Flow

```text
Python Scanner
      │
      │ JSON report
      ▼
API Gateway
      │
      ▼
POST /scan
      │
      ▼
AWS Lambda
      │
      ▼
DynamoDB
```

The scanner uploads the complete scan report to AWS.

Example response:

```json
{
    "message": "Scan stored successfully",
    "scan_id": "example-scan-id"
}
```

---

# 🔌 REST API

The backend exposes four main endpoints.

| Method | Endpoint | Description |
|---|---|---|
| POST | `/scan` | Upload a new network scan |
| GET | `/devices` | Retrieve devices from the latest scan |
| GET | `/firewall-rules` | Retrieve firewall configuration from the latest scan |
| GET | `/cis-results` | Retrieve CIS benchmark results from the latest scan |

### Authentication

API Gateway API keys are used to protect the API endpoints.

The API key is supplied using the following HTTP header:

```text
x-api-key: YOUR_API_KEY
```

API keys and credentials are not included in this repository.

---

# 📊 Streamlit Dashboard

The project includes a Streamlit dashboard for viewing the latest network security posture.

The dashboard displays:

### Devices

- Total devices
- IP addresses
- Hostnames
- Device status
- Open ports
- Services

### Firewall

- Default inbound policy
- Default outbound policy
- Logging status
- Syslog server
- Firewall rules

### CIS Results

- PASS checks
- FAIL checks
- Severity
- Evidence
- Recommendations

Example dashboard summary:

```text
┌──────────────┬──────────────┬──────────────┬──────────────┐
│   Devices    │  Open Ports  │ PASS Checks  │ FAIL Checks  │
├──────────────┼──────────────┼──────────────┼──────────────┤
│      1       │      4       │      4       │      2       │
└──────────────┴──────────────┴──────────────┴──────────────┘
```

---

# 📁 Project Structure

```text
network-posture-scanner/
│
├── config/
│   ├── __init__.py
│   ├── settings.py
│   └── sample_firewall.conf
│
├── dashboard/
│   ├── app.py
│   ├── api.py
│   └── config.py
│
├── lambda/
│   ├── NetworkPostureScannerAPI/
│   │   └── lambda_function.py
│   │
│   ├── GetDevicesLambda/
│   │   └── lambda_function.py
│   │
│   ├── GetFirewallRulesLambda/
│   │   └── lambda_function.py
│   │
│   └── GetCISResultsLambda/
│       └── lambda_function.py
│
├── scanner/
│   ├── main.py
│   ├── network.py
│   ├── config_parser.py
│   ├── benchmark_checks.py
│   ├── aws_client.py
│   └── utils.py
│
├── reports/
│
├── .gitignore
├── requirements.txt
└── README.md
```

---

# 🛠️ Technology Stack

### Programming

- Python
- JSON
- REST APIs

### Network Security

- Nmap
- Network discovery
- Port scanning
- Service detection
- Firewall configuration analysis
- CIS-inspired security checks

### AWS

- Amazon API Gateway
- AWS Lambda
- Amazon DynamoDB

### Frontend

- Streamlit
- Pandas

### Development

- Git
- GitHub
- VS Code

---

# ⚙️ Installation

## 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/network-posture-scanner.git
cd network-posture-scanner
```

---

## 2. Create a virtual environment

### Windows

```bash
python -m venv venv
```

Activate using Git Bash:

```bash
source venv/Scripts/activate
```

Or using Command Prompt:

```cmd
venv\Scripts\activate
```

---

## 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Install Nmap

Nmap is required for network discovery and service detection.

Verify the installation:

```bash
nmap --version
```

Make sure Nmap is available in the system PATH.

---

# 🔐 Environment Configuration

API credentials are stored outside the repository.

Create the following file:

```text
dashboard/.env
```

Add:

```env
API_BASE_URL=https://YOUR_API_GATEWAY_URL/prod
API_KEY=YOUR_API_KEY
```

Do not commit this file to GitHub.

The `.gitignore` file excludes environment files and other sensitive information.

---

# 🚀 Running the Scanner

From the project root:

```bash
python -m scanner.main
```

The scanner performs the following workflow:

```text
1. Network discovery
2. Port and service detection
3. Firewall configuration parsing
4. CIS-inspired security checks
5. JSON report generation
6. AWS upload
```

Reports are generated in:

```text
reports/
```

Example:

```text
reports/
├── scan_results.json
├── firewall_rules.json
└── cis_results.json
```

---

# 📊 Running the Dashboard

Navigate to the dashboard:

```bash
cd dashboard
```

Start Streamlit:

```bash
streamlit run app.py
```

The dashboard will be available at:

```text
http://localhost:8501
```

---

# 📡 Example Scanner Output

```text
============================================================
                NETWORK POSTURE SCANNER v1.0
============================================================

Target        : 127.0.0.1

============================================================
                     SCAN SUMMARY
============================================================

Devices Found      : 1
Open Ports Found   : 4
Firewall Rules     : 7
PASS Checks        : 4
FAIL Checks        : 2

============================================================
                         AWS UPLOAD
============================================================

Status Code : 200

Response:
{
    "message": "Scan stored successfully",
    "scan_id": "example-scan-id"
}
```

---

# 🔒 Security Considerations

The project follows basic security practices:

- API keys are stored using environment variables.
- `.env` files are excluded from Git.
- Virtual environments are excluded from Git.
- Python cache files are excluded from Git.
- Generated reports are excluded from Git.
- AWS credentials are not stored in source code.
- API Gateway API key authentication is used for protected endpoints.

---

# 🔮 Future Improvements

Potential future improvements include:

- ARP-based device discovery
- Larger network range scanning
- MAC address and vendor identification
- Additional CIS benchmark checks
- Historical scan comparison
- Security posture scoring
- Risk-based visualization
- Scheduled automated scans
- CloudWatch monitoring
- Exportable security reports
- Docker deployment
- CI/CD integration

---

# ⚠️ Disclaimer

This project is intended for authorized network security assessment and educational purposes.

Only scan systems and networks that you own or have explicit permission to assess.

---

# 👨‍💻 Author

**Rishabh Verma**

Computer Science Engineering  
Dronacharya College of Engineering

---

## ⭐ Project Summary

The Network Posture Scanner combines network security assessment, cloud infrastructure, REST APIs, and visualization into a single end-to-end security posture monitoring solution.

```text
Python
  +
Nmap
  +
Network Security
  +
AWS Lambda
  +
API Gateway
  +
DynamoDB
  +
REST APIs
  +
Streamlit
```