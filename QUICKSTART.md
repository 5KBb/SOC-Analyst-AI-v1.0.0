# 🚀 Quick Start Guide - SOC Analyst AI

## ⚡ 5-Minute Setup

### Step 1: Install Dependencies

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Test with Sample Logs

```bash
# Analyze sample firewall logs
python soc_cli.py analyze -f data/samples/sample_firewall.log

# Analyze sample Windows Event logs
python soc_cli.py analyze -f data/samples/sample_windows.log
```

### Step 3: View Generated Report

The PDF report will be generated in the `reports/` directory with a timestamp:
- `reports/soc_report_20241022_120000.pdf`

Open it to see the full professional security analysis!

---

## 📝 Common Usage Examples

### Analyze a Single Log File

```bash
# Auto-detect log type
python soc_cli.py analyze -f /path/to/firewall.log

# Specify parser type
python soc_cli.py analyze -f /path/to/logs.txt -p windows

# Custom output path
python soc_cli.py analyze -f /path/to/logs.txt -o my_report.pdf
```

### Batch Analysis (Multiple Files)

```bash
# Analyze all logs in a directory
python soc_cli.py batch -d /var/log/security/

# With custom output
python soc_cli.py batch -d /var/log/ -o combined_report.pdf
```

### Interactive Mode

```bash
python soc_cli.py interactive
```

Then type:
- `analyze /path/to/log.txt` - Analyze a file
- `status` - Show system status
- `config` - Show configuration
- `help` - Show available commands
- `quit` - Exit

---

## 🎯 What Gets Analyzed?

The AI SOC Analyst automatically detects and analyzes:

### 🔥 Attack Patterns
- ✅ Brute Force Attacks
- ✅ Port Scanning
- ✅ Lateral Movement
- ✅ Privilege Escalation
- ✅ Data Exfiltration
- ✅ Malware Execution

### 🎯 MITRE ATT&CK Mapping
- ✅ T1110 - Brute Force
- ✅ T1046 - Network Service Scanning
- ✅ T1021 - Remote Services (Lateral Movement)
- ✅ T1003 - Credential Dumping
- ✅ T1059 - Command Execution (PowerShell)
- ✅ And many more...

### 🚨 IOCs (Indicators of Compromise)
- ✅ Malicious IPs
- ✅ Suspicious Domains
- ✅ File Hashes
- ✅ Malicious Processes

---

## 📊 Report Sections

Every PDF report includes:

1. **📘 Executive Summary** - Non-technical overview for management
2. **🔍 Technical Analysis** - Detailed event statistics and patterns
3. **🎯 MITRE ATT&CK Mapping** - Threat categorization
4. **🚨 Indicators of Compromise** - Extracted IOCs
5. **⏱️ Event Timeline** - Chronological event sequence
6. **✅ Recommendations** - Actionable security measures
7. **📝 Conclusion** - Final assessment and next steps

---

## ⚙️ Configuration

Edit `config/config.yaml` to customize:

### Enable Threat Intelligence Integration

```yaml
threat_intel:
  enable: true
  
  virustotal:
    enable: true
    api_key: "YOUR_VT_API_KEY"
  
  abuseipdb:
    enable: true
    api_key: "YOUR_ABUSEIPDB_KEY"
```

### Enable SIEM Integration

```yaml
siem:
  elasticsearch:
    enable: true
    host: "localhost"
    port: 9200
    index: "soc-alerts"
```

### Enable Ticketing (Jira/ServiceNow)

```yaml
ticketing:
  jira:
    enable: true
    url: "https://your-instance.atlassian.net"
    username: "your-email@company.com"
    api_token: "YOUR_JIRA_TOKEN"
    project_key: "SEC"
    auto_create: true
```

---

## 🎨 Supported Log Formats

### Firewall Logs
- ✅ Cisco ASA
- ✅ Palo Alto Networks
- ✅ Fortinet FortiGate
- ✅ pfSense
- ✅ iptables

### Windows Logs
- ✅ Windows Event Viewer (Security, System, Application)
- ✅ PowerShell logs
- ✅ Sysmon

### Linux Logs
- ✅ Syslog
- ✅ Auth.log
- ✅ Secure log
- ✅ Messages

### Security Tools
- ✅ IDS/IPS (Snort, Suricata, Zeek)
- ✅ EDR (CrowdStrike, Carbon Black, Defender)
- ✅ Web Proxy (Squid, BlueCoat, Zscaler)
- ✅ DNS logs (BIND, Windows DNS, Pi-hole)

---

## 🔥 Real-World Example

Let's say you have suspicious SSH login attempts:

```bash
python soc_cli.py analyze -f /var/log/auth.log
```

**The AI will:**
1. ✅ Parse the auth.log
2. ✅ Detect 10+ failed SSH attempts from same IP
3. ✅ Classify as **Brute Force Attack**
4. ✅ Map to MITRE T1110
5. ✅ Extract malicious IP as IOC
6. ✅ Assign severity: **HIGH**
7. ✅ Generate recommendations:
   - Block IP at firewall
   - Enable MFA
   - Implement account lockout policy
8. ✅ Create professional PDF report

---

## 🆘 Troubleshooting

### Import Errors

```bash
# Make sure you're in the virtual environment
venv\Scripts\activate

# Reinstall dependencies
pip install -r requirements.txt
```

### No Events Parsed

- Check log file format
- Try specifying parser: `-p firewall` or `-p windows`
- Check log file encoding (should be UTF-8)

### PDF Generation Fails

```bash
# Reinstall reportlab
pip install --upgrade reportlab
```

---

## 📚 Next Steps

1. ✅ Test with your real log files
2. ✅ Customize `config/config.yaml`
3. ✅ Set up threat intelligence feeds
4. ✅ Integrate with your SIEM
5. ✅ Automate with cron jobs/scheduled tasks

---

## 🤝 Need Help?

- 📖 Read full documentation: `README.md`
- 🐛 Found a bug? Open an issue
- 💡 Feature request? Let us know!

---

**Happy Threat Hunting! 🎯🛡️**
