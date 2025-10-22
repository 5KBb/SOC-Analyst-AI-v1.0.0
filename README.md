# 🛡️ SOC Analyst AI - Sistema Esperto per Analisi dei Log di Sicurezza

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Production](https://img.shields.io/badge/status-production--ready-green.svg)]()

> **Un analista SOC AI che automatizza l'analisi dei log, il rilevamento delle minacce e la generazione di report professionali**

**SOC Analyst AI** agisce come un esperto analista di sicurezza, interpretando log complessi, identificando minacce reali, correlando eventi e producendo report professionali pronti per clienti e management.

---

## 🎯 Cosa Fa Questo Sistema

Quando ricevi **log grezzi** da firewall, IDS/IPS, EDR, Windows, Linux o altre fonti, il SOC Analyst AI:

1. 🔍 **Analizza e interpreta** automaticamente il formato del log
2. 🚨 **Individua anomalie** e comportamenti sospetti
3. 🎯 **Classifica le minacce** secondo MITRE ATT&CK
4. 🔗 **Correla gli eventi** per ricostruire attacchi complessi
5. ✂️ **Riduce i falsi positivi** con logica intelligente
6. 💡 **Suggerisce contromisure** specifiche e attuabili
7. 📄 **Genera report PDF** professionali e strutturati

---

## ⚡ Quick Start (5 Minuti)

```bash
# 1. Clona o scarica il progetto
cd ai_soc

# 2. Crea ambiente virtuale
python -m venv venv

# 3. Attiva ambiente (Windows)
venv\Scripts\activate
# Oppure (Linux/Mac)
source venv/bin/activate

# 4. Installa dipendenze
pip install -r requirements.txt

# 5. Testa con log di esempio
python soc_cli.py analyze -f data/samples/sample_firewall.log

# 6. Apri il report PDF generato in reports/
```

✅ **Fatto! Il tuo primo report di sicurezza è pronto.**

---

## 🎯 Caratteristiche Principali

### 📋 Multi-Source Log Parsing
Supporta automaticamente 7+ tipi di log di sicurezza:
- ✅ **Firewall**: Cisco ASA, Palo Alto, Fortinet, pfSense, iptables
- ✅ **Windows**: Event Viewer, PowerShell, Sysmon
- ✅ **Linux**: Syslog, Auth.log, Secure
- ✅ **EDR**: CrowdStrike, Carbon Black, Microsoft Defender
- ✅ **Proxy**: Squid, BlueCoat, Zscaler
- ✅ **DNS**: BIND, Windows DNS, Pi-hole
- ✅ **IDS/IPS**: Snort, Suricata, Zeek

### 🔎 Threat Detection Engine
Rileva automaticamente:
- ✅ **Brute Force Attacks** (5+ tentativi falliti)
- ✅ **Port Scanning** (10+ porte diverse)
- ✅ **Lateral Movement** (SMB, RDP, PSExec)
- ✅ **Privilege Escalation** (modifiche gruppi admin)
- ✅ **Data Exfiltration** (upload file sospetti)

### 🎯 MITRE ATT&CK Mapping
Mappa automaticamente le minacce a:
- ✅ **12+ tecniche** pre-configurate
- ✅ **Tattiche** (Initial Access, Execution, Persistence, etc.)
- ✅ **Occorrenze** per ogni tecnica
- ✅ **Descrizioni** dettagliate

### 📄 Professional PDF Reports
Ogni report include:
- 📘 **Executive Summary** - Sintesi per management non tecnico
- 🔍 **Analisi Tecnica** - Dettagli per SOC analysts
- 🎯 **MITRE Mapping** - Classificazione tattiche/tecniche
- 🚨 **Indicatori IoC** - IP, domini, hash da bloccare
- ⏱️ **Timeline Eventi** - Ricostruzione cronologica
- ✅ **Raccomandazioni** - Azioni specifiche da intraprendere
- 📊 **Severity Scoring** - Low/Medium/High/Critical

### 🔌 Integrazioni (Ready)
- ✅ **Threat Intelligence**: VirusTotal, AbuseIPDB, AlienVault OTX, MISP
- ✅ **SIEM**: Elasticsearch, Splunk
- ✅ **Ticketing**: Jira, ServiceNow

---

## 📋 Requisiti di Sistema

- **Python**: 3.11 o superiore
- **OS**: Windows 10/11, Linux, macOS
- **RAM**: 4GB minimo, 8GB raccomandato
- **Spazio Disco**: 500MB per installazione + log
- **Network**: Opzionale (per threat intelligence)

---

## 🚀 Installazione Completa

### Windows

```powershell
# 1. Apri PowerShell nella directory del progetto
cd C:\path\to\ai_soc

# 2. Crea ambiente virtuale
python -m venv venv

# 3. Attiva ambiente
.\venv\Scripts\activate

# 4. Installa dipendenze
pip install -r requirements.txt

# 5. Verifica installazione
python soc_cli.py version
```

### Linux/macOS

```bash
# 1. Naviga nella directory
cd /path/to/ai_soc

# 2. Crea ambiente virtuale
python3 -m venv venv

# 3. Attiva ambiente
source venv/bin/activate

# 4. Installa dipendenze
pip install -r requirements.txt

# 5. Verifica installazione
python soc_cli.py version
```

---

## ⚙️ Configurazione (Opzionale)

Il sistema funziona out-of-the-box con configurazione di default.

Per personalizzare, modifica `config/config.yaml`:

### Threat Intelligence (Opzionale)
```yaml
threat_intel:
  virustotal:
    enable: true
    api_key: "YOUR_VT_API_KEY"
```

### Email Alerts (Opzionale)
```yaml
notifications:
  email:
    enable: true
    smtp_server: "smtp.gmail.com"
    to_addresses:
      - "security-team@company.com"
    severity_filter: ["high", "critical"]
```

---

## 🎯 Utilizzo

### Analisi Singolo File

```bash
# Auto-detection del tipo di log
python soc_cli.py analyze -f /path/to/firewall.log

# Con output personalizzato
python soc_cli.py analyze -f logs.txt -o my_report.pdf

# Specifica tipo di parser
python soc_cli.py analyze -f logs.txt -p windows
```

### Analisi Batch (Directory)

```bash
# Analizza tutti i log in una directory
python soc_cli.py batch -d /var/log/security/

# Con output personalizzato
python soc_cli.py batch -d /logs/ -o combined_report.pdf
```

### Modalità Interattiva

```bash
python soc_cli.py interactive

SOC-AI> analyze /path/to/log.txt
SOC-AI> status
SOC-AI> config
SOC-AI> quit
```

### Tipi di Parser Disponibili

- `auto` - Auto-detection (default) ⭐
- `firewall` - Cisco ASA, Palo Alto, Fortinet, iptables
- `windows` - Windows Event Viewer, PowerShell
- `syslog` - Linux syslog, auth.log
- `edr` - EDR logs (CrowdStrike, Defender)
- `proxy` - Web proxy logs
- `dns` - DNS query logs
- `ids` - IDS/IPS alerts (Snort, Suricata)

---

## 📊 Esempio Output

### Console Output
```
🛡️  SOC Analyst AI - Log Analysis

📁 Analyzing: firewall.log
🔍 Parsing logs...
✅ Parsed 24 events
⚠️  Found 21 suspicious events

🔎 Performing threat analysis...
📊 Analysis Results:
   Threat Score: 5.625/10
   Severity: MEDIUM
   Attack Patterns: 1

🚨 Detecting Indicators of Compromise...
   Found 5 unique IOCs

🎯 Mapping to MITRE ATT&CK...
   Mapped to 1 techniques

📄 Generating PDF report...
✅ Report generated: reports/soc_report_20251022_131834.pdf

📋 SUMMARY
────────────────────────────────────────────────────────────
Severity Level: MEDIUM
Threat Score: 5.625/10
Suspicious Events: 21/24

⚠️  DETECTED ATTACK PATTERNS:
   • Lateral Movement [CRITICAL]

🎯 TOP MITRE ATT&CK TECHNIQUES:
   • T1021: Remote Services (4x)

🚨 HIGH-SEVERITY IOCs:
   • [IP] 45.76.123.45
   • [IP] 203.0.113.45

✅ TOP RECOMMENDATIONS:
   ⚠️ CRITICAL: Isolate affected systems immediately
   🔐 Force password reset for affected accounts
   🔎 Conduct full forensic investigation
────────────────────────────────────────────────────────────
```

### PDF Report Sections

Il report PDF include:

1. **📘 Executive Summary** - Sintesi non tecnica per dirigenti
2. **🔍 Analisi Tecnica** - Statistiche eventi, pattern rilevati
3. **🎯 MITRE ATT&CK** - Tattiche e tecniche identificate
4. **🚨 IoC List** - Indirizzi IP, domini, hash da bloccare
5. **⏱️ Timeline** - Sequenza cronologica degli eventi
6. **✅ Raccomandazioni** - Azioni specifiche da intraprendere
7. **📝 Conclusione** - Stato finale e next steps

## 🔧 Architettura

```
ai_soc/
├── src/
│   ├── parsers/          # Log parsers multi-formato
│   ├── analyzers/        # Threat detection engine
│   ├── correlation/      # Event correlation
│   ├── mitre/           # MITRE ATT&CK integration
│   ├── integrations/    # SIEM, TI, Ticketing
│   ├── reporting/       # PDF report generator
│   └── utils/           # Utilities
├── data/
│   ├── ioc_database/    # IoC storage
│   ├── rules/           # Detection rules (Sigma, YARA)
│   └── templates/       # Report templates
└── tests/               # Unit tests
```

## 🧪 Testing

```bash
# Esegui tutti i test
pytest

# Test con coverage
pytest --cov=src tests/

# Test specifico
pytest tests/test_parsers.py
```

## 📚 Documentazione

Per documentazione completa, consulta la [Wiki](docs/wiki.md)

## 🤝 Contributi

I contributi sono benvenuti! Vedi [CONTRIBUTING.md](CONTRIBUTING.md)

## 📄 Licenza

Questo progetto è rilasciato sotto licenza MIT. Vedi [LICENSE](LICENSE)

## 👨‍💻 Autore

Sviluppato per supportare Security Operations Centers nell'analisi automatizzata delle minacce.

---

**⚠️ Disclaimer**: Questo tool è progettato per uso legittimo in ambito di sicurezza informatica. L'autore non è responsabile per usi impropri.

