# 🎉 BENVENUTO AL TUO SOC ANALYST AI!

## ✅ Sistema Installato e Testato con Successo

Il tuo **SOC Analyst AI** è operativo e pronto all'uso!

---

## 🚀 INIZIA SUBITO IN 3 PASSI

### 1️⃣ Attiva l'Ambiente Virtuale

```powershell
# Windows PowerShell
.\venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 2️⃣ Analizza i Tuoi Log

```bash
# Esempio: Analizza firewall logs
python soc_cli.py analyze -f C:\logs\firewall.log

# Esempio: Analizza Windows Event logs
python soc_cli.py analyze -f C:\Windows\System32\winevt\Logs\Security.evtx -p windows

# Esempio: Analizza tutti i log in una directory
python soc_cli.py batch -d C:\logs\security\
```

### 3️⃣ Apri il Report PDF

I report vengono salvati automaticamente in `reports/`

---

## 📚 DOCUMENTAZIONE DISPONIBILE

Scegli la guida che preferisci:

### 🇮🇹 In Italiano
- **[GUIDA_ITALIANA.md](GUIDA_ITALIANA.md)** - Guida completa in italiano con esempi pratici

### 🇬🇧 In English
- **[QUICKSTART.md](QUICKSTART.md)** - Quick start guide (5 minuti)
- **[README.md](README.md)** - Documentazione completa
- **[INSTALLATION_COMPLETE.md](INSTALLATION_COMPLETE.md)** - Dettagli installazione

### 📊 Per Sviluppatori
- **[PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)** - Architettura e statistiche del progetto

---

## ✅ TEST COMPLETATI

Il sistema è stato testato e funziona correttamente:

### ✅ Test #1: Firewall Logs
```bash
python soc_cli.py analyze -f data/samples/sample_firewall.log
```
- **Eventi parsati**: 24
- **Minacce rilevate**: Lateral Movement (CRITICAL)
- **Report**: reports/soc_report_20251022_131834.pdf ✅

### ✅ Test #2: Windows Event Logs
```bash
python soc_cli.py analyze -f data/samples/sample_windows.log
```
- **Eventi parsati**: 11
- **Minacce rilevate**: Privilege Escalation (HIGH)
- **Report**: reports/windows_analysis.pdf ✅

---

## 🎯 COSA PUÒ FARE IL TUO SOC AI

### 🔍 Analizza Automaticamente
- ✅ Firewall logs (Cisco, Palo Alto, Fortinet, iptables)
- ✅ Windows Event Viewer
- ✅ Linux Syslog
- ✅ EDR logs (CrowdStrike, Defender, Carbon Black)
- ✅ Web Proxy logs
- ✅ DNS logs
- ✅ IDS/IPS alerts (Snort, Suricata, Zeek)

### 🚨 Rileva Minacce
- ✅ **Brute Force Attacks** - Tentativi ripetuti di login
- ✅ **Port Scanning** - Scansione di porte di rete
- ✅ **Lateral Movement** - Movimento laterale nella rete
- ✅ **Privilege Escalation** - Escalation di privilegi
- ✅ **Data Exfiltration** - Esfiltrazione di dati

### 🎯 Mappa a MITRE ATT&CK
- ✅ T1110 - Brute Force
- ✅ T1046 - Network Service Scanning
- ✅ T1021 - Remote Services (Lateral Movement)
- ✅ T1068 - Privilege Escalation
- ✅ T1003 - Credential Dumping
- ✅ E molte altre...

### 📄 Genera Report Professionali
- ✅ **Executive Summary** (per management)
- ✅ **Analisi Tecnica** (per SOC analysts)
- ✅ **MITRE ATT&CK Mapping**
- ✅ **Indicatori di Compromissione (IoC)**
- ✅ **Timeline Eventi**
- ✅ **Raccomandazioni Operative**

---

## 💡 ESEMPI PRATICI

### Scenario 1: Attacco SSH Brute Force

**Situazione**: Ricevi alert per tentativi ripetuti di login SSH

**Azione**:
```bash
python soc_cli.py analyze -f /var/log/auth.log
```

**Cosa fa l'AI**:
1. Rileva 10+ tentativi falliti dallo stesso IP
2. Classifica come "Brute Force Attack"
3. Assegna severity: HIGH
4. Mappa a MITRE T1110
5. Raccomanda: "Blocca IP X.X.X.X al firewall"

### Scenario 2: Privilege Escalation su Windows

**Situazione**: Attività sospetta su server Windows

**Azione**:
```bash
python soc_cli.py analyze -f Security.evtx -p windows
```

**Cosa fa l'AI**:
1. Rileva Event ID 4732 (utente aggiunto a gruppo Administrators)
2. Classifica come "Privilege Escalation"
3. Assegna severity: HIGH
4. Mappa a MITRE T1068
5. Raccomanda: "Verifica e revoca privilegi per utente NewAdmin"

### Scenario 3: Port Scanning Detection

**Situazione**: Traffico sospetto rilevato dal firewall

**Azione**:
```bash
python soc_cli.py analyze -f firewall.log
```

**Cosa fa l'AI**:
1. Rileva connessioni a 20+ porte diverse dallo stesso IP
2. Classifica come "Port Scanning"
3. Assegna severity: MEDIUM
4. Mappa a MITRE T1046
5. Raccomanda: "Blocca IP e rivedi firewall rules"

---

## ⚙️ CONFIGURAZIONE AVANZATA (Opzionale)

### Abilita Threat Intelligence

Modifica `config/config.yaml`:

```yaml
threat_intel:
  virustotal:
    enable: true
    api_key: "LA_TUA_API_KEY"
```

### Abilita Email Alerts

```yaml
notifications:
  email:
    enable: true
    smtp_server: "smtp.gmail.com"
    to_addresses:
      - "security-team@azienda.com"
    severity_filter: ["high", "critical"]
```

### Integra con SIEM

```yaml
siem:
  elasticsearch:
    enable: true
    host: "localhost"
    port: 9200
```

---

## 🆘 AIUTO E SUPPORTO

### Problemi Comuni

**"No events parsed"**
- Verifica formato log
- Prova con `-p <parser-type>`
- Esempio: `python soc_cli.py analyze -f logs.txt -p firewall`

**"Import error"**
- Assicurati che l'ambiente virtuale sia attivo
- Reinstalla: `pip install -r requirements.txt`

**"PDF generation failed"**
- Aggiorna: `pip install --upgrade reportlab pillow`

### Comandi Utili

```bash
# Mostra versione
python soc_cli.py version

# Mostra help
python soc_cli.py --help

# Help per comando specifico
python soc_cli.py analyze --help
python soc_cli.py batch --help

# Modalità interattiva
python soc_cli.py interactive
```

---

## 📁 STRUTTURA DIRECTORY

```
ai_soc/
├── soc_cli.py              # CLI principale (INIZIA DA QUI)
├── config/
│   └── config.yaml         # Configurazione
├── data/
│   └── samples/            # Log di esempio per test
│       ├── sample_firewall.log
│       └── sample_windows.log
├── reports/                # Report PDF generati
│   ├── soc_report_....pdf
│   └── windows_analysis.pdf
├── src/                    # Codice sorgente
├── GUIDA_ITALIANA.md       # 🇮🇹 Guida completa italiana
├── QUICKSTART.md           # 🇬🇧 Quick start inglese
└── README.md               # 🇬🇧 Documentazione completa
```

---

## 🎓 IMPARA DI PIÙ

### MITRE ATT&CK Framework
Il sistema mappa automaticamente le minacce al framework MITRE ATT&CK, lo standard globale per la classificazione di tattiche e tecniche degli attaccanti.

**Esempio**:
- **T1110** = Brute Force (Credential Access)
- **T1046** = Network Service Scanning (Discovery)
- **T1021** = Remote Services (Lateral Movement)

### Severity Levels
Il sistema assegna automaticamente un livello di gravità:

- **🟢 LOW (0-3)**: Monitoraggio standard
- **🟡 MEDIUM (4-6)**: Revisione richiesta entro 24-48h
- **🟠 HIGH (7-8)**: Azione richiesta entro poche ore
- **🔴 CRITICAL (9-10)**: Risposta immediata!

---

## 🚀 PROSSIMI PASSI

1. ✅ **Testa con i tuoi log reali**
   ```bash
   python soc_cli.py analyze -f /path/to/your/real/logs.log
   ```

2. ✅ **Personalizza la configurazione** in `config/config.yaml`

3. ✅ **Integra con i tuoi sistemi** (SIEM, Threat Intel, Ticketing)

4. ✅ **Automatizza l'analisi** con cron job o task scheduler

5. ✅ **Leggi la documentazione completa** per funzionalità avanzate

---

## 📞 CONTATTI

- 📖 Documentazione: Vedi file `.md` nella directory
- 🐛 Bug report: Crea una issue
- 💡 Feature request: Apri una discussion

---

## 🏆 HAI COMPLETATO

✅ Installazione Python  
✅ Ambiente virtuale configurato  
✅ Dipendenze installate  
✅ Sistema testato con successo  
✅ Report PDF generati  

---

**🎉 SEI PRONTO A PROTEGGERE LA TUA INFRASTRUTTURA!**

**Inizia subito**:
```bash
# Attiva ambiente
.\venv\Scripts\activate

# Analizza i tuoi log
python soc_cli.py analyze -f C:\path\to\your\logs.log
```

---

*SOC Analyst AI v1.0.0*  
*Status: ✅ Operational*  
*Installation Date: 2025-10-22*  

**Buon Threat Hunting! 🔍🛡️**
