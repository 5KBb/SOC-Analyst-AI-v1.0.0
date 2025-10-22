# 🛡️ SOC Analyst AI - Guida Italiana

## 📘 Benvenuto!

Hai ora a disposizione un **analista SOC AI** completo che analizza automaticamente i log di sicurezza e genera report professionali in formato PDF.

---

## 🚀 Come Iniziare

### 1. Attiva l'Ambiente Virtuale

```powershell
# Su Windows PowerShell
.\venv\Scripts\activate

# Su Linux/Mac
source venv/bin/activate
```

### 2. Analizza un File di Log

```bash
# Analisi automatica (rileva il tipo di log automaticamente)
python soc_cli.py analyze -f percorso/del/tuo/file.log

# Con nome personalizzato per il report
python soc_cli.py analyze -f percorso/del/file.log -o il_mio_report.pdf
```

---

## 📊 Cosa Fa l'AI SOC Analyst?

### Analizza Automaticamente

1. **Parsing Intelligente**: Riconosce automaticamente il formato del log (Firewall, Windows, Linux, EDR, ecc.)

2. **Rilevamento Minacce**: Identifica pattern di attacco:
   - ✅ Brute Force (tentativi ripetuti di login)
   - ✅ Port Scanning (scansione porte)
   - ✅ Lateral Movement (movimento laterale nella rete)
   - ✅ Privilege Escalation (escalation privilegi)
   - ✅ Data Exfiltration (esfiltrazione dati)

3. **Mappatura MITRE ATT&CK**: Classifica le minacce secondo il framework MITRE
   - T1110: Brute Force
   - T1046: Network Service Scanning
   - T1021: Remote Services
   - E molti altri...

4. **Estrazione IoC**: Identifica indicatori di compromissione:
   - Indirizzi IP sospetti
   - Domini malevoli
   - Hash di file
   - Processi sospetti

5. **Report Professionale PDF**: Genera un report completo con:
   - 📘 Executive Summary (per il management)
   - 🔍 Analisi Tecnica Dettagliata
   - 🎯 Mappatura MITRE ATT&CK
   - 🚨 IoC Identificati
   - ⏱️ Timeline Eventi
   - ✅ Raccomandazioni Operative

---

## 📝 Esempi Pratici

### Esempio 1: Analizzare Log Firewall

```bash
python soc_cli.py analyze -f /var/log/firewall.log
```

**Cosa fa l'AI:**
- Rileva automaticamente che è un log firewall
- Identifica tentativi di connessione bloccati
- Conta tentativi ripetuti dallo stesso IP
- Se rileva 5+ tentativi = **Brute Force Attack**
- Assegna severity: HIGH/CRITICAL
- Genera raccomandazioni: "Blocca IP X.X.X.X al firewall"

### Esempio 2: Analizzare Log Windows

```bash
python soc_cli.py analyze -f C:\Windows\System32\winevt\Logs\Security.evtx -p windows
```

**Cosa fa l'AI:**
- Parser specifico per Windows Event Viewer
- Rileva Event ID critici:
  - 4625: Failed logon (login falliti)
  - 1102: Audit log cleared (log cancellati - **CRITICO**)
  - 4720: User account created
  - 4732: User added to admin group
- Mappa a tecniche MITRE
- Suggerisce azioni correttive

### Esempio 3: Analizzare Tutti i Log in una Directory

```bash
python soc_cli.py batch -d /var/log/security/
```

**Cosa fa l'AI:**
- Analizza tutti i file .log nella directory
- Combina i risultati in un unico report
- Correla eventi tra diversi log
- Ricostruisce la timeline completa dell'attacco

---

## 🎯 Interpretare i Risultati

### Threat Score (Punteggio Minaccia)

- **0-3**: 🟢 LOW - Nessuna minaccia significativa
- **4-6**: 🟡 MEDIUM - Attività sospette, richiede revisione
- **7-8**: 🟠 HIGH - Minaccia probabile, azione richiesta
- **9-10**: 🔴 CRITICAL - Attacco in corso, azione immediata!

### Severity Levels (Livelli di Gravità)

- **LOW**: Monitoraggio standard
- **MEDIUM**: Revisione entro 24-48 ore
- **HIGH**: Azione richiesta entro poche ore
- **CRITICAL**: Risposta immediata, escalation al SOC Tier 2

---

## 📁 Dove Trovo i Report?

I report PDF vengono salvati nella cartella `reports/`:

```
ai_soc/
└── reports/
    ├── soc_report_20251022_131834.pdf
    ├── windows_analysis.pdf
    └── il_mio_report.pdf
```

---

## ⚙️ Configurazione Avanzata

### Abilitare Threat Intelligence

Modifica `config/config.yaml`:

```yaml
threat_intel:
  enable: true
  
  virustotal:
    enable: true
    api_key: "LA_TUA_API_KEY_VT"
  
  abuseipdb:
    enable: true
    api_key: "LA_TUA_API_KEY_ABUSEIPDB"
```

Questo permette all'AI di verificare automaticamente IP e domini contro database di minacce globali.

### Abilitare Notifiche Email

```yaml
notifications:
  email:
    enable: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    username: "tuo-email@gmail.com"
    password: "tua-password-app"
    to_addresses:
      - "team-security@azienda.com"
    severity_filter: ["high", "critical"]
```

Riceverai email automatiche solo per alert HIGH e CRITICAL.

---

## 🔍 Modalità Interattiva

```bash
python soc_cli.py interactive
```

Comandi disponibili:
- `analyze /path/to/file.log` - Analizza un file
- `status` - Mostra stato del sistema
- `config` - Mostra configurazione
- `help` - Mostra aiuto
- `quit` - Esci

---

## 💡 Casi d'Uso Reali

### Caso 1: Rilevare Attacco SSH Brute Force

**Scenario**: Il server Linux sta subendo tentativi ripetuti di login SSH.

**Azione**:
```bash
python soc_cli.py analyze -f /var/log/auth.log
```

**Risultato AI**:
- ✅ Rileva 15 tentativi falliti da IP 203.0.113.45
- ✅ Classifica come "Brute Force Attack"
- ✅ Severity: HIGH
- ✅ MITRE: T1110
- ✅ Raccomanda:
  - Blocca IP 203.0.113.45
  - Abilita fail2ban
  - Implementa autenticazione a due fattori

### Caso 2: Rilevare Privilege Escalation su Windows

**Scenario**: Attività sospetta su server Windows.

**Azione**:
```bash
python soc_cli.py analyze -f Security.evtx -p windows
```

**Risultato AI**:
- ✅ Rileva Event ID 4732 (utente aggiunto a gruppo Administrators)
- ✅ Rileva Event ID 4672 (privilegi speciali assegnati)
- ✅ Classifica come "Privilege Escalation"
- ✅ Severity: HIGH
- ✅ MITRE: T1068
- ✅ Raccomanda:
  - Verifica utente "NewAdmin"
  - Revoca privilegi amministrativi
  - Indaga ulteriormente

### Caso 3: Log Cancellati (Possibile Cover-Up)

**Scenario**: Qualcuno ha cancellato i log di sicurezza.

**Risultato AI**:
- ✅ Rileva Event ID 1102 (Audit log cleared)
- ✅ Severity: **CRITICAL**
- ✅ Raccomanda:
  - 🚨 ALLARME: Possibile tentativo di coprire tracce
  - Verifica identità amministratore
  - Recupera backup dei log
  - Escalation immediata

---

## 📊 Struttura del Report PDF

### 1. Copertina
- Titolo
- Data e ora generazione
- Metadata (fonte log, tipo, analista)

### 2. Executive Summary 📘
**Per chi**: Management, dirigenti non tecnici  
**Contenuto**: 
- Sintesi non tecnica dell'incidente
- Livello di gravità
- Impatto potenziale sull'organizzazione

### 3. Analisi Tecnica 🔍
**Per chi**: Team SOC, analisti di sicurezza  
**Contenuto**:
- Statistiche eventi
- Pattern di attacco rilevati
- Dettagli tecnici completi

### 4. MITRE ATT&CK Mapping 🎯
**Per chi**: Security architects, threat hunters  
**Contenuto**:
- Tecniche utilizzate dall'attaccante
- Tattiche (Initial Access, Execution, ecc.)
- Frequenza di ogni tecnica

### 5. Indicatori di Compromissione 🚨
**Per chi**: Firewall admin, network security  
**Contenuto**:
- IP malevoli da bloccare
- Domini sospetti
- Hash di malware
- Processi da terminare

### 6. Timeline ⏱️
**Per chi**: Incident responders  
**Contenuto**:
- Sequenza cronologica degli eventi
- Ricostruzione dell'attacco
- Correlazione temporale

### 7. Raccomandazioni ✅
**Per chi**: Tutti  
**Contenuto**:
- Azioni immediate da intraprendere
- Misure preventive future
- Best practices

### 8. Conclusione 📝
**Stato finale**:
- ✅ Risolto
- ⚠️ In corso
- 🔍 Monitoraggio continuo
- 🚨 Escalation a Tier 2

---

## 🆘 Risoluzione Problemi

### Problema: "No events parsed"

**Causa**: Formato log non riconosciuto  
**Soluzione**: 
```bash
# Specifica il tipo di parser
python soc_cli.py analyze -f file.log -p firewall
# oppure
python soc_cli.py analyze -f file.log -p windows
```

### Problema: "Import error: loguru"

**Causa**: Dipendenze non installate  
**Soluzione**:
```bash
pip install -r requirements.txt
```

### Problema: PDF non si genera

**Causa**: reportlab non installato correttamente  
**Soluzione**:
```bash
pip install --upgrade reportlab pillow
```

---

## 📚 Formati Log Supportati

### Firewall
- ✅ Cisco ASA
- ✅ Palo Alto Networks
- ✅ Fortinet FortiGate
- ✅ pfSense
- ✅ iptables (Linux)

### Windows
- ✅ Event Viewer (Security, System, Application)
- ✅ PowerShell Logs
- ✅ Sysmon

### Linux
- ✅ Syslog
- ✅ Auth.log
- ✅ /var/log/secure
- ✅ /var/log/messages

### Security Tools
- ✅ IDS/IPS: Snort, Suricata, Zeek
- ✅ EDR: CrowdStrike, Carbon Black, Microsoft Defender
- ✅ Proxy: Squid, BlueCoat, Zscaler
- ✅ DNS: BIND, Windows DNS, Pi-hole

---

## 🎓 Glossario

**IoC (Indicator of Compromise)**: Indicatore di compromissione, evidenza che un sistema è stato attaccato (es: IP malevolo, hash malware)

**MITRE ATT&CK**: Framework globale che categorizza le tattiche e tecniche utilizzate dagli attaccanti

**Brute Force**: Attacco che prova ripetutamente password diverse per accedere

**Lateral Movement**: Movimento dell'attaccante all'interno della rete dopo la compromissione iniziale

**Privilege Escalation**: Ottenimento di privilegi superiori (es: da utente normale a amministratore)

**SOC (Security Operations Center)**: Centro operativo di sicurezza che monitora le minacce 24/7

---

## 📞 Supporto

- 📖 Documentazione completa: `README.md`
- 🚀 Guida rapida: `QUICKSTART.md`
- ✅ Installazione: `INSTALLATION_COMPLETE.md`

---

## 🎯 Best Practices

1. **Analizza regolarmente**: Automatizza l'analisi con cron job o task scheduler
2. **Mantieni aggiornato**: `pip install --upgrade -r requirements.txt`
3. **Backup report**: I PDF contengono evidenze forensi importanti
4. **Configura alerting**: Ricevi notifiche per severity HIGH/CRITICAL
5. **Integra con SIEM**: Invia i risultati al tuo SIEM aziendale

---

## 🏆 Cosa Hai Ottenuto

✅ Sistema SOC AI completamente funzionante  
✅ Analisi automatica di 7+ tipi di log  
✅ Rilevamento automatico minacce  
✅ Mappatura MITRE ATT&CK  
✅ Report PDF professionali  
✅ 2 test di esempio completati  

---

**🎉 Sei pronto ad analizzare i tuoi log!**

**Inizia subito con**:
```bash
python soc_cli.py analyze -f /percorso/dei/tuoi/log.log
```

---

*Buon Threat Hunting! 🔍🛡️*
