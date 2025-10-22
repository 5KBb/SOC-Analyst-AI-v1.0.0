# Security Policy

## 🔒 Reporting a Vulnerability

If you discover a security vulnerability in **SOC Analyst AI**, please help us protect our users by reporting it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within **48 hours** and provide a timeline for a fix.

---

## ✅ Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 1.0.x   | :white_check_mark: | Active |
| < 1.0   | :x:                | No support |

---

## 🛡️ Security Features

SOC Analyst AI is designed with security in mind:

### Privacy & Data Protection
- ✅ **No telemetry**: We don't collect or send any data
- ✅ **Local processing**: All analysis happens on your machine
- ✅ **No external calls by default**: Threat intelligence integrations are opt-in
- ✅ **Credential safety**: All API keys stored in local config only

### Configuration Security
- ✅ Config file (`config.yaml`) should have restricted permissions
- ✅ Never commit credentials to version control
- ✅ Use environment variables for sensitive data (`.env` file)
- ✅ `.gitignore` configured to exclude sensitive files

### Code Security
- ✅ Input validation on all parsers
- ✅ Sanitization of log data before processing
- ✅ No arbitrary code execution
- ✅ Safe file handling with path validation

---

## ⚠️ Security Best Practices

### For Users

1. **Protect Your Config File**
   ```bash
   # Linux/Mac
   chmod 600 config/config.yaml
   
   # Windows (PowerShell)
   icacls config\config.yaml /inheritance:r /grant:r "$env:USERNAME:F"
   ```

2. **Use Environment Variables**
   Create a `.env` file for sensitive data:
   ```env
   VT_API_KEY=your_virustotal_key
   JIRA_TOKEN=your_jira_token
   ```

3. **Review Generated Reports**
   - PDF reports may contain sensitive IP addresses
   - Sanitize before sharing externally
   - Store reports securely

4. **Update Regularly**
   ```bash
   pip install --upgrade -r requirements.txt
   ```

5. **Isolate Analysis Environment**
   - Run in a dedicated VM or container
   - Limit network access if analyzing untrusted logs
   - Use separate credentials for integrations

### For Developers

1. **Never Hardcode Credentials**
   ```python
   # ❌ Bad
   api_key = "abc123"
   
   # ✅ Good
   api_key = os.getenv('API_KEY')
   ```

2. **Validate All Input**
   ```python
   # Use validators from src/utils/validators.py
   is_valid, ip_type = validate_ip(ip_address)
   ```

3. **Sanitize Log Content**
   ```python
   # Remove sensitive data before processing
   sanitized = sanitize_string(log_line, max_length=1000)
   ```

4. **Use Secure Dependencies**
   - Keep `requirements.txt` updated
   - Monitor Dependabot alerts
   - Review dependency licenses

---

## 🔍 Known Security Considerations

### Log Content
- **Issue**: Analyzed logs may contain sensitive information
- **Mitigation**: Never commit log files to version control; use `.gitignore`

### API Keys in Config
- **Issue**: `config.yaml` contains API keys if integrations enabled
- **Mitigation**: Restrict file permissions; use `.env` instead; never commit config with real keys

### PDF Reports
- **Issue**: Generated PDFs may contain internal IP addresses, usernames
- **Mitigation**: Review reports before sharing; use redaction if needed

### Third-Party Integrations
- **Issue**: Threat intelligence APIs send data externally
- **Mitigation**: All integrations are opt-in (disabled by default); review privacy policies

---

## 🚨 Vulnerability Disclosure Timeline

1. **Day 0**: Vulnerability reported
2. **Day 1-2**: Acknowledgment sent to reporter
3. **Day 3-7**: Vulnerability validated and severity assessed
4. **Day 8-30**: Patch developed and tested
5. **Day 31**: Security advisory published
6. **Day 31**: Patch released as new version

---

## 🏆 Security Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities:

<!-- Add contributors here -->
- *No vulnerabilities reported yet*

---

## 📞 Contact

For security concerns: security@example.com  
For general questions: Open a GitHub issue

---

## 📜 Compliance

SOC Analyst AI processes security logs which may contain:
- IP addresses
- Usernames
- Hostnames
- Network traffic metadata

**Data Processing**:
- All processing is local (on your machine)
- No data sent to external servers (unless integrations enabled)
- User has full control over data retention and deletion

**GDPR Compliance**:
- Data controller: The organization running the tool
- Data processor: The tool itself (local processing only)
- Data subjects: May include employees, customers (depending on logs analyzed)

**Recommendations**:
- Review logs for PII before analysis
- Implement data retention policies
- Secure storage of generated reports
- Follow your organization's data protection policies

---

**Last Updated**: 2025-10-22  
**Version**: 1.0.0

