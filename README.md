# 🛡️ Web Vulnerability Scanner

Uno strumento avanzato in Python per la scansione automatica di vulnerabilità web. Progettato per testare **SQL Injection**, **Cross-Site Scripting (XSS)** e **Cross-Site Request Forgery (CSRF)**, eseguendo anche il crawling ricorsivo del sito target. Pensato per attività di **penetration testing etico**, **audit di sicurezza** e **ricerca bug bounty**.

## 🚀 Funzionalità

- ✅ Rilevamento automatico di:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - CSRF (assenza token)
- 🔎 Crawler integrato per navigare tutte le sottopagine del dominio
- 🔁 Multithreading per migliorare la velocità di scansione
- 🧠 Analisi intelligente di form HTML (input, select, textarea)
- 🪪 Intestazioni HTTP personalizzabili
- 📜 Logging avanzato (INFO, WARNING, CRITICAL)

## 🧰 Tecnologie utilizzate

- Python 3.10+
- `requests`
- `BeautifulSoup` (`bs4`)
- `argparse`, `threading`, `concurrent.futures`, `re`, `logging`

## 📦 Installazione

Clona il repository ed esegui l'installazione dei pacchetti:

```bash
git clone https://github.com/LancoShell/web-scanner.git
cd web-scanner
pip install -r requirements.txt
```

▶️ Utilizzo

Lancia il tool specificando l'URL target da analizzare:
```bash
python web-scanner.py http://www.sito-target.it
```
Esempio pratico:
```bash
python scanner.py https://testphp.vulnweb.com
```
🧪 Esempio di Output
```bash
[INFO] Starting scan on https://testphp.vulnweb.com
[INFO] Scanning: https://testphp.vulnweb.com/login.php
[CRITICAL] SQLi vulnerability found: https://testphp.vulnweb.com/login.php?vulntest=' OR '1'='1
[CRITICAL] XSS vulnerability found at: https://testphp.vulnweb.com/search.php
[WARNING] Potential CSRF vulnerability: https://testphp.vulnweb.com/profile
[INFO] Scan completed in 12.34 seconds
```
👤 Autore
https://lancohacker.com  |   
info@lancohacker.com
