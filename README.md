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
git clone https://github.com/tuo-username/web-vulnerability-scanner.git
cd web-vulnerability-scanner
pip install -r requirements.txt
