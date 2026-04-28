# LowHangingFruits

LowHangingFruits is an asynchronous Python-based web attack surface triage tool designed to quickly identify low-hanging vulnerabilities in web applications.

## Features

* Missing security headers detection (CSP, HSTS, X-Frame-Options, etc.)
* Sensitive endpoint discovery (`/.env`, `/.git`, `/admin`, etc.)
* JavaScript secret scanning (API keys, tokens, JWTs)
* Risk scoring system (Low / Medium / High)
* CWE mapping for findings
* Subdomain discovery:

  * crt.sh (certificate transparency logs)
  * subfinder integration
* Async scanning using aiohttp
* JSON + HTML report generation
* Clean CLI output with severity levels

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/LowHangingFruits.git
cd LowHangingFruits
pip install -r requirements.txt
```

---

## Usage

### Basic scan

```bash
python LowHangingFruits.py -t example.com
```

### With subdomain discovery

```bash
python LowHangingFruits.py -t example.com --subdomains --crtsh --subfinder
```

### Generate HTML report

```bash
python LowHangingFruits.py -t example.com --html
```

---

## Output

Results are automatically saved in:

```
outputs/
```

* JSON report (machine-readable)
* HTML report (human-readable)

---

## Disclaimer

This tool is intended for educational and authorized security testing purposes only.

---

## Future Improvements

* Automatic scanning of discovered subdomains
* More secret detection patterns (You know what to change. Clone the repo and feel free to change or add whatever you want(secret patterns that i did'nt included, more sensitive endpoints).)
* Improved false-positive filtering
* Additional recon integrations
