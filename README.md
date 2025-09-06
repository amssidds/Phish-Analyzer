# Phish Analyzer

A self-hosted phishing email analysis tool.  

Forward suspicious emails as `.eml` attachments to a dedicated mailbox — the tool polls, analyzes, and replies with a clear report (SPF, DKIM, VirusTotal, Google Safe Browsing, attachments, scoring, etc.).



## Features
- ✅ SPF & DKIM checks  
- 🔗 Extracts and scans URLs (VirusTotal + Safe Browsing)  
- 📎 Hashes and lists attachments  
- 🧮 Gives a score & verdict (Safe / Suspicious / Malicious)  
- ❤️ Sends **Uptime Kuma heartbeat** to confirm it’s alive  
- 🐳 Runs standalone or in Docker  



## Installation

### 1. Clone the repo
```bash
git clone https://github.com/YOURNAME/phish-analyzer.git
cd phish-analyzer
```

### 2. Configure environment
Copy the example file and edit with your own credentials and API keys:
```bash
cp .env.example .env
nano .env
```

### 3. Run with Docker
```bash
docker compose up -d --build
```

Check logs:
```bash
docker logs -f phish-analyzer
```



## Usage

1. From Outlook/Gmail, **forward suspicious emails as attachment** (`.eml`) to the configured inbox (e.g., `phish@company.com`).  
2. The analyzer polls every 30 seconds (configurable via `.env`).  
3. You’ll receive an automatic reply with the full analysis.  



## Example Report

- Clear **verdict banner** (Safe / Suspicious / Malicious)  
- Table of checks with ✅ / ❌ emojis  
- List of URLs & attachments  
- Simple guidance box: “What should I do?”  



## Config Options

`.env` includes:
- IMAP & SMTP settings (your mail provider)  
- VirusTotal & Google Safe Browsing API keys  
- Uptime Kuma push URL (optional)  
- Scoring thresholds  

See `.env.example` for details.



## Project Structure

```
phish-analyzer/
├── phish.py             # main analyzer logic
├── templates.py         # HTML/text report layout
├── requirements.txt     # python dependencies
├── Dockerfile           # docker image definition
├── docker-compose.yml   # compose service config
├── .env.example         # sample config
└── samples/             # saved .eml samples
```



## ⚠️ Disclaimer
This project is for **educational and internal security use**.  
Do not rely solely on this tool for production-grade phishing defense.  
Always follow your organization’s incident response process.

<br>This tool has code optimized and assisted using AI
