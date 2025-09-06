#!/usr/bin/env python3
# phish.py — continuous poller, reply threading, Uptime Kuma heartbeat, tunable scoring
# Layout is kept in templates.py (build_html/build_text).

import os, re, time, imaplib, smtplib, email, hashlib, base64, socket
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.utils import parseaddr, getaddresses, make_msgid

import requests
import dkim, spf, dns.resolver, tldextract

# Use our layout module
from templates import build_html, build_text

socket.setdefaulttimeout(30)

# ---------- env loader ----------
def load_env(path=".env"):
    if not os.path.exists(path): return
    with open(path) as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k,v=line.split("=",1)
            v=v.strip().strip('"').strip("'")
            os.environ.setdefault(k.strip(), v)
load_env()

def env_int(name, default):
    try: return int(os.getenv(name, "").strip())
    except Exception: return default

IMAP_SERVER = os.getenv("IMAP_SERVER", "mail.mxrouting.net")
IMAP_USER   = os.getenv("IMAP_USER")
IMAP_PASS   = os.getenv("IMAP_PASS")

SMTP_SERVER = os.getenv("SMTP_SERVER", "mail.mxrouting.net")
SMTP_PORT   = int(os.getenv("SMTP_PORT", "465"))
SMTP_USER   = os.getenv("SMTP_USER", IMAP_USER)
SMTP_PASS   = os.getenv("SMTP_PASS", IMAP_PASS)

REPLY_FROM  = os.getenv("REPLY_FROM", IMAP_USER)
VT_API_KEY  = os.getenv("VT_API_KEY", "")
GSB_API_KEY = os.getenv("GSB_API_KEY", "")
KUMA_URL    = os.getenv("KUMA_URL", "")

# Tunable scoring
DKIM_FAIL_POINTS       = env_int("DKIM_FAIL_POINTS", 35)
SPF_NOTPASS_POINTS     = env_int("SPF_NOTPASS_POINTS", 25)
VT_MALICIOUS_POINTS    = env_int("VT_MALICIOUS_POINTS", 30)
SB_HIT_POINTS          = env_int("SB_HIT_POINTS", 30)
THRESHOLD_SUSPICIOUS   = env_int("THRESHOLD_SUSPICIOUS", 35)
THRESHOLD_MALICIOUS    = env_int("THRESHOLD_MALICIOUS", 70)

SAVE_FOLDER = "samples"
os.makedirs(SAVE_FOLDER, exist_ok=True)

POLL_SECONDS = env_int("POLL_SECONDS", 30)
URL_REGEX = re.compile(r'https?://[^\s"<>\)]+', re.IGNORECASE)

# ---------- Uptime Kuma ----------
def kuma_ping():
    if not KUMA_URL: 
        return
    try:
        requests.get(KUMA_URL, timeout=5)
        print("[♥] Uptime Kuma heartbeat sent", flush=True)
    except Exception as e:
        print(f"[!] Kuma heartbeat failed: {e}", flush=True)

# ---------- helpers ----------
def extract_reporter_address(msg):
    name, addr = parseaddr(msg.get("From",""))
    return addr or ""

def extract_outer_ids(msg):
    return msg.get("Message-ID"), msg.get("Subject",""), msg.get("Date","")

def extract_urls_from_msg(msg):
    urls=set()
    for part in msg.walk():
        if part.get_content_type() in ("text/html","text/plain"):
            body = part.get_payload(decode=True)
            if not body: continue
            try: text = body.decode(errors="ignore")
            except Exception: continue
            for u in re.findall(URL_REGEX, text):
                urls.add(u.strip().rstrip(").,;"))
    return list(urls)

def extract_sender_ip_from_headers(msg):
    for line in msg.get_all("Received-SPF", []) or []:
        m=re.search(r"client-ip=([0-9a-fA-F\:\.]+)", line)
        if m: return m.group(1)
    for line in (msg.get_all("Received", []) or [])[::-1]:
        m=re.search(r"\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]", line)
        if m: return m.group(1)
    return None

def get_mail_from_domain(msg):
    addrs = getaddresses([msg.get("From","")])
    if not addrs: return None
    _, addr = addrs[0]
    if "@" in addr: return addr.split("@",1)[1].lower()
    return None

# ---------- checks ----------
def check_dkim_on_raw(raw_bytes):
    try: return bool(dkim.verify(raw_bytes))
    except Exception: return False

def check_spf_result(sender_ip, mail_from_domain, helo_host="unknown"):
    if not sender_ip or not mail_from_domain: return "neutral"
    try:
        res = spf.check2(i=sender_ip, s=f"postmaster@{mail_from_domain}", h=helo_host)
        return res[0]
    except Exception:
        return "neutral"

def check_virustotal_url(url):
    if not VT_API_KEY: return None
    try:
        requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": VT_API_KEY},
            data={"url": url}, timeout=15
        )
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r2 = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VT_API_KEY}, timeout=15
        )
        if r2.status_code != 200: return None
        return r2.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
    except Exception:
        return None

def check_safe_browsing(url):
    if not GSB_API_KEY: return False
    payload = {
        "client": {"clientId": "phishbox", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE","SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
            json=payload, timeout=15
        )
        return r.json() != {}
    except Exception:
        return False

# ---------- core fetch/analyze/respond ----------
def fetch_unseen_with_eml():
    out=[]
    print("[+] Connecting to IMAP...", flush=True)
    mail=imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(IMAP_USER, IMAP_PASS)
    mail.select("inbox")
    typ, msgs = mail.search(None, "UNSEEN")
    if typ!="OK":
        print("[!] IMAP search failed", flush=True)
        mail.logout(); return out

    ids = msgs[0].split()
    print(f"[~] UNSEEN messages: {len(ids)}", flush=True)
    if not ids:
        mail.logout(); return out

    for num in ids:
        typ, data = mail.fetch(num, "(RFC822)")
        if typ!="OK" or not data or not data[0]:
            continue
        outer = email.message_from_bytes(data[0][1], policy=policy.default)
        reporter = extract_reporter_address(outer)
        outer_msgid, outer_subject, _ = extract_outer_ids(outer)

        for part in outer.iter_attachments():
            fname=(part.get_filename() or "").lower()
            ctype=part.get_content_type()
            if fname.endswith(".msg"):
                continue
            if ctype=="message/rfc822":
                raw_bytes=None
                try:
                    payload=part.get_payload()
                    if isinstance(payload, list) and payload:
                        raw_bytes=payload[0].as_bytes(policy=policy.default)
                    elif hasattr(payload, "as_bytes"):
                        raw_bytes=payload.as_bytes(policy=policy.default)
                    else:
                        raw_bytes=part.get_payload(decode=True)
                except Exception:
                    raw_bytes=None
                if not raw_bytes: continue
                path=f"{SAVE_FOLDER}/{datetime.now().timestamp()}.eml"
                with open(path,"wb") as f: f.write(raw_bytes)
                out.append((num, path, reporter, outer_msgid, outer_subject))
                print(f"[+] Saved {path} from {reporter}", flush=True)

    mail.logout()
    return out

def analyze_eml(path):
    with open(path,"rb") as f:
        raw=f.read()
        msg=email.message_from_bytes(raw, policy=policy.default)

    score=0
    urls=extract_urls_from_msg(msg)
    attachments=[]
    vt_hits=0; sb_hits=0
    reasons=[]

    for part in msg.walk():
        fname=part.get_filename()
        if not fname: continue
        content=part.get_payload(decode=True)
        if not content: continue
        sha256=hashlib.sha256(content).hexdigest()
        attachments.append((fname, sha256))

    for url in urls:
        vt=check_virustotal_url(url)
        if vt and vt.get("malicious",0)>0:
            vt_hits+=1; score+=VT_MALICIOUS_POINTS; reasons.append("URL flagged by VirusTotal")
        if check_safe_browsing(url):
            sb_hits+=1; score+=SB_HIT_POINTS; reasons.append("URL flagged by Google Safe Browsing")

    dkim_ok=check_dkim_on_raw(raw)
    if not dkim_ok:
        score+=DKIM_FAIL_POINTS; reasons.append("DKIM failed/missing")

    sender_ip=extract_sender_ip_from_headers(msg)
    mail_from_domain=get_mail_from_domain(msg)
    spf_res=check_spf_result(sender_ip, mail_from_domain)
    if spf_res!="pass":
        score+=SPF_NOTPASS_POINTS; reasons.append(f"SPF result: {spf_res}")

    if score>=THRESHOLD_MALICIOUS: verdict="Malicious"
    elif score>=THRESHOLD_SUSPICIOUS: verdict="Suspicious"
    else: verdict="Safe"
    if not reasons: reasons.append("No obvious red flags detected")

    return {
        "subject": msg.get("Subject",""),
        "from": msg.get("From",""),
        "urls": urls,
        "attachments": attachments,
        "vt_hits": vt_hits,
        "sb_hits": sb_hits,
        "dkim": dkim_ok,
        "spf": spf_res,
        "verdict": verdict,
        "score": score,
        "reasons": reasons,
    }

def send_report(report, to_email, outer_msgid=None, outer_subject=None):
    html = build_html(report)
    text = build_text(report)

    msg = EmailMessage()
    if outer_msgid:
        msg["In-Reply-To"] = outer_msgid
        msg["References"]  = outer_msgid
    msg["Subject"] = f"Re: {outer_subject} — Verdict: {report['verdict']}" if outer_subject else f"Phish Analysis Report — Verdict: {report['verdict']}"
    msg["From"] = REPLY_FROM
    msg["To"]   = to_email
    msg["Message-ID"] = make_msgid()
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")

    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as smtp:
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)
        print(f"[+] Report sent to {to_email}", flush=True)

# ---------- run loop ----------
def fetch_and_process_once():
    batches = fetch_unseen_with_eml()
    if not batches:
        print("[~] Nothing to process this cycle", flush=True)
        return
    for _seq, eml_path, reporter, outer_msgid, outer_subject in batches:
        print(f"[*] Analyzing {eml_path} ...", flush=True)
        try:
            results = analyze_eml(eml_path)
            send_report(results, reporter, outer_msgid=outer_msgid, outer_subject=outer_subject)
        except Exception as e:
            print(f"[!] Error analyzing {eml_path}: {e}", flush=True)

if __name__=="__main__":
    print(f"[~] Starting poller. Checking every {POLL_SECONDS}s...", flush=True)
    while True:
        try:
            kuma_ping()
            fetch_and_process_once()
            time.sleep(POLL_SECONDS)
        except Exception as e:
            print(f"[!] Unexpected error: {e}", flush=True)
            time.sleep(30)
