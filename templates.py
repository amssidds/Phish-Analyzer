# templates.py — layout for phishing analysis reports

def build_html(report):
    if report["verdict"] == "Malicious":
        bar_color = "#c62828"
        icon = "🛑"
    elif report["verdict"] == "Suspicious":
        bar_color = "#ef6c00"
        icon = "⚠️"
    else:
        bar_color = "#2e7d32"
        icon = "✅"

    def flag_emoji(x):
        s = str(x).lower() if not isinstance(x, bool) else ("pass" if x else "fail")
        return "✅ Pass" if s=="pass" else "❌ Fail" if s=="fail" else "⚠️ Check"

    return f"""
<html>
  <body style="background:#fff;font-family:Arial,sans-serif;line-height:1.6;color:#111;">
    <div style="max-width:800px;margin:0 auto;">
      <div style="background:{bar_color};color:#fff;padding:12px;font-size:16px;font-weight:700;">
        {icon} {report['verdict']} ({report['score']}/100)
      </div>
      <div style="padding:14px;border:1px solid #ddd;border-top:none;">
        <p><b>Sender:</b> {report['from']}<br>
           <b>Subject:</b> {report['subject']}</p>
        <p><b>Why this verdict:</b></p>
        <ul>{"".join(f"<li>{r}</li>" for r in report['reasons'])}</ul>
        <table style="border-collapse:collapse;width:100%;margin-top:10px;">
          <tr><th align="left">Check</th><th align="left">Result</th></tr>
          <tr><td>SPF</td><td>{flag_emoji(report['spf'])}</td></tr>
          <tr><td>DKIM</td><td>{flag_emoji(report['dkim'])}</td></tr>
          <tr><td>VirusTotal</td><td>{report['vt_hits']} detections</td></tr>
          <tr><td>Google Safe Browsing</td><td>{report['sb_hits']} hits</td></tr>
        </table>
        <p><b>Links found:</b></p>
        <ul>{"".join(f"<li><a href='{u}'>{u}</a></li>" for u in report['urls']) or "<li>None</li>"}</ul>
        <p><b>Attachments:</b></p>
        <ul>{"".join(f"<li>{n} ({h})</li>" for n,h in report['attachments']) or "<li>None</li>"}</ul>
        <div style="margin-top:20px;padding:12px;background:#fff7ed;border:1px solid #eee;">
          <b>What should I do?</b><br>
          If unexpected: don’t click links, don’t reply, delete it.<br>
          If expected but looks off: contact IT.
        </div>
        <p style="margin-top:10px;color:#666;font-size:12px;">Automated report from Phish Analyzer.</p>
      </div>
    </div>
  </body>
</html>
"""

def build_text(report):
    return f"""Verdict: {report['verdict']} ({report['score']}/100)
Sender: {report['from']}
Subject: {report['subject']}
Reasons: {", ".join(report['reasons'])}
SPF: {report['spf']}
DKIM: {"pass" if report['dkim'] else "fail"}
VirusTotal: {report['vt_hits']} detections
Safe Browsing: {report['sb_hits']} hits
Links: {", ".join(report['urls']) or "None"}
Attachments: {", ".join(n for n,_ in report['attachments']) or "None"}
"""
