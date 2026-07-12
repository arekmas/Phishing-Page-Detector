import sys
import re
import socket
import ssl

from datetime import datetime, timezone
from urllib.parse import urlparse
try:
    import requests
except ImportError:
    print("[-] Missing requests library. Installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

try:
    import whois
except ImportError:
    print("[-] Missing python-whois library. Installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-whois"])
    import whois


def check_ssl(hostname):
    result = {"valid": False, "expires": None, "issuer": None, "days_left": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["valid"] = True
                result["expires"] = cert.get("notAfter")
                result["issuer"] = dict(cert.get("issuer", [])).get("organizationName", "Unknown")
                if result["expires"]:
                    expiry = datetime.strptime(result["expires"], "%b %d %H:%M:%S %Y %Z")
                    result["days_left"] = (expiry - datetime.now()).days
    except:
        pass
    return result


def check_whois(domain):
    result = {"exists": False, "created": None, "expires": None, "registrar": None, "days_since_reg": None}
    try:
        w = whois.whois(domain)
        if w.domain_name:
            result["exists"] = True
            result["registrar"] = w.registrar
            if isinstance(w.creation_date, list):
                result["created"] = w.creation_date[0]
            else:
                result["created"] = w.creation_date
            if isinstance(w.expiration_date, list):
                result["expires"] = w.expiration_date[0]
            else:
                result["expires"] = w.expiration_date
            if result["created"]:
                diff = datetime.now(timezone.utc) - result["created"]
                result["days_since_reg"] = diff.days
    except:
        pass
    return result


def check_page(url):
    result = {"status": None, "title": None, "forms": 0, "external_links": 0, "iframe": False, "redirect": None}
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        r = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        result["status"] = r.status_code
        result["redirect"] = r.url if r.url != url else None

        if "text/html" in r.headers.get("Content-Type", ""):
            html = r.text.lower()
            match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
            if match:
                result["title"] = match.group(1).strip()[:100]

            result["forms"] = len(re.findall(r"<form", html, re.IGNORECASE))
            result["iframe"] = bool(re.search(r"<iframe", html, re.IGNORECASE))

            base_domain = urlparse(url).netloc
            links = re.findall(r'href=["\'](https?://[^"\']+)', html, re.IGNORECASE)
            for link in links:
                if base_domain not in link:
                    result["external_links"] += 1
    except:
        pass
    return result


def analyze_phishing(url):
    score = 0
    warnings = []

    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")

    print(f"\n{'='*55}")
    print(f"  SCANNING: {url}")
    print(f"{'='*55}")

    # --- Step 1: WHOIS ---
    print(f"\n[1/4] Checking WHOIS...")
    whois_info = check_whois(domain)

    if whois_info["exists"]:
        print(f"  Registrar: {whois_info['registrar'] or 'No data'}")
        if whois_info["days_since_reg"] is not None:
            print(f"  Domain registered: {whois_info['days_since_reg']} days ago")
        if whois_info["expires"]:
            print(f"  Expires: {whois_info['expires']}")

        if whois_info["days_since_reg"] is not None and whois_info["days_since_reg"] < 365:
            score += 25
            warnings.append("Domain registered less than a year ago (suspicious)")
        if whois_info["registrar"] and any(x in (whois_info["registrar"] or "").lower() for x in ["privacy", "whoisguard", "anonymize"]):
            score += 10
            warnings.append("WHOIS hidden by privacy service")
    else:
        score += 30
        warnings.append("Unable to retrieve WHOIS information")

    # --- Step 2: SSL ---
    print(f"\n[2/4] Checking SSL...")
    ssl_info = check_ssl(parsed.hostname or domain)

    if ssl_info["valid"]:
        print(f"  SSL Certificate: OK")
        print(f"  Issuer: {ssl_info['issuer']}")
        if ssl_info["days_left"] is not None:
            print(f"  Expires in: {ssl_info['days_left']} days")
            if ssl_info["days_left"] < 30:
                score += 15
                warnings.append("SSL certificate expires in less than 30 days")
    else:
        score += 30
        warnings.append("No valid SSL certificate")

    # --- Step 3: Page structure ---
    print(f"\n[3/4] Analyzing page structure...")
    page = check_page(url)

    if page["status"]:
        print(f"  HTTP Status: {page['status']}")
        if page["title"]:
            print(f"  Title: {page['title']}")
        if page["redirect"]:
            print(f"  Redirects to: {page['redirect']}")
            score += 15
            warnings.append("Page redirects to another address")
        print(f"  Forms: {page['forms']}")
        print(f"  External links: {page['external_links']}")
        print(f"  IFrame: {'YES' if page['iframe'] else 'NO'}")

        if page["forms"] > 0:
            score += 20
            warnings.append(f"Found {page['forms']} form(s) - possible data harvesting")
        if page["external_links"] > 5:
            score += 10
            warnings.append("High number of external links")
        if page["iframe"]:
            score += 15
            warnings.append("Page uses iframe - possible malicious embedding")
    else:
        score += 25
        warnings.append("Cannot fetch page (may be blocked or does not exist)")

    # --- Step 4: Additional heuristics ---
    print(f"\n[4/4] Additional heuristics...")

    if re.search(r"(login|signin|account|verify|secure|banking|update|confirm)", domain, re.IGNORECASE):
        score += 10
        warnings.append("Domain contains suspicious keywords (login, secure, bank, etc.)")

    if re.search(r"(https?://)?[^/]+\.[^/]{2,3}/[^/]+\.[^/]{2,3}", url):
        score += 15
        warnings.append("URL contains nested domain - may be misleading")

    if page["title"] and any(x in page["title"].lower() for x in ["login", "sign in", "log in", "verify", "account", "bank", "password", "secure"]):
        score += 10
        warnings.append("Page title suggests a login page")

    if warnings:
        print(f"\n  WARNINGS:")
        for w in warnings:
            print(f"    - {w}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("Enter website URL (e.g. https://example.com): ").strip()

    if not url.startswith("http"):
        url = "https://" + url

    analyze_phishing(url)