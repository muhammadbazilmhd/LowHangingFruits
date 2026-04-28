import argparse
import asyncio
import json
import math
import re
import socket
import ssl
import subprocess
import sys
import shutil
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
    from bs4 import BeautifulSoup
    from colorama import Fore, Style, init as colorama_init
    from tqdm import tqdm
except ImportError:
    print("Missing dependencies. Install with:")
    print("pip install aiohttp beautifulsoup4 colorama tqdm")
    sys.exit(1)

colorama_init(autoreset=True)

DEFAULT_TIMEOUT = 6
MAX_JS_FILES = 20
MAX_CONCURRENT_REQUESTS = 20

COMMON_FILES = [
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/config.php.bak",
    "/admin/",
    "/server-status",
]

RECOMMENDED_HEADERS = {
    "Content-Security-Policy": "Missing CSP",
    "Strict-Transport-Security": "Missing HSTS",
    "X-Content-Type-Options": "Missing X-Content-Type-Options",
    "X-Frame-Options": "Missing X-Frame-Options",
    "Referrer-Policy": "Missing Referrer-Policy",
}

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token": r"github_pat_[A-Za-z0-9_]{20,}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]+",
    "JWT": r"eyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+",
    "Generic API Key": r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{12,}['\"]",
}

RISK_WEIGHTS = {
    "missing_header": 5,
    "sensitive_file": 20,
    "risky_method": 10,
    "secret_match": 25,
    "tls_expiring_soon": 15,
    "tls_expired": 30,
    "http_only": 15,
}

CWE_CVE_MAPPING = {
    "missing_header": {
        "cwe": "CWE-693",
        "cve_examples": ["CVE-2021-41182"]
    },
    "sensitive_file": {
        "cwe": "CWE-552",
        "cve_examples": ["CVE-2019-11043"]
    },
    "risky_method": {
        "cwe": "CWE-284",
        "cve_examples": []
    },
    "secret_match": {
        "cwe": "CWE-798",
        "cve_examples": ["CVE-2022-3219"]
    },
    "tls_expired": {
        "cwe": "CWE-295",
        "cve_examples": []
    },
    "tls_expiring_soon": {
        "cwe": "CWE-295",
        "cve_examples": []
    },
    "http_only": {
        "cwe": "CWE-319",
        "cve_examples": []
    }
}


def normalize_target(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def unique_preserve_order(items):
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_high_entropy_secret(candidate: str, min_entropy: float = 3.5, min_length: int = 16) -> bool:
    cleaned = candidate.strip().strip("\"' ")
    if len(cleaned) < min_length:
        return False
    return shannon_entropy(cleaned) >= min_entropy


def enrich_with_cwe_cve(findings: list) -> list:
    for finding in findings:
        mapping = CWE_CVE_MAPPING.get(finding["type"], {})
        finding["cwe"] = mapping.get("cwe")
        finding["cve_examples"] = mapping.get("cve_examples", [])
    return findings


def summarize_risk(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def color_for_severity(sev: str) -> str:
    sev = sev.lower()
    if sev == "critical":
        return Fore.MAGENTA
    if sev == "high":
        return Fore.RED
    if sev == "medium":
        return Fore.YELLOW
    if sev == "low":
        return Fore.GREEN
    return Fore.WHITE


def color_for_risk(risk: str) -> str:
    if risk == "high":
        return Fore.RED
    if risk == "medium":
        return Fore.YELLOW
    if risk == "low":
        return Fore.GREEN
    return Fore.WHITE


def fingerprint_technology(headers: dict, html: str) -> dict:
    indicators = {
        "server": headers.get("Server"),
        "powered_by": headers.get("X-Powered-By"),
        "generator_meta": None,
    }

    try:
        soup = BeautifulSoup(html, "html.parser")
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen:
            indicators["generator_meta"] = gen.get("content")
    except Exception:
        pass

    return indicators


def extract_js_urls(base_url: str, html: str) -> list:
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return []

    js_urls = []
    for script in soup.find_all("script", src=True):
        src = script.get("src")
        if src:
            js_urls.append(urljoin(base_url, src))

    return unique_preserve_order(js_urls)


def calculate_score(findings: list, tls_info: dict, scheme: str) -> int:
    score = 0

    if scheme == "http":
        score += RISK_WEIGHTS["http_only"]

    for finding in findings:
        score += RISK_WEIGHTS.get(finding["type"], 0)

    days_remaining = tls_info.get("days_remaining")
    if tls_info.get("supported") and days_remaining is not None:
        if days_remaining < 0:
            score += RISK_WEIGHTS["tls_expired"]
        elif days_remaining < 14:
            score += RISK_WEIGHTS["tls_expiring_soon"]

    return min(score, 100)


def get_tls_info(hostname: str, port: int = 443) -> dict:
    info = {
        "hostname": hostname,
        "port": port,
        "supported": False,
        "expires_at": None,
        "days_remaining": None,
        "issuer": None,
        "subject": None,
        "error": None,
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info["supported"] = True
                info["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                info["subject"] = dict(x[0] for x in cert.get("subject", ()))

                not_after = cert.get("notAfter")
                if not_after:
                    expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    info["expires_at"] = expires.isoformat()
                    info["days_remaining"] = (expires - now).days

    except Exception as exc:
        info["error"] = str(exc)

    return info


def ensure_output_dir(folder_name: str = "outputs") -> Path:
    base_dir = Path(__file__).resolve().parent
    output_dir = base_dir / folder_name
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def sanitize_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")


def build_output_filename(targets: list, extension: str, prefix: str = "lowhangingfruits") -> Path:
    output_dir = ensure_output_dir()

    if len(targets) == 1:
        parsed = urlparse(normalize_target(targets[0]))
        target_name = parsed.hostname or sanitize_filename(targets[0])
    else:
        target_name = "multi_target"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = sanitize_filename(target_name)
    filename = f"{prefix}_{safe_name}_{timestamp}.{extension}"
    return output_dir / filename


async def safe_request(session: aiohttp.ClientSession, method: str, url: str, **kwargs):
    try:
        async with session.request(method, url, timeout=DEFAULT_TIMEOUT, allow_redirects=True, **kwargs) as response:
            text = None
            if method.upper() != "HEAD":
                try:
                    text = await response.text(errors="ignore")
                except Exception:
                    text = ""
            return {
                "url": str(response.url),
                "status": response.status,
                "headers": dict(response.headers),
                "text": text if text is not None else "",
            }
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return None


def analyze_headers(headers: dict) -> list:
    findings = []
    for header, message in RECOMMENDED_HEADERS.items():
        if header not in headers:
            findings.append({
                "type": "missing_header",
                "header": header,
                "message": message,
                "severity": "medium"
            })
    return findings


async def analyze_methods(session: aiohttp.ClientSession, url: str) -> list:
    findings = []
    response = await safe_request(session, "OPTIONS", url)
    if not response:
        return findings

    allow_header = response["headers"].get("Allow", "")
    methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
    risky = {"PUT", "DELETE", "TRACE", "CONNECT"}

    for method in methods:
        if method in risky:
            findings.append({
                "type": "risky_method",
                "method": method,
                "message": f"Server allows risky HTTP method: {method}",
                "severity": "high" if method in {"PUT", "DELETE"} else "medium"
            })
    return findings


async def fetch_common_file(session: aiohttp.ClientSession, base_url: str, path: str):
    full_url = urljoin(base_url, path)
    response = await safe_request(session, "GET", full_url)
    if response and response["status"] == 200 and response["text"]:
        return {
            "type": "sensitive_file",
            "url": full_url,
            "status_code": response["status"],
            "message": f"Potentially sensitive or interesting path exposed: {path}",
            "severity": "high"
        }
    return None


async def analyze_common_files(session: aiohttp.ClientSession, base_url: str) -> list:
    tasks = [fetch_common_file(session, base_url, path) for path in COMMON_FILES]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r]


async def fetch_js_and_scan(session: aiohttp.ClientSession, js_url: str):
    response = await safe_request(session, "GET", js_url)
    if not response or response["status"] != 200:
        return []

    content = response["text"]
    findings = []

    for secret_name, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, content)
        if not matches:
            continue

        if secret_name == "Generic API Key":
            filtered_matches = []
            for match in matches:
                if isinstance(match, tuple):
                    joined = " ".join(str(m) for m in match if m)
                    candidate = joined
                else:
                    candidate = str(match)

                value_match = re.search(r"['\"]([A-Za-z0-9_\-\.]{12,})['\"]", candidate)
                candidate_value = value_match.group(1) if value_match else candidate

                if is_high_entropy_secret(candidate_value):
                    filtered_matches.append(candidate_value)

            if not filtered_matches:
                continue

            findings.append({
                "type": "secret_match",
                "url": js_url,
                "secret_type": secret_name,
                "match_count": len(filtered_matches),
                "message": f"Possible {secret_name} found in JavaScript asset",
                "severity": "critical"
            })
        else:
            findings.append({
                "type": "secret_match",
                "url": js_url,
                "secret_type": secret_name,
                "match_count": len(matches),
                "message": f"Possible {secret_name} found in JavaScript asset",
                "severity": "critical"
            })

    return findings


async def analyze_js_for_secrets(session: aiohttp.ClientSession, js_urls: list) -> list:
    limited = js_urls[:MAX_JS_FILES]
    tasks = [fetch_js_and_scan(session, js_url) for js_url in limited]
    results = await asyncio.gather(*tasks)
    findings = []
    for item in results:
        findings.extend(item)
    return findings


async def fetch_crtsh_subdomains(domain: str) -> list:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    timeout = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT + 4)
    connector = aiohttp.TCPConnector(ssl=False)

    try:
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            async with session.get(url) as response:
                if response.status != 200:
                    return []
                text = await response.text(errors="ignore")
                data = json.loads(text)
    except Exception:
        return []

    names = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for item in name_value.split("\n"):
            cleaned = item.strip().lower()
            if cleaned.startswith("*."):
                cleaned = cleaned[2:]
            if cleaned and cleaned.endswith(domain.lower()):
                names.add(cleaned)

    return sorted(names)

def find_subfinder_binary() -> str:
    found = shutil.which("subfinder")
    if found:
        return found

    common_paths = [
        str(Path.home() / "go" / "bin" / "subfinder"),
        "/usr/local/bin/subfinder",
        "/usr/bin/subfinder",
    ]

    for path in common_paths:
        if Path(path).exists():
            return path

    return "subfinder"

def fetch_subfinder_subdomains(domain: str) -> list:
    try:
        subfinder_path = find_subfinder_binary()
        print(f"[DEBUG] Using subfinder binary: {subfinder_path}")

        result = subprocess.run(
            [subfinder_path, "-silent", "-d", domain],
            capture_output=True,
            text=True,
            timeout=90,
            check=False
        )

        if result.stderr:
            print(f"[DEBUG] subfinder stderr: {result.stderr.strip()}")

        output_lines = [
            line.strip().lower()
            for line in result.stdout.splitlines()
            if line.strip()
        ]

        return sorted(set(output_lines))

    except subprocess.TimeoutExpired:
        print(f"[DEBUG] subfinder timed out for {domain}")
        return []

    except Exception as exc:
        print(f"[DEBUG] subfinder error for {domain}: {exc}")
        return []


async def gather_subdomains(domain: str, use_crtsh: bool, use_subfinder: bool) -> dict:
    
    print(f"[DEBUG] Starting subdomain discovery for: {domain}")
    print(f"[DEBUG] use_crtsh={use_crtsh}, use_subfinder={use_subfinder}")

    crtsh_results = []
    if use_crtsh:
        print("[DEBUG] Running crt.sh lookup...")
        crtsh_results = await fetch_crtsh_subdomains(domain)
        print(f"[DEBUG] crt.sh found {len(crtsh_results)} subdomains")

    subfinder_results = []
    if use_subfinder:
        print("[DEBUG] Running subfinder...")
        loop = asyncio.get_running_loop()
        subfinder_results = await loop.run_in_executor(None, fetch_subfinder_subdomains, domain)
        print(f"[DEBUG] subfinder raw output count: {len(subfinder_results)}")

    #This is CRITICAL — shows merged results
    combined = sorted(set(crtsh_results + subfinder_results))
    # remove root domain
    combined = [sub for sub in combined if sub != domain]
    print(f"[DEBUG] Combined unique subdomains: {len(combined)}")

    return {
        "crtsh": crtsh_results,
        "subfinder": subfinder_results,
        "all": combined
    }


async def scan_target(target: str, discover_subdomains: bool = False, use_crtsh: bool = True, use_subfinder: bool = False) -> dict:
    normalized = normalize_target(target)
    parsed = urlparse(normalized)
    domain = parsed.hostname or target

    result = {
        "target": target,
        "normalized_url": normalized,
        "final_url": None,
        "status_code": None,
        "tech_fingerprint": {},
        "tls": {},
        "subdomains": {},
        "findings": [],
        "score": 0,
        "risk": "unknown",
        "error": None,
    }

    timeout = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_REQUESTS, ssl=False)

    async with aiohttp.ClientSession(
        timeout=timeout,
        connector=connector,
        headers={"User-Agent": "LowHangingFruits/2.0"}
    ) as session:
        response = await safe_request(session, "GET", normalized)
        if not response:
            result["error"] = "Could not connect or request failed"
            return result

        result["final_url"] = response["url"]
        result["status_code"] = response["status"]

        final_parsed = urlparse(response["url"])
        result["tech_fingerprint"] = fingerprint_technology(response["headers"], response["text"])

        findings = []
        findings.extend(analyze_headers(response["headers"]))

        methods_task = analyze_methods(session, response["url"])
        common_files_task = analyze_common_files(session, response["url"])
        js_urls = extract_js_urls(response["url"], response["text"])
        js_secrets_task = analyze_js_for_secrets(session, js_urls)

        methods_findings, common_file_findings, js_secret_findings = await asyncio.gather(
            methods_task,
            common_files_task,
            js_secrets_task
        )

        findings.extend(methods_findings)
        findings.extend(common_file_findings)
        findings.extend(js_secret_findings)

        if discover_subdomains and domain:
            result["subdomains"] = await gather_subdomains(domain, use_crtsh=use_crtsh, use_subfinder=use_subfinder)
            print("[DEBUG] Subdomain scanning triggered")

        if final_parsed.scheme == "https" and final_parsed.hostname:
            loop = asyncio.get_running_loop()
            result["tls"] = await loop.run_in_executor(None, get_tls_info, final_parsed.hostname, 443)
        else:
            result["tls"] = {
                "supported": False,
                "error": "Target is not using HTTPS"
            }

        findings = enrich_with_cwe_cve(findings)

        result["findings"] = findings
        result["score"] = calculate_score(result["findings"], result["tls"], final_parsed.scheme)
        result["risk"] = summarize_risk(result["score"])

    return result


def print_human_output(scan_result: dict):
    print("=" * 90)
    print(f"{Fore.CYAN}Target      :{Style.RESET_ALL} {scan_result['target']}")
    print(f"{Fore.CYAN}Final URL   :{Style.RESET_ALL} {scan_result['final_url']}")
    print(f"{Fore.CYAN}Status Code :{Style.RESET_ALL} {scan_result['status_code']}")
    print(f"{Fore.CYAN}Risk Score  :{Style.RESET_ALL} {scan_result['score']}/100")
    print(f"{Fore.CYAN}Risk Level  :{Style.RESET_ALL} {color_for_risk(scan_result['risk'])}{scan_result['risk'].upper()}{Style.RESET_ALL}")

    if scan_result.get("tech_fingerprint"):
        print(f"{Fore.CYAN}Tech        :{Style.RESET_ALL} {json.dumps(scan_result['tech_fingerprint'], ensure_ascii=False)}")

    tls_info = scan_result.get("tls", {})
    if tls_info:
        print(f"{Fore.CYAN}TLS         :{Style.RESET_ALL} {json.dumps(tls_info, ensure_ascii=False)}")

    subdomains = scan_result.get("subdomains", {})
    if subdomains.get("all"):
        print(f"{Fore.CYAN}Subdomains ({len(subdomains['all'])}):{Style.RESET_ALL}")
        for sub in subdomains["all"]:
            print(f"   - {sub}")
    else:
        print(f"{Fore.CYAN}Subdomains  :{Style.RESET_ALL} None found")

    if scan_result["findings"]:
        print(f"\n{Fore.WHITE}{Style.BRIGHT}Findings:{Style.RESET_ALL}")
        for idx, finding in enumerate(scan_result["findings"], start=1):
            sev_color = color_for_severity(finding["severity"])
            print(f"  {idx}. {sev_color}[{finding['severity'].upper()}]{Style.RESET_ALL} {finding['message']}")
            print(f"     CWE: {finding.get('cwe')}")
            if finding.get("cve_examples"):
                print(f"     CVE Examples: {', '.join(finding['cve_examples'])}")
            extra = {k: v for k, v in finding.items() if k not in {"type", "message", "severity", "cwe", "cve_examples"}}
            if extra:
                print(f"     Details: {json.dumps(extra, ensure_ascii=False)}")
    else:
        print("\nFindings: None")

    if scan_result.get("error"):
        print(f"{Fore.RED}Error:{Style.RESET_ALL} {scan_result['error']}")


def build_html_report(results: list) -> str:
    rows = []

    summary = {
        'total_targets': len(results),
        'high_risk': len([r for r in results if r.get('risk') == 'high']),
        'medium_risk': len([r for r in results if r.get('risk') == 'medium']),
        'low_risk': len([r for r in results if r.get('risk') == 'low']),
        'total_findings': sum(len(r.get('findings', [])) for r in results)
    }

    summary_html = f"""
    <section class="summary">
    <h2>Executive Summary</h2>
    <p><strong>Report Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p><strong>Total Targets Scanned:</strong> {summary['total_targets']}</p>
    <p><strong>High Risk Targets:</strong> {summary['high_risk']}</p>
    <p><strong>Medium Risk Targets:</strong> {summary['medium_risk']}</p>
    <p><strong>Low Risk Targets:</strong> {summary['low_risk']}</p>
    <p><strong>Total Findings:</strong> {summary['total_findings']}</p>
    </section>
    """

    for result in results:
        findings_html = ""
        if result["findings"]:
            finding_items = []
            for finding in result["findings"]:
                cve_text = ", ".join(finding.get("cve_examples", [])) if finding.get("cve_examples") else "N/A"
                extra = {
                    k: v for k, v in finding.items()
                    if k not in {"type", "message", "severity", "cwe", "cve_examples"}
                }
                finding_items.append(
                    f"""
                    <div class="finding severity-{escape(finding['severity'])}">
                        <strong>[{escape(finding['severity'].upper())}]</strong> {escape(finding['message'])}<br>
                        <strong>CWE:</strong> {escape(str(finding.get('cwe')))}<br>
                        <strong>CVE Examples:</strong> {escape(cve_text)}<br>
                        <strong>Details:</strong> <code>{escape(json.dumps(extra, ensure_ascii=False))}</code>
                    </div>
                    """
                )
            findings_html = "\n".join(finding_items)
        else:
            findings_html = "<p>No findings.</p>"

        subdomains_html = ""
        if result.get("subdomains", {}).get("all"):
            subdomains_html = "<ul>" + "".join(f"<li>{escape(sd)}</li>" for sd in result["subdomains"]["all"][:100]) + "</ul>"
        else:
            subdomains_html = "<p>None</p>"

        rows.append(
            f"""
            <section class="card">
                <h2>{escape(str(result['target']))}</h2>
                <p><strong>Final URL:</strong> {escape(str(result.get('final_url')))}</p>
                <p><strong>Status Code:</strong> {escape(str(result.get('status_code')))}</p>
                <p><strong>Risk Score:</strong> {escape(str(result.get('score')))} / 100</p>
                <p><strong>Risk Level:</strong> <span class="risk-{escape(result.get('risk', 'unknown'))}">{escape(str(result.get('risk'))).upper()}</span></p>
                <p><strong>Tech Fingerprint:</strong> <code>{escape(json.dumps(result.get('tech_fingerprint', {}), ensure_ascii=False))}</code></p>
                <p><strong>TLS:</strong> <code>{escape(json.dumps(result.get('tls', {}), ensure_ascii=False))}</code></p>
                <h3>Subdomains</h3>
                {subdomains_html}
                <h3>Findings</h3>
                {findings_html}
            </section>
            """
        )

    return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>LowHangingFruits Threat Report</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

body {
    font-family: 'Inter', sans-serif;
    margin: 0;
    padding: 20px;
    background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
    color: #333;
    line-height: 1.6;
}

h1 {
    text-align: center;
    color: #2c3e50;
    font-weight: 700;
    font-size: 2.5em;
    margin-bottom: 40px;
    text-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.summary {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 30px;
    margin-bottom: 30px;
    border-radius: 15px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
    position: relative;
    overflow: hidden;
}

.summary::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(255,255,255,0.1);
    border-radius: 15px;
}

.summary h2 {
    margin-top: 0;
    font-size: 1.8em;
    font-weight: 600;
}

.summary p {
    margin: 10px 0;
    font-size: 1.1em;
}

.card {
    background: white;
    padding: 25px;
    margin-bottom: 25px;
    border-radius: 15px;
    box-shadow: 0 8px 25px rgba(0,0,0,0.1);
    transition: transform 0.3s ease, box-shadow 0.3s ease;
    position: relative;
    overflow: hidden;
}

.card:hover {
    transform: translateY(-5px);
    box-shadow: 0 15px 35px rgba(0,0,0,0.15);
}

.card h2 {
    color: #34495e;
    font-weight: 600;
    margin-top: 0;
    border-bottom: 2px solid #ecf0f1;
    padding-bottom: 10px;
}

.card p {
    margin: 10px 0;
}

.card h3 {
    color: #7f8c8d;
    font-weight: 500;
    margin-top: 20px;
    margin-bottom: 10px;
}

.finding {
    padding: 15px;
    margin-bottom: 15px;
    border-radius: 10px;
    border-left: 5px solid;
    position: relative;
}

.severity-critical {
    background: linear-gradient(135deg, #ff9a9e 0%, #fecfef 100%);
    border-left-color: #e91e63;
}

.severity-high {
    background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);
    border-left-color: #ff5722;
}

.severity-medium {
    background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
    border-left-color: #ffc107;
}

.severity-low {
    background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
    border-left-color: #28a745;
}

.risk-high {
    color: #c0392b;
    font-weight: bold;
    background: #ffeaea;
    padding: 2px 8px;
    border-radius: 5px;
}

.risk-medium {
    color: #e67e22;
    font-weight: bold;
    background: #fff3cd;
    padding: 2px 8px;
    border-radius: 5px;
}

.risk-low {
    color: #27ae60;
    font-weight: bold;
    background: #d4edda;
    padding: 2px 8px;
    border-radius: 5px;
}

code {
    background: #f8f9fa;
    padding: 2px 6px;
    border-radius: 4px;
    font-family: 'Courier New', monospace;
    white-space: pre-wrap;
    word-break: break-word;
    border: 1px solid #e9ecef;
}

ul {
    padding-left: 20px;
}

li {
    margin-bottom: 5px;
}

@media (max-width: 768px) {
    body {
        padding: 10px;
    }
    h1 {
        font-size: 2em;
    }
    .summary, .card {
        padding: 20px;
    }
}
</style>
</head>
<body>
<h1>LowHangingFruits Threat Report</h1>
""" + summary_html + ''.join(rows) + """
</body>
</html>
"""


async def scan_many_targets(targets: list, discover_subdomains: bool, use_crtsh: bool, use_subfinder: bool):
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    results = []

    async def bounded_scan(target):
        async with semaphore:
            return await scan_target(
                target,
                discover_subdomains=discover_subdomains,
                use_crtsh=use_crtsh,
                use_subfinder=use_subfinder
            )

    tasks = [bounded_scan(target) for target in targets]

    with tqdm(total=len(tasks), desc="Scanning", unit="target") as pbar:
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            pbar.update(1)

    return results


def read_targets_from_file(file_path: str) -> list:
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip()]
    except OSError as exc:
        print(f"Failed to read input file: {exc}")
        sys.exit(1)


def save_json(results: list, output_file: str = None, targets: list = None):
    try:
        if output_file:
            final_path = Path(output_file)
        else:
            final_path = build_output_filename(targets or ["scan"], "json")

        with open(final_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)

        print(f"\nSaved JSON output to {final_path}")
    except OSError as exc:
        print(f"Failed to write JSON output file: {exc}")


def save_html(results: list, html_file: str = None, targets: list = None):
    try:
        if html_file:
            final_path = Path(html_file)
        else:
            final_path = build_output_filename(targets or ["scan"], "html")

        html_content = build_html_report(results)

        with open(final_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)

        print(f"Saved HTML report to {final_path}")
    except OSError as exc:
        print(f"Failed to write HTML output file: {exc}")


async def async_main():
    parser = argparse.ArgumentParser(description="LowHangingFruits - Async external web attack surface triage tool")
    parser.add_argument("-t", "--target", action="append", help="Single target URL/domain, can be used multiple times")
    parser.add_argument("-f", "--file", help="File containing target URLs/domains, one per line")
    parser.add_argument("-o", "--output", help="Write JSON results to file")
    parser.add_argument("--html", nargs="?", const="", help="Write HTML report to file")
    parser.add_argument("--subdomains", action="store_true", help="Enable subdomain discovery")
    parser.add_argument("--crtsh", action="store_true", help="Use crt.sh for subdomain discovery")
    parser.add_argument("--subfinder", action="store_true", help="Use subfinder for subdomain discovery")
    args = parser.parse_args()

    targets = []

    if args.target:
        targets.extend(args.target)

    if args.file:
        targets.extend(read_targets_from_file(args.file))

    targets = unique_preserve_order(targets)

    if not targets:
        parser.error("Provide at least one target with -t or use -f")

    use_crtsh = args.crtsh or (args.subdomains and not args.subfinder)
    use_subfinder = args.subfinder

    results = await scan_many_targets(
        targets=targets,
        discover_subdomains=args.subdomains,
        use_crtsh=use_crtsh,
        use_subfinder=use_subfinder
    )

    for result in results:
        print_human_output(result)

    save_json(results, args.output, targets)

    if args.html is not None:
        html_path = args.html if args.html else None
        save_html(results, html_path, targets)


def main():
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")


if __name__ == "__main__":
    main()