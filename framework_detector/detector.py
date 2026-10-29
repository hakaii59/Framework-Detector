"""Core detection engine."""

import base64
import json
import re
import sys
import urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.exceptions import RequestException

from framework_detector.signatures import SIGNATURES
from framework_detector.structures import DIRECTORY_STRUCTURES

requests.packages.urllib3.disable_warnings()

BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
DIM = "\033[2m"
RESET = "\033[0m"


class FrameworkDetector:
    def __init__(self, url, timeout=10, probe_paths=True, threads=10, verbose=False):
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme:
            url = "https://" + url
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.probe_paths = probe_paths
        self.threads = threads
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        )
        self.session.verify = False
        self.results = defaultdict(list)

    def log(self, msg):
        if self.verbose:
            print(f"  {DIM}[*] {msg}{RESET}", file=sys.stderr)

    def fetch(self, url):
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except RequestException as e:
            self.log(f"Request failed: {url} — {e}")
            return None

    @staticmethod
    def _is_laravel_encrypted(value):
        try:
            decoded = base64.b64decode(urllib.parse.unquote(value))
            obj = json.loads(decoded)
            return {"iv", "value", "mac"}.issubset(obj.keys())
        except Exception:
            return False

    def check_cookies(self, resp, framework, sigs):
        patterns = sigs.get("cookies", [])
        name_patterns = sigs.get("cookie_name_patterns", [])
        value_checks = sigs.get("cookie_value_checks", [])

        for cookie in resp.cookies:
            for pat in patterns:
                if re.search(pat, cookie.name, re.IGNORECASE):
                    self.results[framework].append(f"Cookie: {cookie.name}")

            for pat in name_patterns:
                if re.search(pat, cookie.name, re.IGNORECASE):
                    self.results[framework].append(
                        f"Cookie name pattern '{pat}': {cookie.name}"
                    )

            for check in value_checks:
                if check == "laravel_encrypted" and self._is_laravel_encrypted(cookie.value):
                    self.results[framework].append(
                        f"Cookie '{cookie.name}' has Laravel encrypted format (iv/value/mac)"
                    )

    def check_headers(self, resp, framework, patterns):
        for header, value in resp.headers.items():
            for pat in patterns:
                combined = f"{header}: {value}"
                if re.search(pat, combined, re.IGNORECASE):
                    self.results[framework].append(f"Header: {header}: {value}")

    def check_html(self, body, framework, patterns):
        for pat in patterns:
            match = re.search(pat, body, re.IGNORECASE)
            if match:
                snippet = match.group(0)[:80]
                self.results[framework].append(f"HTML: {snippet}")

    def check_error_pages(self, body, framework, patterns):
        for pat in patterns:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                snippet = m.group(0)[:60]
                self.results[framework].append(f"Error page: {snippet}")

    def probe_path(self, path):
        full = self.url + path
        self.log(f"Probing {full}")
        resp = self.fetch(full)
        if resp is None:
            return None
        return (path, resp.status_code, resp.text[:2000], resp.headers)

    def run(self):
        print(f"\n{BOLD}{'='*60}")
        print(f"  Framework Detector v2.0")
        print(f"  Target: {CYAN}{self.url}{RESET}")
        print(f"{BOLD}{'='*60}{RESET}\n")

        # Phase 1: Main page
        print(f"{BOLD}[Phase 1]{RESET} Fetching main page...")
        resp = self.fetch(self.url)
        if resp is None:
            print(f"{RED}[!] Could not reach target. Aborting.{RESET}")
            return

        print(f"  Status:       {resp.status_code}")
        print(f"  Server:       {resp.headers.get('Server', 'N/A')}")
        print(f"  X-Powered-By: {resp.headers.get('X-Powered-By', 'N/A')}")
        cookies_str = ", ".join(c.name for c in resp.cookies) or "N/A"
        print(f"  Cookies:      {cookies_str}")

        body = resp.text

        for fw, sigs in SIGNATURES.items():
            self.check_cookies(resp, fw, sigs)
            self.check_headers(resp, fw, sigs["headers"])
            self.check_html(body, fw, sigs["html"])

        # Phase 2: Error page (trigger 404)
        print(f"\n{BOLD}[Phase 2]{RESET} Fetching 404 error page...")
        err_resp = self.fetch(self.url + "/th1s-p4g3-d0es-n0t-ex1st-xyzzy42")
        if err_resp:
            print(f"  Status: {err_resp.status_code}")
            err_body = err_resp.text
            for fw, sigs in SIGNATURES.items():
                self.check_error_pages(err_body, fw, sigs["error_pages"])
                self.check_headers(err_resp, fw, sigs["headers"])
                self.check_cookies(err_resp, fw, sigs)

        # Phase 3: Probe known paths
        if self.probe_paths:
            all_paths = set()
            for sigs in SIGNATURES.values():
                all_paths.update(sigs.get("paths", []))

            print(f"\n{BOLD}[Phase 3]{RESET} Probing {len(all_paths)} known paths...")

            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                futures = {pool.submit(self.probe_path, p): p for p in all_paths}
                for future in as_completed(futures):
                    result = future.result()
                    if result is None:
                        continue
                    path, status, body_snippet, headers = result
                    if status < 400:
                        for fw, sigs in SIGNATURES.items():
                            if path in sigs.get("paths", []):
                                self.results[fw].append(
                                    f"Path {GREEN}{status}{RESET}: {path}"
                                )

        self._print_report()

    def _print_report(self):
        print(f"\n{BOLD}{'='*60}")
        print(f"  RESULTS")
        print(f"{'='*60}{RESET}\n")

        if not self.results:
            print(f"  {DIM}No frameworks detected.")
            print(f"  The site may hide its stack or use custom code.{RESET}")
            return

        sorted_results = sorted(
            self.results.items(), key=lambda x: len(x[1]), reverse=True
        )

        for fw, evidence in sorted_results:
            unique = list(dict.fromkeys(evidence))
            count = len(unique)
            if count >= 3:
                color = GREEN
                level = "HIGH"
            elif count == 2:
                color = YELLOW
                level = "MED "
            else:
                color = DIM
                level = "LOW "

            bar = "#" * min(count * 3, 20)
            print(f"  {color}[{level}]{RESET} {bar:<20s} {BOLD}{fw}{RESET}")
            for e in unique:
                print(f"         {DIM}-{RESET} {e}")
            print()

        # Directory structures for detected frameworks
        detected = [fw for fw, _ in sorted_results if fw in DIRECTORY_STRUCTURES]
        if not detected:
            return

        print(f"{BOLD}{'='*60}")
        print(f"  DIRECTORY STRUCTURES & SENSITIVE PATHS")
        print(f"{'='*60}{RESET}")

        for fw in detected:
            info = DIRECTORY_STRUCTURES[fw]
            print(f"\n  {BOLD}{CYAN}[ {fw} ]{RESET}")

            print(f"\n  {BOLD}Directory Structure:{RESET}")
            print(info["tree"])

            paths = info.get("sensitive_paths", [])
            if paths:
                print(f"  {BOLD}{RED}Sensitive / Interesting Paths:{RESET}")
                for p in paths:
                    full = f"{self.url}{p}"
                    print(f"    {YELLOW}>{RESET} {p:<45s} {DIM}{full}{RESET}")
                print()
