import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor

# Config logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# Global configurations
MAX_THREADS = 10
TIMEOUT = 5
USER_AGENT = "Mozilla/5.0 (WebVulnScanner)"
HEADERS = {"User-Agent": USER_AGENT}

# Common payloads
SQLI_PAYLOADS = ["' OR '1'='1", "\" OR \"1\"=\"1", "'--", "\") OR 1=1--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]

scanned_links = set()
lock = threading.Lock()


def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)


def get_all_forms(url):
    try:
        res = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        soup = BeautifulSoup(res.content, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        logging.warning(f"Error fetching forms: {e}")
        return []


def get_form_details(form):
    details = {}
    try:
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all(["input", "textarea", "select"]):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            if input_name:
                inputs.append({"type": input_type, "name": input_name})
        details['action'] = action
        details['method'] = method
        details['inputs'] = inputs
    except Exception as e:
        logging.error(f"Error parsing form: {e}")
    return details


def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] in ["text", "search", "textarea"]:
            data[input["name"]] = payload
        else:
            data[input["name"]] = "test"

    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, headers=HEADERS, timeout=TIMEOUT)
        else:
            return requests.get(target_url, params=data, headers=HEADERS, timeout=TIMEOUT)
    except Exception as e:
        logging.warning(f"Form submission error: {e}")
        return None


def scan_sql_injection(url):
    logging.info("Scanning for SQL Injection")
    for payload in SQLI_PAYLOADS:
        test_url = f"{url}?vulntest={payload}"
        try:
            res = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT)
            if re.search("sql|syntax|mysql|error", res.text, re.IGNORECASE):
                logging.critical(f"SQLi vulnerability found: {test_url}")
        except Exception:
            continue


def scan_xss(url):
    logging.info("Scanning for XSS")
    forms = get_all_forms(url)
    for form in forms:
        details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            res = submit_form(details, url, payload)
            if res and payload in res.text:
                logging.critical(f"XSS vulnerability found at: {urljoin(url, details['action'])}")
                break


def scan_csrf(url):
    logging.info("Scanning for CSRF")
    forms = get_all_forms(url)
    for form in forms:
        inputs = form.find_all("input")
        token_found = any("csrf" in input.attrs.get("name", "").lower() for input in inputs)
        if not token_found:
            logging.warning(f"Potential CSRF vulnerability: {url}")


def crawl_and_scan(base_url):
    logging.info(f"Starting scan on {base_url}")
    to_scan = [base_url]
    scanned_local = set()

    while to_scan:
        url = to_scan.pop()
        if url in scanned_local:
            continue
        scanned_local.add(url)

        with lock:
            if url not in scanned_links:
                scanned_links.add(url)
                logging.info(f"Scanning: {url}")
                scan_url(url)

        try:
            res = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            soup = BeautifulSoup(res.text, "html.parser")
            for a_tag in soup.find_all("a"):
                href = a_tag.attrs.get("href")
                full_url = urljoin(base_url, href)
                if is_valid_url(full_url) and urlparse(base_url).netloc in urlparse(full_url).netloc:
                    to_scan.append(full_url)
        except Exception as e:
            logging.warning(f"Crawling error: {e}")


def scan_url(url):
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        executor.submit(scan_sql_injection, url)
        executor.submit(scan_xss, url)
        executor.submit(scan_csrf, url)


def main():
    parser = argparse.ArgumentParser(description="Advanced Web Vulnerability Scanner")
    parser.add_argument("url", help="Target URL to scan")
    args = parser.parse_args()
    start = time.time()
    crawl_and_scan(args.url)
    end = time.time()
    logging.info(f"Scan completed in {end - start:.2f} seconds")


if __name__ == "__main__":
    main()
