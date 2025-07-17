import requests
import urllib.parse
import argparse
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Tuple
import json
import logging
from utils import url_validate_and_normalize, load_wordlist, log_error

DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 5
DEFAULT_METHOD = "GET"

def build_request(args, fuzz_value: str) -> Dict:
    url = args.url.replace("FUZZ", fuzz_value)
    headers = {k.split(":")[0]: k.split(":")[1].replace("FUZZ", fuzz_value)
               for k in args.header_template} if args.header_template else {}
    if args.content_type == "json":
        data = args.json_template.replace("FUZZ", fuzz_value)
        headers["Content-Type"] = "application/json"
    elif args.mode == "body":
        data = args.body_template.replace("FUZZ", fuzz_value)
    else:
        data = None
    return {
        "method": args.method.upper(),
        "url": url,
        "headers": headers,
        "data": data,
        "timeout": args.timeout,
        "allow_redirects": True
    }

def track_redirects(response: requests.Response) -> str:
    history = " → ".join(f"{r.status_code}" for r in response.history)
    return f"{history} → {response.status_code}" if response.history else f"{response.status_code}"

def send_request(args, fuzz_value: str, results: List[Dict], silent: bool):
    req = build_request(args, fuzz_value)
    try:
        response = requests.request(**req)
        final_status = track_redirects(response)
        content_length = len(response.content)
        if response.status_code in args.status_filter and content_length not in args.size_filter:
            result = {
                "vulnerability": "Interesting Parameter Response",
                "endpoint": req['url'],
                "evidence": f"Status: {response.status_code}, Content-Length: {content_length}",
                "request": {
                    "method": req['method'],
                    "url": req['url'],
                    "headers": req['headers'],
                    "body": req['data'] if 'data' in req else None
                },
                "response_snippet": response.text[:200],
                "response_code": response.status_code,
                "headers": dict(response.headers)
            }
            results.append(result)
            if not silent:
                print(f"[{final_status}] {req['url']} ({content_length} bytes)")
    except Exception as e:
        if not silent:
            print(f"Error with {req['url']}: {e}")

class ParameterFuzzer:
    def __init__(self, config: dict):
        self.url = url_validate_and_normalize(config.get('url'))
        self.wordlist = config.get('wordlist')
        self.method = config.get('method', DEFAULT_METHOD)
        self.mode = config.get('mode', 'path')
        self.threads = config.get('threads', DEFAULT_THREADS)
        self.timeout = config.get('timeout', DEFAULT_TIMEOUT)
        self.status_filter = config.get('status_filter', [200, 403])
        self.size_filter = config.get('size_filter', [])
        self.header_template = config.get('header_template', [])
        self.body_template = config.get('body_template', "")
        self.json_template = config.get('json_template', "")
        self.content_type = config.get('content_type', 'form')
        self.silent = config.get('silent', False)
        self.verbose = config.get('verbose', False)
        self.wordlist_data = config.get('wordlist_data')  # Optional: in-memory wordlist
        self.log_file = config.get('log_file', 'fuzzer.log')

    def run(self) -> dict:
        """
        Orchestrator-friendly entry point: runs parameter fuzzing and returns results as a dict.
        Handles errors and supports silent/verbose operation.
        Logs each finding to a log file as JSON.
        """
        class Args:
            pass
        args = Args()
        args.url = self.url
        args.method = self.method
        args.mode = self.mode
        args.threads = self.threads
        args.timeout = self.timeout
        args.status_filter = self.status_filter
        args.size_filter = self.size_filter
        args.header_template = self.header_template
        args.body_template = self.body_template
        args.json_template = self.json_template
        args.content_type = self.content_type
        args.silent = self.silent

        findings = []
        errors = []
        try:
            if not self.silent:
                print(f"[ParamFuzz] Starting parameter fuzzing for {self.url}")
            if self.wordlist_data is not None:
                wordlist = self.wordlist_data
            else:
                wordlist = load_wordlist(self.wordlist)
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = [executor.submit(send_request, args, word, findings, self.silent) for word in wordlist]
                for f in futures:
                    f.result()  # Wait for all to finish
            if not self.silent:
                print(f"[ParamFuzz] Fuzzing complete. {len(findings)} interesting responses found.")
            # Log each finding to the log file
            with open(self.log_file, 'a', encoding='utf-8') as logf:
                for finding in findings:
                    logf.write(json.dumps({'module': 'parameter', 'finding': finding}) + '\n')
            return {'findings': findings, 'errors': errors}
        except Exception as e:
            log_error(None, f"[ParamFuzz] Fuzzing failed: {e}")
            errors.append(str(e))
            return {'findings': findings, 'errors': errors}

def main():
    parser = argparse.ArgumentParser(description="Advanced Fuzzing Tool with Path/Body/Header/JSON support")
    parser.add_argument("--url", required=True, help="Target URL (use FUZZ as placeholder)")
    parser.add_argument("--wordlist", required=True, help="Wordlist path")
    parser.add_argument("--method", default=DEFAULT_METHOD, help="HTTP method to use")
    parser.add_argument("--mode", choices=["param-name", "param-value", "path", "body", "json"], required=True, help="Fuzzing mode")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Thread count")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout in seconds")
    parser.add_argument("--status-filter", type=int, nargs="+", default=[200, 403], help="Status codes to show")
    parser.add_argument("--size-filter", type=int, nargs="*", default=[], help="Response sizes to ignore")
    parser.add_argument("--header-template", nargs="*", default=[], help="Headers to inject (use FUZZ)")
    parser.add_argument("--body-template", default="", help="Body template (use FUZZ)")
    parser.add_argument("--json-template", default="", help="JSON body (use FUZZ)")
    parser.add_argument("--content-type", choices=["form", "json"], default="form", help="Content-Type for body/json")
    parser.add_argument("--silent", action="store_true", help="Suppress request errors")
    args = parser.parse_args()

    wordlist = load_wordlist(args.wordlist)
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(send_request, args, word, results, args.silent) for word in wordlist]
        for f in futures:
            f.result()

if __name__ == "__main__":
    main()
