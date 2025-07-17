import requests
from urllib.parse import urlparse, parse_qs

class WaybackEnumerator:
    def __init__(self, config):
        self.target = config.get('target')
        self.log_file = config.get('log_file', 'fuzzer.log')
        self.errors = []
        self.findings = []

    def run(self):
        if not self.target:
            self.errors.append('No target specified for Wayback enumeration.')
            return {'findings': self.findings, 'errors': self.errors}
        try:
            urls = self.query_wayback_urls(self.target)
            parsed = self.parse_urls(urls)
            self.findings = parsed
            self.log_findings(parsed)
        except Exception as e:
            self.errors.append(str(e))
        return {'findings': self.findings, 'errors': self.errors}

    def query_wayback_urls(self, domain):
        # Use the CDX API to get all URLs for the domain
        api = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
        resp = requests.get(api, timeout=15)
        if resp.status_code != 200:
            raise Exception(f"Wayback Machine API error: {resp.status_code}")
        data = resp.json()
        # First row is header
        urls = [row[0] for row in data[1:]]
        return urls

    def parse_urls(self, urls):
        unique_paths = set()
        unique_params = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                path = parsed.path
                if path:
                    unique_paths.add(path)
                params = parse_qs(parsed.query)
                for param in params:
                    unique_params.add(param)
            except Exception:
                continue
        return {
            'unique_paths': sorted(unique_paths),
            'unique_params': sorted(unique_params),
            'total_urls': len(urls)
        }

    def log_findings(self, findings):
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(f"[WaybackEnumerator] Findings for {self.target}: {findings}\n")
        except Exception:
            pass 

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python wayback.py <domain>")
        sys.exit(1)
    domain = sys.argv[1]
    config = {'target': domain, 'log_file': 'fuzzer.log'}
    enumerator = WaybackEnumerator(config)
    result = enumerator.run()
    print("Findings:", result['findings'])
    print("Errors:", result['errors']) 