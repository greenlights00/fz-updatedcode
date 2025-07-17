# v-host

import argparse
import requests
import sys
import time
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import url_validate_and_normalize, load_wordlist, log_error
from urllib.parse import urlparse

# --- Configuration Constants ---
# Our trusty User-Agent. Makes our requests look like they're coming from a normal browser.
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0); Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"

# A list of common Host header values that might reveal hidden or default virtual hosts.
COMMON_HOST_BYPASSES = [
    "localhost", "127.0.0.1", "::1", "burp", "test", "dev", "staging", "admin", "api",
    "internal", "assets", "mail", "owa", "vpn", "proxy", "cdn", "debug",
]

# Alternative X-Forwarded-Host headers, commonly processed by proxies/load balancers.
X_FORWARDED_HOST_HEADERS = [
    "X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-HTTP-Host-Override", "Forwarded",
]

# --- Default Wordlists ---

# A solid collection of common subdomain prefixes. Our go-to if no custom list is provided.
DEFAULT_SUBDOMAIN_WORDLIST = [
    "www", "dev", "test", "staging", "api", "admin", "mail", "blog", "shop", "portal",
    "app", "secure", "vpn", "login", "dashboard", "intranet", "extranet", "beta", "cdn",
    "files", "docs", "prod", "qa", "demo", "assets", "media", "status", "monitor",
    "analytics", "support", "help", "wiki", "cpanel", "webmail", "ftp", "sftp", "ssh",
    "git", "repo", "jenkins", "jira", "confluence", "proxy", "gateway", "internal",
    "external", "private", "public", "test-env", "dev-env", "qa-env", "staging-env",
    "production", "backup", "archive", "data", "db", "sql", "mongo", "elastic", "redis",
    "cache", "queue", "loadbalancer", "router", "firewall", "security", "testbed", "build",
    "ci", "cd", "pipeline", "deploy", "uat", "dr", "recovery", "site", "store", "crm",
    "erp", "hr", "billing", "payment", "checkout", "order", "account", "user", "customer",
    "partner", "vendor", "feedback", "events", "news", "media", "gallery", "img", "video",
    "audio", "download", "upload", "report", "metrics", "stats", "graph", "chart", "panel",
    "management", "control", "system", "config", "setup", "install", "update", "patch",
    "hotfix", "release", "alpha", "gamma", "omega", "matrix", "service", "customer-service",
    "sales", "marketing", "finance", "legal", "compliance", "audit", "devops", "it",
    "engineering", "research", "development", "innovation", "labs", "project", "task",
    "forum", "community", "chat", "meeting", "conference", "webinar", "training", "edu",
    "education", "elearning", "lms", "wiki", "knowledge", "docs", "manual", "guide", "faq",
    "troubleshoot", "debug", "monitor", "alert", "notify", "log", "trace", "debug",
    "metric", "stream", "feed", "push", "sync", "mirror", "replica", "master", "slave",
    "primary", "secondary", "node", "cluster", "worker", "agent", "client", "host",
    "server", "db-server", "app-server", "web-server", "mail-server", "dns-server",
    "ntp-server", "sso", "auth", "identity", "license", "billing-portal", "customer-portal"
]

# Our extensive list for Host header enumeration. A solid starting point for finding hidden vhosts.
DEFAULT_VHOST_WORDLIST = [
    "localhost", "127.0.0.1", "::1", "test.local", "dev.local", "admin.local",
    "internal.domain.com", "dev.domain.com", "staging.domain.com", "prod.domain.com",
    "test.app.com", "dev.app.com", "api.app.com", "app.internal", "dashboard.internal",
    "control.panel", "management.portal", "service.gateway", "hidden.site", "secret.app",
    "confidential.data", "private.api", "jenkins.server", "jira.instance",
    "confluence.wiki", "mail.server", "owa.exchange", "vpn.access", "proxy.server",
    "cdn.cache", "debug.tool", "monitoring.console", "analytics.dashboard",
    "support.system", "helpdesk.portal", "wiki.docs", "cpanel.hosting", "webmail.access",
    "ftp.upload", "sftp.data", "ssh", "git", "repo", "ci.build", "cd.deploy",
    "pipeline.status", "deploy.env", "uat.testing", "dr.site", "recovery.plan", "site.main",
    "store.online", "crm.system", "erp.suite", "hr.portal", "billing.platform",
    "payment.gateway", "checkout.process", "order.tracking", "account.manager",
    "user.profile", "customer.support", "partner.connect", "vendor.portal",
    "feedback.form", "events.calendar", "news.feed", "media.library", "gallery.photos",
    "img.storage", "video.streaming", "audio.clips", "download.center", "upload.files",
    "report.generator", "metrics.display", "stats.summary", "graph.visuals", "chart.data",
    "panel.control", "management.tools", "control.center", "system.info", "config.manager",
    "setup.wizard", "install.package", "update.service", "patch.manager", "hotfix.deploy",
    "release.notes", "alpha.build", "beta.release", "gamma.test", "omega.version",
    "matrix.system", "service.desk", "customer.care", "sales.platform", "marketing.suite",
    "finance.module", "legal.docs", "compliance.center", "audit.report", "devops.tools",
    "it.operations", "engineering.hub", "research.data", "development.area",
    "innovation.lab", "project.tracker", "task.management", "forum.discussion",
    "community.space", "chat.platform", "meeting.room", "conference.app",
    "webinar.platform", "training.portal", "edu.resource", "education.hub",
    "elearning.platform", "lms.system", "knowledge.base", "docs.library", "manual.guide",
    "faq.page", "troubleshoot.tool", "debug.log", "monitor.status", "alert.system",
    "notify.service", "log.viewer", "trace.analyzer", "metric.collector", "stream.data",
    "feed.reader", "push.service", "sync.engine", "mirror.site", "replica.db", "master.node",
    "slave.node", "primary.server", "secondary.server", "node.manager", "cluster.controller",
    "worker.queue", "agent.host", "client.interface", "host.manager", "server.farm",
    "db.cluster", "app.farm", "web.farm", "mail.cluster", "dns.service", "ntp.sync",
    "sso.provider", "auth.system", "identity.service", "license.manager", "billing.api"
]

# --- Utility Functions ---

def print_banner():
    """Kicks things off with a fancy banner for the tool."""
    print("\n" + "="*50)
    print("        Virtual Host Enumerator Tool        ")
    print("            Developed In-House            ")
    print("="*50 + "\n")

def calculate_response_hash(response_content):
    """Generates a unique fingerprint (SHA256 hash) for web page content, crucial for spotting differences."""
    return hashlib.sha256(response_content).hexdigest()

def parse_custom_headers(header_string):
    """Turns a comma-separated string of custom headers into a proper dictionary. Super flexible!"""
    headers = {}
    if header_string:
        for header_pair in header_string.split(','):
            if ':' in header_pair:
                key, value = header_pair.split(':', 1)
                headers[key.strip()] = value.strip()
    return headers

def send_request(url, method="GET", headers=None, allow_redirects=True, timeout=10, verify_ssl=False):
    """
    Sends an HTTP request. This is the workhorse, handling connections and basic error catching.

    Args:
        url (str): Where are we sending this request?
        method (str): GET, POST, you name it.
        headers (dict): Any special HTTP headers to include.
        allow_redirects (bool): Should we follow redirects (301, 302)? Sometimes we want to see them explicitly!
        timeout (int): How long until we give up on a response? (seconds)
        verify_ssl (bool): Validate SSL certificates? Good practice, but sometimes turned off for tricky labs.

    Returns:
        requests.Response: The web server's reply, or `None` if things went south.
    """
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            allow_redirects=allow_redirects,
            timeout=timeout,
            verify=verify_ssl
        )
        return response
    except requests.exceptions.Timeout:
        sys.stderr.write(f"[*] Request to {url} timed out.\n")
    except requests.exceptions.ConnectionError:
        sys.stderr.write(f"[*] Connection error for {url}.\n")
    except requests.exceptions.RequestException as e:
        sys.stderr.write(f"[-] Request to {url} failed: {e}\n")
    return None

def extract_hostname(url):
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return parsed.netloc
    return url

# --- Enumeration Functions ---

def enumerate_subdomains(target_domain, subdomain_wordlist, args, custom_headers):
    """
    Kicks off the subdomain hunt. We're brute-forcing, checking if each potential subdomain responds.

    Args:
        target_domain (str): The primary domain we're targeting.
        subdomain_wordlist (list): The list of words to try as subdomains.
        args (argparse.Namespace): All the command-line settings.
        custom_headers (dict): Any extra headers we want to include in every request.

    Returns:
        list: All the active subdomains we managed to discover.
    """
    if not subdomain_wordlist:
        print("[-] Subdomain wordlist is empty. No subdomains to enumerate!")
        return []

    print(f"[+] Starting the subdomain reconnaissance for: {target_domain}")
    discovered_subdomains = []
    base_url_scheme = "https" if args.https else "http"

    # We use a ThreadPoolExecutor to send requests concurrently. It's much faster!
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for word in subdomain_wordlist:
            subdomain = f"{word}.{target_domain}"
            url = f"{base_url_scheme}://{subdomain}"
            # Combining default, custom, and Host-specific headers for a robust request.
            headers = {**{"User-Agent": DEFAULT_USER_AGENT}, **custom_headers, "Host": subdomain}
            futures.append(executor.submit(send_request, url, headers=headers, verify_ssl=args.verify_ssl))

        # As requests complete, we check their responses for signs of life.
        for future in as_completed(futures):
            response = future.result()
            if response:
                if args.verbose:
                    print(f"    [->] Checked {response.url} - Status: {response.status_code}")
                # A successful HTTP response usually means we found an active subdomain!
                print(f"[+] Found active subdomain: {response.url} (Status: {response.status_code})")
                discovered_subdomains.append(response.url)

            # A brief pause to be polite and avoid overwhelming the target.
            if args.delay:
                time.sleep(args.delay)

    print(f"[+] Subdomain enumeration complete. Discovered {len(discovered_subdomains)} active subdomains.")
    return discovered_subdomains

def enumerate_vhosts_via_host_header(target_ip_or_domain, vhost_wordlist, args, custom_headers):
    """
    This is where the magic happens for finding hidden virtual hosts.
    We try different 'Host' headers against the target IP/domain, looking for unique responses.

    Args:
        target_ip_or_domain (str): The IP or domain where the server resides.
        vhost_wordlist (list): Our list of potential virtual host names to try.
        args (argparse.Namespace): All the scanner settings.
        custom_headers (dict): Any additional headers to send with each request.

    Returns:
        list: A curated list of virtual hosts that showed distinct content or behavior.
    """
    if not vhost_wordlist:
        print("[-] Virtual host wordlist is empty. No hidden vhosts to uncover!")
        return []

    # Always use just the hostname (no protocol)
    hostname = extract_hostname(target_ip_or_domain)
    print(f"[+] Initiating virtual host discovery on: {hostname}")
    discovered_vhosts = []
    base_url_scheme = "https" if args.https else "http"
    target_url = f"{base_url_scheme}://{hostname}:{args.port}"

    # First, we grab a 'baseline' response. This is what the server typically serves.
    # We'll compare all subsequent responses to this to identify unique content.
    print(f"[*] Grabbing baseline response from {target_url} with default Host header...")
    baseline_headers = {**{"User-Agent": DEFAULT_USER_AGENT}, **custom_headers, "Host": hostname}
    baseline_response = send_request(target_url, headers=baseline_headers, verify_ssl=args.verify_ssl)

    if not baseline_response:
        print("[-] Uh oh, couldn't even get a baseline response. VHost scanning might be unreliable.", file=sys.stderr)
        baseline_content_hash = ""
        baseline_status_code = None
        baseline_content_length = None
    else:
        baseline_content_hash = calculate_response_hash(baseline_response.content)
        baseline_status_code = baseline_response.status_code
        baseline_content_length = len(baseline_response.content)
        print(f"[*] Baseline details: Status={baseline_status_code}, Length={baseline_content_length}, Hash={baseline_content_hash[:8]}...")

    # Combining our wordlist with common bypasses to maximize discovery potential.
    wordlist_to_test = list(set(vhost_wordlist + COMMON_HOST_BYPASSES))

    # Preparing status codes to filter out, if specified.
    exclude_status_codes = []
    if args.exclude_status:
        try:
            exclude_status_codes = [int(code.strip()) for code in args.exclude_status.split(',')]
            print(f"[*] Responses with status codes {exclude_status_codes} will be ignored.")
        except ValueError:
            print(f"[-] Warning: Invalid status code in --exclude-status. Ignoring status filter.", file=sys.stderr)

    # Launching concurrent requests to speed up the process.
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for host_candidate in wordlist_to_test:
            # Test with the candidate in the standard Host header.
            headers_host = {**{"User-Agent": DEFAULT_USER_AGENT}, **custom_headers, "Host": host_candidate}
            futures.append(executor.submit(send_request, target_url, headers=headers_host, verify_ssl=args.verify_ssl, allow_redirects=False))

            # Also try various X-Forwarded-Host headers. This is a common trick!
            for x_header in X_FORWARDED_HOST_HEADERS:
                headers_x_forwarded = {
                    **{"User-Agent": DEFAULT_USER_AGENT},
                    **custom_headers,
                    "Host": hostname, # Keep the original Host for routing.
                    x_header: host_candidate
                }
                futures.append(executor.submit(send_request, target_url, headers=headers_x_forwarded, verify_ssl=args.verify_ssl, allow_redirects=False))

        for future in as_completed(futures):
            response = future.result()
            if response:
                # Filter out responses based on status code, if configured.
                if response.status_code in exclude_status_codes:
                    if args.verbose:
                        print(f"    [->] Filtered out Status {response.status_code} for Host: {response.request.headers.get('Host', 'N/A')}")
                    continue

                # Filter out responses based on content string, if configured.
                if args.exclude_content and args.exclude_content.lower() in response.text.lower():
                    if args.verbose:
                        print(f"    [->] Filtered out content match for Host: {response.request.headers.get('Host', 'N/A')}")
                    continue

                current_hash = calculate_response_hash(response.content)
                current_length = len(response.content)
                
                # Comparing the current response to our baseline.
                is_different = (
                    response.status_code != baseline_status_code or
                    current_length != baseline_content_length or
                    current_hash != baseline_content_hash
                )
                
                # Redirects (3xx) are usually a strong indicator of a unique vhost.
                if response.status_code >= 300 and response.status_code < 400:
                    is_different = True 

                # Extracting headers used for reporting.
                host_header_sent = response.request.headers.get("Host", "N/A")
                x_forwarded_header_sent = {k:v for k,v in response.request.headers.items() if k in X_FORWARDED_HOST_HEADERS}

                if is_different:
                    # Hooray, we found something! Recording all the juicy details.
                    vhost_info = {
                        "vulnerability": "Vhost Admin Access or Unique Vhost Response",
                        "endpoint": response.url,
                        "evidence": f"Status: {response.status_code}, Length: {current_length}, Host: {host_header_sent}",
                        "request": {
                            "method": "GET",
                            "url": response.url,
                            "headers": dict(response.request.headers),
                            "body": None
                        },
                        "response_snippet": response.text[:200],
                        "Host_Header_Used": host_header_sent,
                        "X_Forwarded_Headers_Used": x_forwarded_header_sent if x_forwarded_header_sent else "None",
                        "Status_Code": response.status_code,
                        "Reason": response.reason,
                        "Content_Length": current_length,
                        "Content_Hash_Prefix": current_hash[:8],
                        "Baseline_Comparison": "DIFFERENT",
                        "Redirect_Location": response.headers.get('Location') if response.status_code >= 300 and response.status_code < 400 else "N/A"
                    }
                    discovered_vhosts.append(vhost_info)
                    x_fwd_str = ", ".join([f"{k}: {v}" for k, v in x_forwarded_header_sent.items()]) if x_forwarded_header_sent else ""
                    print(f"[+] **FOUND VHOST:** Host='{host_header_sent}' {f'(X-Forwarded: {x_fwd_str})' if x_fwd_str else ''} -> Status={response.status_code} ({response.reason}), Length={current_length}")
                elif args.verbose:
                    print(f"    [->] Host='{host_header_sent}' -> Status={response.status_code} ({response.reason}), Length={current_length} (Looks like the baseline)")
            
            # Short break before the next request.
            if args.delay:
                time.sleep(args.delay)

    print(f"[+] Virtual host enumeration complete. Discovered {len(discovered_vhosts)} potential virtual hosts.")
    return discovered_vhosts

class VHostEnumerator:
    def __init__(self, config: dict):
        # Only use the hostname for vhost enumeration
        raw_target = config.get('target', config.get('url'))
        self.target = extract_hostname(raw_target)
        self.port = config.get('port', 80)
        self.https = config.get('https', False)
        self.verify_ssl = config.get('verify_ssl', False)
        self.threads = config.get('threads', 10)
        self.delay = config.get('delay', 0.1)
        self.verbose = config.get('verbose', False)
        self.silent = config.get('silent', False)
        self.subdomains_wordlist = config.get('subdomains_wordlist')
        self.vhosts_wordlist = config.get('vhosts_wordlist')
        self.custom_headers = config.get('custom_headers', {})
        self.exclude_status = config.get('exclude_status')
        self.exclude_content = config.get('exclude_content')
        self.wordlist_data = config.get('wordlist_data')  # Optional: in-memory wordlist
        self.log_file = config.get('log_file', 'fuzzer.log')

    def run(self) -> dict:
        """
        Orchestrator-friendly entry point: runs vhost enumeration and returns results as a dict.
        Handles errors and supports silent/verbose operation.
        """
        class Args:
            pass
        args = Args()
        args.port = self.port
        args.https = self.https
        args.verify_ssl = self.verify_ssl
        args.threads = self.threads
        args.delay = self.delay
        args.verbose = self.verbose
        args.exclude_status = self.exclude_status
        args.exclude_content = self.exclude_content

        findings = []
        errors = []
        try:
            if not self.silent:
                print(f"[VHost] Starting virtual host enumeration for {self.target}:{self.port}")
            # Prepare wordlist
            vhost_wordlist = self.wordlist_data if self.wordlist_data is not None else (
                load_wordlist(self.vhosts_wordlist, DEFAULT_VHOST_WORDLIST) if self.vhosts_wordlist else DEFAULT_VHOST_WORDLIST
            )
            # Prepare custom headers
            custom_headers = self.custom_headers if isinstance(self.custom_headers, dict) else parse_custom_headers(self.custom_headers)
            # Run enumeration
            discovered_vhosts = enumerate_vhosts_via_host_header(self.target, vhost_wordlist, args, custom_headers)
            findings.extend(discovered_vhosts)
            # Log each finding
            with open(self.log_file, 'a', encoding='utf-8') as logf:
                for finding in findings:
                    logf.write(json.dumps({'module': 'vhost', 'finding': finding}) + '\n')
            if not self.silent:
                print(f"[VHost] Enumeration complete. {len(findings)} vhosts found.")
            return {
                'findings': findings,
                'errors': errors,
                'target': self.target,
                'port': self.port,
                'https': self.https
            }
        except Exception as e:
            log_error(None, f"[VHost] Enumeration failed: {e}")
            errors.append(str(e))
            return {
                'findings': findings,
                'errors': errors,
                'target': self.target,
                'port': self.port,
                'https': self.https
            }

# --- Main Execution Logic ---

def main():
    print_banner()

    # Setting up our command-line argument parser. This makes the tool easy to use!
    parser = argparse.ArgumentParser(
        description="An in-house Virtual Host Pentesting Tool for robust enumeration.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Core arguments that define our target and how we interact with it.
    parser.add_argument("-t", "--target", required=True,
                        help="Target domain (e.g., example.com) or IP address (e.g., 192.168.1.1).")
    parser.add_argument("-p", "--port", type=int, default=80,
                        help="Target port (default: 80).")
    parser.add_argument("--https", action="store_true",
                        help="Use HTTPS for connections instead of HTTP.")
    parser.add_argument("--verify-ssl", action="store_true",
                        help="Verify SSL certificates when using HTTPS. Recommended for production environments.")
    parser.add_argument("--threads", type=int, default=10,
                        help="Number of concurrent threads for requests (default: 10). More threads can be faster, but also riskier for the target.")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Delay in seconds between requests (default: 0.1). Helps prevent rate limiting and detection.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enables verbose output, showing all checked permutations and filtered responses.")

    # Arguments to control which enumeration types to run and what wordlists to use.
    parser.add_argument("--subdomains-wordlist",
                        help="Path to a custom wordlist for subdomain brute-forcing. Uses built-in defaults if not provided.")
    parser.add_argument("--vhosts-wordlist",
                        help="Path to a custom wordlist for virtual host (Host header) brute-forcing. Uses built-in defaults if not provided.")
    parser.add_argument("--output",
                        help="Path to save results in JSON format. Highly recommended for analysis!")
    
    # Advanced features for fine-tuning our scans.
    parser.add_argument("--custom-headers",
                        help="Add custom HTTP headers (e.g., 'X-Custom-Header:value,Another:value2'). Handy for bypassing WAFs or custom auth.")
    parser.add_argument("--exclude-status",
                        help="Comma-separated HTTP status codes to exclude from results (e.g., '404,500'). Filters out noise.")
    parser.add_argument("--exclude-content",
                        help="Case-insensitive string to filter out responses containing this text in the body. Great for ignoring default pages.")

    args = parser.parse_args()

    # Parsing any custom headers provided by the user.
    parsed_custom_headers = {}
    if args.custom_headers:
        parsed_custom_headers = parse_custom_headers(args.custom_headers)

    # FIX: If HTTPS is enabled and port is still default 80, switch to 443.
    # This ensures HTTPS traffic goes to the correct port unless specified otherwise.
    if args.https and args.port == 80:
        args.port = 443
        print("[*] Automatically switching to port 443 for HTTPS connections.")


    # A quick sanity check to ensure we have something to scan.
    if not args.subdomains_wordlist and not args.vhosts_wordlist and \
       not (DEFAULT_SUBDOMAIN_WORDLIST or DEFAULT_VHOST_WORDLIST):
        print("[-] Error: No enumeration type selected. You need to provide a custom wordlist or rely on the default ones.", file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    # Printing a summary of the scan configuration.
    print(f"[*] Target: {args.target}")
    print(f"[*] Port: {args.port}")
    print(f"[*] Protocol: {'HTTPS' if args.https else 'HTTP'}")
    print(f"[*] SSL Verification: {'On' if args.verify_ssl and args.https else 'Off (or N/A for HTTP)'}")
    print(f"[*] Concurrent requests (threads): {args.threads}")
    print(f"[*] Delay per request: {args.delay} seconds")
    print(f"[*] Verbose Mode: {'On' if args.verbose else 'Off'}")
    if parsed_custom_headers:
        print(f"[*] Custom Headers: {parsed_custom_headers}")
    if args.exclude_status:
        print(f"[*] Excluding Status Codes: {args.exclude_status}")
    if args.exclude_content:
        print(f"[*] Excluding Content Containing: '{args.exclude_content}'")
    print("-" * 50)

    all_results = {} # This will store all our findings.

    # --- Subdomain Enumeration ---
    # Load the wordlist, preferring custom over default.
    subdomain_wordlist = load_wordlist(args.subdomains_wordlist, DEFAULT_SUBDOMAIN_WORDLIST)
    if subdomain_wordlist:
        discovered_subdomains = enumerate_subdomains(args.target, subdomain_wordlist, args, parsed_custom_headers)
        all_results["Subdomains"] = discovered_subdomains
        print(f"\n[+] Total Discovered Subdomains: {len(discovered_subdomains)}")
        for sub in discovered_subdomains:
            print(f"    - {sub}")
        print("-" * 50)
    else:
        print("[-] Subdomain enumeration skipped (empty wordlist).")

    # --- Virtual Host Enumeration ---
    # Load the wordlist, preferring custom over default.
    vhost_wordlist = load_wordlist(args.vhosts_wordlist, DEFAULT_VHOST_WORDLIST)
    if vhost_wordlist:
        discovered_vhosts = enumerate_vhosts_via_host_header(args.target, vhost_wordlist, args, parsed_custom_headers)
        all_results["Virtual_Hosts"] = discovered_vhosts
        print(f"\n[+] Total Potential Virtual Hosts Discovered: {len(discovered_vhosts)}")
        for vhost_info in discovered_vhosts:
            x_fwd_display = ", ".join([f"{k}: {v}" for k, v in vhost_info['X_Forwarded_Headers_Used'].items()]) if isinstance(vhost_info['X_Forwarded_Headers_Used'], dict) else vhost_info['X_Forwarded_Headers_Used']
            redirect_info = f" -> Redirect to: {vhost_info['Redirect_Location']}" if vhost_info['Redirect_Location'] != "N/A" else ""
            print(f"    - Host Header: {vhost_info['Host_Header_Used']}{', X-Forwarded: ' + x_fwd_display if x_fwd_display else ''}, Status: {vhost_info['Status_Code']} ({vhost_info['Reason']}), Length: {vhost_info['Content_Length']}{redirect_info}")
        print("-" * 50)
    else:
        print("[-] Virtual host enumeration skipped (empty wordlist).")

    # Saving all our findings to a JSON file, if specified.
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(all_results, f, indent=4)
            print(f"\n[+] Results saved to: {args.output}")
        except Exception as e:
            print(f"[-] Error saving results to file: {e}", file=sys.stderr)

    print("\n[+] Enumeration complete. Exiting.")

if __name__ == "__main__":
    main()
