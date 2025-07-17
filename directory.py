# dir and file

"""
Web Directory and ( File Fuzzer - to be implemented: wordlist not integrated)
A comprehensive directory and file discovery tool similar to Dirb/Gobuster


Status till 03/06/2025 : Directory enumeration on the basis of a basic wordlist works, file enumeration is yet to be implemented, wordlist not integrated as of now)
"""

import argparse
import requests
import threading
import time
import sys
import os
from urllib.parse import urljoin, urlparse
from queue import Queue
import random
from datetime import datetime
import json
from utils import url_validate_and_normalize, load_wordlist, log_error

class Colors:
  
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class WebFuzzer:
    def __init__(self, target_url, wordlist_path, threads=10, extensions=None, 
                 status_codes=None, timeout=10, delay=0, user_agent=None,
                 recursive=False, max_depth=3, output_file=None, follow_redirects=True,
                 show_redirect_chain=False, filter_redirects=True):
        
        self.target_url = target_url.rstrip('/')
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.extensions = extensions or ['']
        self.valid_status_codes = status_codes or [200, 204, 301, 302, 307, 401, 403, 405]
        self.timeout = timeout
        self.delay = delay
        self.recursive = recursive
        self.max_depth = max_depth
        self.output_file = output_file
        self.follow_redirects = follow_redirects
        self.show_redirect_chain = show_redirect_chain
        self.filter_redirects = filter_redirects
        
        # Results storage
        self.discovered_paths = []
        self.discovered_directories = []
        self.redirect_patterns = {}  
        self.total_requests = 0
        self.start_time = None
        
        # Threading
        self.queue = Queue()
        self.threads_list = []
        self.lock = threading.Lock()
        
        # Session configuration
        self.session = requests.Session()
        self.session.timeout = timeout
        
        # User agent rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101',
        ]
        
        if user_agent:
            self.session.headers.update({'User-Agent': user_agent})
        
        requests.packages.urllib3.disable_warnings()
        
    def load_wordlist(self):
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
            return words
        except FileNotFoundError:
            print(f"{Colors.RED}[ERROR]{Colors.END} Wordlist file not found: {self.wordlist_path}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.END} Error loading wordlist: {str(e)}")
            sys.exit(1)
    
    def generate_urls(self, base_url, words):
        urls = []
        for word in words:
            for ext in self.extensions:
                if ext:
                    url = urljoin(base_url + '/', word + '.' + ext.lstrip('.'))
                else:
                    url = urljoin(base_url + '/', word)
                urls.append((url, word, ext))
        return urls
    
    def follow_redirect_chain(self, url, max_redirects=10):
        redirect_chain = []
        current_url = url
        
        for i in range(max_redirects):
            try:
                if random.randint(1, 10) == 1:
                    self.session.headers.update({
                        'User-Agent': random.choice(self.user_agents)
                    })
                
                response = self.session.get(
                    current_url, 
                    allow_redirects=False,
                    verify=False,
                    timeout=self.timeout
                )
                
                redirect_info = {
                    'url': current_url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'headers': dict(response.headers),
                    'response_time': response.elapsed.total_seconds()
                }
                
                redirect_chain.append(redirect_info)
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location')
                    if location:
                        if location.startswith('/'):
                            parsed_url = urlparse(current_url)
                            current_url = f"{parsed_url.scheme}://{parsed_url.netloc}{location}"
                        elif location.startswith('http'):
                            current_url = location
                        else:
                            current_url = urljoin(current_url, location)
                        
                        if current_url in [info['url'] for info in redirect_chain]:
                            break
                    else:
                        break
                else:
                    break
                    
            except requests.exceptions.Timeout:
                break
            except requests.exceptions.ConnectionError:
                break
            except requests.exceptions.RequestException:
                break
        
        return redirect_chain
    
    def make_request(self, url):
        if self.follow_redirects:
            return self.follow_redirect_chain(url)
        else:
            try:
                if random.randint(1, 10) == 1:
                    self.session.headers.update({
                        'User-Agent': random.choice(self.user_agents)
                    })
                
                response = self.session.get(
                    url, 
                    allow_redirects=False,
                    verify=False,
                    timeout=self.timeout
                )
                
                return [{
                    'url': url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'headers': dict(response.headers),
                    'response_time': response.elapsed.total_seconds()
                }]
                
            except requests.exceptions.Timeout:
                return None
            except requests.exceptions.ConnectionError:
                return None
            except requests.exceptions.RequestException:
                return None
    
    def is_mass_redirect(self, redirect_chain):
        if not self.filter_redirects or len(redirect_chain) <= 1:
            return False
        
        final_response = redirect_chain[-1]
        final_url = final_response['url']
        
        with self.lock:
            if final_url in self.redirect_patterns:
                self.redirect_patterns[final_url] += 1
            else:
                self.redirect_patterns[final_url] = 1
        if self.redirect_patterns[final_url] > 5:
            return True
        mass_redirect_indicators = [
            'index.html', 'index.php', 'home.html', 'default.html',
            'login.html', 'login.php', 'main.html', 'main.php'
        ]
        
        for indicator in mass_redirect_indicators:
            if indicator in final_url.lower():
                return True
        
        return False
    
    def analyze_response(self, redirect_chain, url, word, ext):
        """Analyze response chain and determine if it's interesting"""
        if not redirect_chain:
            return False
        
        initial_response = redirect_chain[0]
        final_response = redirect_chain[-1]
        
        if self.is_mass_redirect(redirect_chain):
            return False
        
        final_status = final_response['status_code']
        
        if final_status not in self.valid_status_codes:
            if initial_response['status_code'] not in self.valid_status_codes:
                return False
        
        if self.is_false_positive(final_response):
            return False
        
        # Standardized finding object
        result = {
            'vulnerability': 'Interesting Directory/File',
            'endpoint': url,
            'evidence': f"Status: {final_status}, Content-Length: {final_response['content_length']}",
            'request': {
                'method': 'GET',
                'url': url,
                'headers': dict(self.session.headers),
                'body': None
            },
            'response_snippet': '',
            'initial_status': initial_response['status_code'],
            'final_status': final_status,
            'final_url': final_response['url'],
            'content_length': final_response['content_length'],
            'response_time': sum(resp['response_time'] for resp in redirect_chain),
            'redirect_chain': redirect_chain if len(redirect_chain) > 1 else None,
            'headers': final_response['headers']
        }
        # Try to get a snippet of the response body
        try:
            resp = self.session.get(url, allow_redirects=False, verify=False, timeout=self.timeout)
            result['response_snippet'] = resp.text[:200]
        except Exception:
            result['response_snippet'] = ''
        self.discovered_paths.append(result)
        
        final_url = final_response['url']
        if (final_url.endswith('/') or final_status in [301, 302] or 
            'text/html' in final_response['headers'].get('content-type', '')):
            self.discovered_directories.append(final_url)
            
        return True
    
    def is_false_positive(self, response_info):
        """Enhanced false positive detection"""
        
        content_length = response_info['content_length']
        status_code = response_info['status_code']
        
        if content_length < 50 and status_code not in [301, 302, 307]:
            return True
        
        content_type = response_info['headers'].get('content-type', '').lower()
        if 'text/plain' in content_type and content_length < 100:
            return True
                    
        return False
    
    def worker(self):
        """Worker thread function"""
        while True:
            try:
                item = self.queue.get(timeout=1)
                if item is None:
                    break
                    
                url, word, ext = item
                
                if self.delay > 0:
                    time.sleep(self.delay / 1000.0)  
                
                redirect_chain = self.make_request(url)
                
                with self.lock:
                    self.total_requests += 1
                    
                if redirect_chain and self.analyze_response(redirect_chain, url, word, ext):
                    self.print_result(redirect_chain, url)
                
                self.queue.task_done()
                
            except:
                break
    
    def print_result(self, redirect_chain, original_url):
        """Print discovered result with enhanced redirect information"""
        initial_response = redirect_chain[0]
        final_response = redirect_chain[-1]
        
        initial_status = initial_response['status_code']
        final_status = final_response['status_code']
        final_url = final_response['url']
        content_length = final_response['content_length']
        
        if final_status == 200:
            color = Colors.GREEN
        elif final_status in [301, 302, 307]:
            color = Colors.YELLOW
        elif final_status in [401, 403]:
            color = Colors.RED
        else:
            color = Colors.CYAN
        
        if self.show_redirect_chain and len(redirect_chain) > 1:
            result_line = f"{color}[{initial_status}→{final_status}]{Colors.END} {original_url}"
            if original_url != final_url:
                result_line += f" → {final_url}"
            result_line += f" ({content_length} bytes)"
            
            if len(redirect_chain) > 2:
                result_line += f"\n  {Colors.CYAN}Chain:{Colors.END} "
                chain_parts = []
                for i, resp in enumerate(redirect_chain):
                    if i == 0:
                        chain_parts.append(f"{resp['status_code']}")
                    else:
                        chain_parts.append(f"{resp['status_code']}")
                result_line += " → ".join(chain_parts)
        else:
            if initial_status != final_status:
                result_line = f"{color}[{initial_status}→{final_status}]{Colors.END} {original_url} ({content_length} bytes)"
            else:
                result_line = f"{color}[{final_status}]{Colors.END} {original_url} ({content_length} bytes)"
        
        print(result_line)
        
        if self.output_file:
            with open(self.output_file, 'a') as f:
                if initial_status != final_status:
                    f.write(f"[{initial_status}→{final_status}] {original_url} ({content_length} bytes)\n")
                else:
                    f.write(f"[{final_status}] {original_url} ({content_length} bytes)\n")
    
    def print_banner(self):
        banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    Web Directory Fuzzer                     ║
║                     Enhanced Implementation                  ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}

{Colors.BOLD}Target:{Colors.END}        {self.target_url}
{Colors.BOLD}Wordlist:{Colors.END}      {self.wordlist_path}
{Colors.BOLD}Threads:{Colors.END}       {self.threads}
{Colors.BOLD}Extensions:{Colors.END}    {', '.join(self.extensions) if self.extensions != [''] else 'None'}
{Colors.BOLD}Timeout:{Colors.END}       {self.timeout}s
{Colors.BOLD}Follow Redirects:{Colors.END} {'Yes' if self.follow_redirects else 'No'}
{Colors.BOLD}Show Redirect Chain:{Colors.END} {'Yes' if self.show_redirect_chain else 'No'}
{Colors.BOLD}Filter Mass Redirects:{Colors.END} {'Yes' if self.filter_redirects else 'No'}
{Colors.BOLD}Recursive:{Colors.END}     {'Yes' if self.recursive else 'No'}
        """
        print(banner)
    
    def print_summary(self):
        elapsed_time = time.time() - self.start_time
        
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}SCAN SUMMARY{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"Total Requests: {self.total_requests}")
        print(f"Discovered Paths: {len(self.discovered_paths)}")
        print(f"Elapsed Time: {elapsed_time:.2f} seconds")
        print(f"Requests/Second: {self.total_requests/elapsed_time:.2f}")
        
        if self.filter_redirects and self.redirect_patterns:
            print(f"\n{Colors.BOLD}REDIRECT PATTERNS DETECTED:{Colors.END}")
            sorted_patterns = sorted(self.redirect_patterns.items(), key=lambda x: x[1], reverse=True)
            for pattern, count in sorted_patterns[:5]: 
                if count > 2:
                    print(f"  {count} paths redirect to: {pattern}")
        
        if self.discovered_paths:
            print(f"\n{Colors.BOLD}DISCOVERED PATHS:{Colors.END}")
            for result in self.discovered_paths:
                if result['initial_status'] != result['final_status']:
                    status_color = Colors.GREEN if result['final_status'] == 200 else Colors.YELLOW
                    print(f"  {status_color}[{result['initial_status']}→{result['final_status']}]{Colors.END} {result['url']}")
                else:
                    status_color = Colors.GREEN if result['final_status'] == 200 else Colors.YELLOW
                    print(f"  {status_color}[{result['final_status']}]{Colors.END} {result['url']}")
    
    def run_recursive_scan(self, base_url, depth=1):
        if depth > self.max_depth:
            return
            
        print(f"\n{Colors.PURPLE}[INFO]{Colors.END} Scanning depth {depth}: {base_url}")
        
        words = self.load_wordlist()
        urls = self.generate_urls(base_url, words)
        
        for url_data in urls:
            self.queue.put(url_data)
        
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            self.threads_list.append(t)
        
        self.queue.join()
        
        if self.recursive and depth < self.max_depth:
            current_dirs = self.discovered_directories.copy()
            for directory in current_dirs:
                if directory.startswith(base_url):
                    self.run_recursive_scan(directory, depth + 1)
    
    def run(self):
        self.start_time = time.time()
        if not self.silent:
            self.print_banner()
        results = {
            'discovered_paths': [],
            'discovered_directories': [],
            'redirect_patterns': {},
            'total_requests': 0,
            'elapsed_time': 0,
            'errors': [],
        }
        try:
            if not self.silent:
                print(f"{Colors.BLUE}[INFO]{Colors.END} Testing target accessibility...")
            test_chain = self.make_request(self.target_url)
            if not test_chain:
                msg = f"Target is not accessible: {self.target_url}"
                if not self.silent:
                    print(f"{Colors.RED}[ERROR]{Colors.END} {msg}")
                self.errors.append(msg)
                results['errors'] = self.errors
                return results
            if not self.silent:
                print(f"{Colors.BLUE}[INFO]{Colors.END} Starting directory/file enumeration...")
            final_response = test_chain[-1]
            if len(test_chain) > 1:
                initial_status = test_chain[0]['status_code']
                final_status = final_response['status_code']
                print(f"{Colors.GREEN}[INFO]{Colors.END} Target is accessible ({initial_status}→{final_status})")
            else:
                print(f"{Colors.GREEN}[INFO]{Colors.END} Target is accessible (Status: {final_response['status_code']})")
            print(f"{Colors.BLUE}[INFO]{Colors.END} Starting directory/file enumeration...")
            if self.recursive:
                self.run_recursive_scan(self.target_url)
            else:
                words = self.load_wordlist()
                urls = self.generate_urls(self.target_url, words)
                for url_data in urls:
                    self.queue.put(url_data)
                for _ in range(self.threads):
                    t = threading.Thread(target=self.worker)
                    t.daemon = True
                    t.start()
                    self.threads_list.append(t)
                self.queue.join()
            results['discovered_paths'] = self.discovered_paths
            results['discovered_directories'] = self.discovered_directories
            results['redirect_patterns'] = self.redirect_patterns
            results['total_requests'] = self.total_requests
            results['elapsed_time'] = time.time() - self.start_time
            results['errors'] = self.errors
            return results
        except Exception as e:
            msg = f"Unexpected error: {str(e)}"
            if not self.silent:
                print(f"{Colors.RED}[ERROR]{Colors.END} {msg}")
            self.errors.append(msg)
            results['errors'] = self.errors
            return results

class DirectoryFuzzer:
    def __init__(self, config: dict):
        self.target_url = url_validate_and_normalize(config.get('url'))
        self.wordlist_path = config.get('wordlist')
        self.threads = config.get('threads', 10)
        self.extensions = config.get('extensions', [''])
        self.valid_status_codes = config.get('status_codes', [200, 204, 301, 302, 307, 401, 403, 405])
        self.timeout = config.get('timeout', 10)
        self.delay = config.get('delay', 0)
        self.recursive = config.get('recursive', False)
        self.max_depth = config.get('max_depth', 3)
        self.output_file = config.get('output_file')
        self.follow_redirects = config.get('follow_redirects', True)
        self.show_redirect_chain = config.get('show_redirect_chain', False)
        self.filter_redirects = config.get('filter_redirects', True)
        self.user_agent = config.get('user_agent')
        self.silent = config.get('silent', False)
        self.verbose = config.get('verbose', False)
        self.wordlist = config.get('wordlist_data')  # Optional: in-memory wordlist
        self.log_file = config.get('log_file', 'fuzzer.log')

        # Results storage
        self.discovered_paths = []
        self.discovered_directories = []
        self.redirect_patterns = {}
        self.total_requests = 0
        self.start_time = None
        self.errors = []

        # Threading
        self.queue = Queue()
        self.threads_list = []
        self.lock = threading.Lock()

        # Session configuration
        self.session = requests.Session()
        self.session.timeout = self.timeout
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101',
        ]
        if self.user_agent:
            self.session.headers.update({'User-Agent': self.user_agent})
        requests.packages.urllib3.disable_warnings()

    def load_wordlist(self):
        if self.wordlist is not None:
            return self.wordlist
        try:
            return load_wordlist(self.wordlist_path)
        except Exception as e:
            self.errors.append(f"Error loading wordlist: {str(e)}")
            log_error(None, f"Error loading wordlist: {str(e)}")
            return []

    def generate_urls(self, base_url, words):
        urls = []
        for word in words:
            for ext in self.extensions:
                if ext:
                    url = urljoin(base_url + '/', word + '.' + ext.lstrip('.'))
                else:
                    url = urljoin(base_url + '/', word)
                urls.append((url, word, ext))
        return urls

    def follow_redirect_chain(self, url, max_redirects=10):
        redirect_chain = []
        current_url = url
        
        for i in range(max_redirects):
            try:
                if random.randint(1, 10) == 1:
                    self.session.headers.update({
                        'User-Agent': random.choice(self.user_agents)
                    })
                
                response = self.session.get(
                    current_url, 
                    allow_redirects=False,
                    verify=False,
                    timeout=self.timeout
                )
                
                redirect_info = {
                    'url': current_url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'headers': dict(response.headers),
                    'response_time': response.elapsed.total_seconds()
                }
                
                redirect_chain.append(redirect_info)
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location')
                    if location:
                        if location.startswith('/'):
                            parsed_url = urlparse(current_url)
                            current_url = f"{parsed_url.scheme}://{parsed_url.netloc}{location}"
                        elif location.startswith('http'):
                            current_url = location
                        else:
                            current_url = urljoin(current_url, location)
                        
                        if current_url in [info['url'] for info in redirect_chain]:
                            break
                    else:
                        break
                else:
                    break
                    
            except requests.exceptions.Timeout:
                break
            except requests.exceptions.ConnectionError:
                break
            except requests.exceptions.RequestException:
                break
        
        return redirect_chain

    def make_request(self, url):
        if self.follow_redirects:
            return self.follow_redirect_chain(url)
        else:
            try:
                if random.randint(1, 10) == 1:
                    self.session.headers.update({
                        'User-Agent': random.choice(self.user_agents)
                    })
                
                response = self.session.get(
                    url, 
                    allow_redirects=False,
                    verify=False,
                    timeout=self.timeout
                )
                
                return [{
                    'url': url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'headers': dict(response.headers),
                    'response_time': response.elapsed.total_seconds()
                }]
                
            except requests.exceptions.Timeout:
                return None
            except requests.exceptions.ConnectionError:
                return None
            except requests.exceptions.RequestException:
                return None

    def is_mass_redirect(self, redirect_chain):
        if not self.filter_redirects or len(redirect_chain) <= 1:
            return False
        
        final_response = redirect_chain[-1]
        final_url = final_response['url']
        
        with self.lock:
            if final_url in self.redirect_patterns:
                self.redirect_patterns[final_url] += 1
            else:
                self.redirect_patterns[final_url] = 1
        if self.redirect_patterns[final_url] > 5:
            return True
        mass_redirect_indicators = [
            'index.html', 'index.php', 'home.html', 'default.html',
            'login.html', 'login.php', 'main.html', 'main.php'
        ]
        
        for indicator in mass_redirect_indicators:
            if indicator in final_url.lower():
                return True
        
        return False

    def analyze_response(self, redirect_chain, url, word, ext):
        """Analyze response chain and determine if it's interesting"""
        if not redirect_chain:
            return False
        
        initial_response = redirect_chain[0]
        final_response = redirect_chain[-1]
        
        if self.is_mass_redirect(redirect_chain):
            return False
        
        final_status = final_response['status_code']
        
        if final_status not in self.valid_status_codes:
            if initial_response['status_code'] not in self.valid_status_codes:
                return False
        
        if self.is_false_positive(final_response):
            return False
        
        # Standardized finding object
        result = {
            'vulnerability': 'Interesting Directory/File',
            'endpoint': url,
            'evidence': f"Status: {final_status}, Content-Length: {final_response['content_length']}",
            'request': {
                'method': 'GET',
                'url': url,
                'headers': dict(self.session.headers),
                'body': None
            },
            'response_snippet': '',
            'initial_status': initial_response['status_code'],
            'final_status': final_status,
            'final_url': final_response['url'],
            'content_length': final_response['content_length'],
            'response_time': sum(resp['response_time'] for resp in redirect_chain),
            'redirect_chain': redirect_chain if len(redirect_chain) > 1 else None,
            'headers': final_response['headers']
        }
        # Try to get a snippet of the response body
        try:
            resp = self.session.get(url, allow_redirects=False, verify=False, timeout=self.timeout)
            result['response_snippet'] = resp.text[:200]
        except Exception:
            result['response_snippet'] = ''
        self.discovered_paths.append(result)
        
        final_url = final_response['url']
        if (final_url.endswith('/') or final_status in [301, 302] or 
            'text/html' in final_response['headers'].get('content-type', '')):
            self.discovered_directories.append(final_url)
            
        return True

    def is_false_positive(self, response_info):
        """Enhanced false positive detection"""
        
        content_length = response_info['content_length']
        status_code = response_info['status_code']
        
        if content_length < 50 and status_code not in [301, 302, 307]:
            return True
        
        content_type = response_info['headers'].get('content-type', '').lower()
        if 'text/plain' in content_type and content_length < 100:
            return True
                    
        return False

    def worker(self):
        """Worker thread function"""
        while True:
            try:
                item = self.queue.get(timeout=1)
                if item is None:
                    break
                    
                url, word, ext = item
                
                if self.delay > 0:
                    time.sleep(self.delay / 1000.0)  
                
                redirect_chain = self.make_request(url)
                
                with self.lock:
                    self.total_requests += 1
                    
                if redirect_chain and self.analyze_response(redirect_chain, url, word, ext):
                    self.print_result(redirect_chain, url)
                
                self.queue.task_done()
                
            except:
                break

    def print_result(self, redirect_chain, original_url):
        """Print discovered result with enhanced redirect information"""
        initial_response = redirect_chain[0]
        final_response = redirect_chain[-1]
        
        initial_status = initial_response['status_code']
        final_status = final_response['status_code']
        final_url = final_response['url']
        content_length = final_response['content_length']
        
        if final_status == 200:
            color = Colors.GREEN
        elif final_status in [301, 302, 307]:
            color = Colors.YELLOW
        elif final_status in [401, 403]:
            color = Colors.RED
        else:
            color = Colors.CYAN
        
        if self.show_redirect_chain and len(redirect_chain) > 1:
            result_line = f"{color}[{initial_status}→{final_status}]{Colors.END} {original_url}"
            if original_url != final_url:
                result_line += f" → {final_url}"
            result_line += f" ({content_length} bytes)"
            
            if len(redirect_chain) > 2:
                result_line += f"\n  {Colors.CYAN}Chain:{Colors.END} "
                chain_parts = []
                for i, resp in enumerate(redirect_chain):
                    if i == 0:
                        chain_parts.append(f"{resp['status_code']}")
                    else:
                        chain_parts.append(f"{resp['status_code']}")
                result_line += " → ".join(chain_parts)
        else:
            if initial_status != final_status:
                result_line = f"{color}[{initial_status}→{final_status}]{Colors.END} {original_url} ({content_length} bytes)"
            else:
                result_line = f"{color}[{final_status}]{Colors.END} {original_url} ({content_length} bytes)"
        
        print(result_line)
        
        if self.output_file:
            with open(self.output_file, 'a') as f:
                if initial_status != final_status:
                    f.write(f"[{initial_status}→{final_status}] {original_url} ({content_length} bytes)\n")
                else:
                    f.write(f"[{final_status}] {original_url} ({content_length} bytes)\n")

    def print_banner(self):
        banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    Web Directory Fuzzer                     ║
║                     Enhanced Implementation                  ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}

{Colors.BOLD}Target:{Colors.END}        {self.target_url}
{Colors.BOLD}Wordlist:{Colors.END}      {self.wordlist_path}
{Colors.BOLD}Threads:{Colors.END}       {self.threads}
{Colors.BOLD}Extensions:{Colors.END}    {', '.join(self.extensions) if self.extensions != [''] else 'None'}
{Colors.BOLD}Timeout:{Colors.END}       {self.timeout}s
{Colors.BOLD}Follow Redirects:{Colors.END} {'Yes' if self.follow_redirects else 'No'}
{Colors.BOLD}Show Redirect Chain:{Colors.END} {'Yes' if self.show_redirect_chain else 'No'}
{Colors.BOLD}Filter Mass Redirects:{Colors.END} {'Yes' if self.filter_redirects else 'No'}
{Colors.BOLD}Recursive:{Colors.END}     {'Yes' if self.recursive else 'No'}
        """
        print(banner)

    def print_summary(self):
        elapsed_time = time.time() - self.start_time
        
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}SCAN SUMMARY{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"Total Requests: {self.total_requests}")
        print(f"Discovered Paths: {len(self.discovered_paths)}")
        print(f"Elapsed Time: {elapsed_time:.2f} seconds")
        print(f"Requests/Second: {self.total_requests/elapsed_time:.2f}")
        
        if self.filter_redirects and self.redirect_patterns:
            print(f"\n{Colors.BOLD}REDIRECT PATTERNS DETECTED:{Colors.END}")
            sorted_patterns = sorted(self.redirect_patterns.items(), key=lambda x: x[1], reverse=True)
            for pattern, count in sorted_patterns[:5]: 
                if count > 2:
                    print(f"  {count} paths redirect to: {pattern}")
        
        if self.discovered_paths:
            print(f"\n{Colors.BOLD}DISCOVERED PATHS:{Colors.END}")
            for result in self.discovered_paths:
                if result['initial_status'] != result['final_status']:
                    status_color = Colors.GREEN if result['final_status'] == 200 else Colors.YELLOW
                    print(f"  {status_color}[{result['initial_status']}→{result['final_status']}]{Colors.END} {result['url']}")
                else:
                    status_color = Colors.GREEN if result['final_status'] == 200 else Colors.YELLOW
                    print(f"  {status_color}[{result['final_status']}]{Colors.END} {result['url']}")
    
    def run_recursive_scan(self, base_url, depth=1):
        if depth > self.max_depth:
            return
            
        print(f"\n{Colors.PURPLE}[INFO]{Colors.END} Scanning depth {depth}: {base_url}")
        
        words = self.load_wordlist()
        urls = self.generate_urls(base_url, words)
        
        for url_data in urls:
            self.queue.put(url_data)
        
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            self.threads_list.append(t)
        
        self.queue.join()
        
        if self.recursive and depth < self.max_depth:
            current_dirs = self.discovered_directories.copy()
            for directory in current_dirs:
                if directory.startswith(base_url):
                    self.run_recursive_scan(directory, depth + 1)
    
    def run(self):
        self.start_time = time.time()
        if not self.silent:
            self.print_banner()
        findings = []
        results = {
            'findings': findings,
            'errors': [],
        }
        try:
            if not self.silent:
                print(f"{Colors.BLUE}[INFO]{Colors.END} Testing target accessibility...")
            test_chain = self.make_request(self.target_url)
            if not test_chain:
                msg = f"Target is not accessible: {self.target_url}"
                if not self.silent:
                    print(f"{Colors.RED}[ERROR]{Colors.END} {msg}")
                self.errors.append(msg)
                results['errors'] = self.errors
                return results
            if not self.silent:
                final_response = test_chain[-1]
                if len(test_chain) > 1:
                    initial_status = test_chain[0]['status_code']
                    final_status = final_response['status_code']
                    print(f"{Colors.GREEN}[INFO]{Colors.END} Target is accessible ({initial_status}→{final_status})")
                else:
                    print(f"{Colors.GREEN}[INFO]{Colors.END} Target is accessible (Status: {final_response['status_code']})")
                print(f"{Colors.BLUE}[INFO]{Colors.END} Starting directory/file enumeration...")
            if self.recursive:
                self.run_recursive_scan(self.target_url)
            else:
                words = self.load_wordlist()
                urls = self.generate_urls(self.target_url, words)
                for url_data in urls:
                    self.queue.put(url_data)
                for _ in range(self.threads):
                    t = threading.Thread(target=self.worker)
                    t.daemon = True
                    t.start()
                    self.threads_list.append(t)
                self.queue.join()
            # Log each discovered path
            with open(self.log_file, 'a', encoding='utf-8') as logf:
                for result in self.discovered_paths:
                    findings.append(result)
                    logf.write(json.dumps({'module': 'directory', 'finding': result}) + '\n')
            results['findings'] = findings
            results['errors'] = self.errors
            return results
        except Exception as e:
            msg = f"Unexpected error: {str(e)}"
            if not self.silent:
                print(f"{Colors.RED}[ERROR]{Colors.END} {msg}")
            self.errors.append(msg)
            results['errors'] = self.errors
            return results

def create_default_wordlist():
    """Create a default wordlist if none provided"""
    default_words = [
        'admin', 'administrator', 'login', 'test', 'backup', 'config', 'data',
        'api', 'assets', 'css', 'js', 'images', 'img', 'uploads', 'files',
        'docs', 'documentation', 'help', 'support', 'contact', 'about',
        'home', 'index', 'main', 'default', 'root', 'www', 'web', 'site',
        'portal', 'dashboard', 'panel', 'control', 'manage', 'management',
        'user', 'users', 'account', 'accounts', 'profile', 'profiles',
        'download', 'downloads', 'upload', 'temp', 'tmp', 'cache',
        'log', 'logs', 'error', 'errors', 'debug', 'dev', 'development',
        'test', 'testing', 'demo', 'sample', 'example', 'private', 'public',
        'secure', 'security', 'hidden', 'secret', 'internal', 'external'
    ]
    
    wordlist_path = 'default_wordlist.txt'
    with open(wordlist_path, 'w') as f:
        for word in default_words:
            f.write(word + '\n')
    
    return wordlist_path

def create_small_test_wordlist():
    """Create a small wordlist for testing"""
    test_words = [
        'index', 'home', 'about', 'contact', 'admin', 'login',
        'test', 'api', 'docs', 'help', 'assets', 'css', 'js', 'images'
    ]
    
    wordlist_path = 'test_wordlist.txt'
    with open(wordlist_path, 'w') as f:
        for word in test_words:
            f.write(word + '\n')
    
    return wordlist_path

def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Web Directory and File Fuzzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan (default wordlist  that is precreated)
  python3 directory-and-file.py -u http://example.com 
  
  # With redirect following and chain display
  python3 directory-and-file.py -u https://target.com -w wordlist.txt --follow-redirects --show-redirects
  
  # Filter mass redirects and show detailed output
  python3 directory-and-file.py -u http://site.com -w wordlist.txt --filter-redirects -v
  
  # Quick test with small wordlist
  python3 directory-and-file.py -u https://httpbin.org --test-mode
  
  # Full scan with all enhancements
  python3 directory-and-file.py -u https://target.com -w wordlist.txt -t 20 --follow-redirects --show-redirects --filter-redirects -o results.txt
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-w', '--wordlist', help='Wordlist file path')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-x', '--extensions', help='File extensions to test (comma-separated)')
    parser.add_argument('-s', '--status-codes', help='Valid status codes (comma-separated)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--delay', type=int, default=0, help='Delay between requests in ms (default: 0)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('-r', '--recursive', action='store_true', help='Enable recursive scanning')
    parser.add_argument('-d', '--max-depth', type=int, default=3, help='Maximum recursion depth (default: 3)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--log-file', help='Output file for detailed logs (default: fuzzer.log)')
    
    parser.add_argument('--follow-redirects', action='store_true', default=True, 
                       help='Follow redirects and report final status (default: True)')
    parser.add_argument('--no-follow-redirects', action='store_true', 
                       help='Do not follow redirects, report initial status only')
    parser.add_argument('--show-redirects', action='store_true', 
                       help='Show detailed redirect chain information')
    parser.add_argument('--filter-redirects', action='store_true', default=True,
                       help='Filter out mass redirect patterns (default: True)')
    parser.add_argument('--no-filter-redirects', action='store_true',
                       help='Disable mass redirect filtering')
    
    parser.add_argument('--test-mode', action='store_true',
                       help='Use small test wordlist for quick validation')
    
    args = parser.parse_args()
    
    follow_redirects = args.follow_redirects and not args.no_follow_redirects
    filter_redirects = args.filter_redirects and not args.no_filter_redirects
    
    if args.test_mode:
        print(f"{Colors.YELLOW}[INFO]{Colors.END} Test mode enabled, creating small test wordlist...")
        wordlist_path = create_small_test_wordlist()
        print(f"{Colors.GREEN}[INFO]{Colors.END} Test wordlist created: {wordlist_path}")
    elif not args.wordlist:
        print(f"{Colors.YELLOW}[INFO]{Colors.END} No wordlist specified, creating default wordlist...")
        wordlist_path = create_default_wordlist()
        print(f"{Colors.GREEN}[INFO]{Colors.END} Default wordlist created: {wordlist_path}")
    else:
        wordlist_path = args.wordlist
    
    extensions = ['']
    if args.extensions:
        extensions = [ext.strip().lstrip('.') for ext in args.extensions.split(',')]
        extensions = [ext for ext in extensions if ext] 
        if not extensions:
            extensions = ['']
    
    status_codes = None
    if args.status_codes:
        try:
            status_codes = [int(code.strip()) for code in args.status_codes.split(',')]
        except ValueError:
            print(f"{Colors.RED}[ERROR]{Colors.END} Invalid status codes format")
            sys.exit(1)
    
    fuzzer = WebFuzzer(
        target_url=args.url,
        wordlist_path=wordlist_path,
        threads=args.threads,
        extensions=extensions,
        status_codes=status_codes,
        timeout=args.timeout,
        delay=args.delay,
        user_agent=args.user_agent,
        recursive=args.recursive,
        max_depth=args.max_depth,
        output_file=args.output,
        follow_redirects=follow_redirects,
        show_redirect_chain=args.show_redirects,
        filter_redirects=filter_redirects
    )
    
    fuzzer.run()

if __name__ == '__main__':
    main()