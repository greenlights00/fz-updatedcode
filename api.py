# v5

"""
Enhanced API Security Testing Module - PERFORMANCE OPTIMIZED
Version: 3.1
Created: 2025-07-16 
Author: greenlights00 - Performance Optimized

Key Performance Optimizations:
- Smarter discovery path prioritization 
- Optimized connection pooling and timeouts
- Intelligent duplicate detection
- Faster response analysis
- Configurable scan modes (quick/full)
- Better memory management
- Parallel processing improvements

Features (ALL PRESERVED):
- API endpoint discovery (including common paths, documentation parsing, robots.txt, HATEOAS links)
- Automatic request body template generation from OpenAPI/Swagger specs
- User-defined request body templates for custom fuzzing
- Comprehensive HTTP method fuzzing (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
- Basic and advanced input validation testing
- Authentication testing (via supplied token or automated login for JWT)
- Rate limiting detection and analysis
- API version enumeration
- Common API vulnerabilities detection
- JWT token analysis
- OAuth/OAuth2 testing (via supplied token)
- Enhanced GraphQL security testing
- REST API security testing
- Advanced session management testing
- API key security testing
- Template and payload management
- Interactive CLI interface
- Enhanced reporting and filtering
- Content-type aware security analysis
- Error handling and progress tracking
"""

import argparse
import requests
import json
import re
import time
import threading
import logging
import base64
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Union
from urllib.parse import urljoin, urlparse
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import jwt
import hashlib
import sys
from tqdm import tqdm
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import uuid
from utils import url_validate_and_normalize, load_wordlist, log_error

# --- OPTIMIZED Configuration Constants ---
DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
COMMON_HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
MAX_RETRIES = 2  # Optimized from 3
BACKOFF_FACTOR = 0.1  # Optimized from 0.3
DEFAULT_TIMEOUT = 8  # Optimized from 10
DEFAULT_CONCURRENT_REQUESTS = 8  # Optimized from 10

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

class ScanMode:
    QUICK = 'quick'
    FULL = 'full'
    STEALTH = 'stealth'

class APIScanner:
    def __init__(self, target_url, options=None):
        """
        Initialize API Security Scanner - PERFORMANCE OPTIMIZED
        """
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Initializing API Security Scanner for {target_url}")
        
        # Validate target URL
        try:
            parsed_url = urlparse(target_url)
            if not all([parsed_url.scheme, parsed_url.netloc]):
                raise ValueError("Invalid URL format. Must include scheme (http:// or https://) and domain")
            self.target_url = url_validate_and_normalize(target_url)
        except Exception as e:
            self.logger.error(f"URL validation error: {str(e)}")
            raise

        # Initialize options
        self.options = options or {}
        
        # Set scanner attributes with optimized defaults
        self.scan_id = str(uuid.uuid4())
        self.start_time = time.time()
        self.api_key = self.options.get('api_key')
        self.timeout = self.options.get('timeout', DEFAULT_TIMEOUT)
        self.verify_ssl = self.options.get('verify_ssl', False)  # Faster default
        self.max_depth = self.options.get('max_depth', 3)
        self.concurrent_requests = self.options.get('concurrent_requests', DEFAULT_CONCURRENT_REQUESTS)
        self.threads = self.concurrent_requests  # For compatibility
        self.lock = threading.Lock()
        self.scan_mode = self.options.get('scan_mode', ScanMode.FULL)
        self.scan_start_time = datetime.utcnow().isoformat()
        self.session = self._create_session()

        # Set user agent and headers
        self.session.headers.update({'User-Agent': DEFAULT_USER_AGENT})
        if self.api_key:
            self.session.headers.update({'Authorization': f'Bearer {self.api_key}'})

        # Initialize containers
        self.discovered_endpoints = []
        self.vulnerabilities = []
        self.stats = {
            'requests_made': 0,
            'vulnerabilities_found': 0,
            'scan_start_time': self.scan_start_time,
            'endpoints_discovered': 0
        }
        self.api_versions = []
        self.graphql_schemas = {}
        self.rate_limits = {}
        self.payload_templates = {}
        self.auth_issues = []
        self.fuzzing_results = []
        self.api_info = {}
        
        # For login/JWT (if used in future)
        self.login_url = self.options.get('login_url')
        self.username = self.options.get('username')
        self.password = self.options.get('password')
        self.custom_headers = self.options.get('custom_headers', {})
        if self.custom_headers:
            self.session.headers.update(self.custom_headers)
        self.output_file = self.options.get('output_file')
        self.payload_templates_file = self.options.get('payload_templates_file')
        if self.payload_templates_file:
            self._load_user_payload_templates(self.payload_templates_file)
        
        # Disable SSL warnings if verify_ssl is False
        if not self.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.silent = self.options.get('silent', False)
        self.verbose = self.options.get('verbose', False)
        self.log_file = self.options.get('log_file', 'fuzzer.log')

    def _create_session(self) -> requests.Session:
        """
        Create a requests session with optimized retry strategy
        """
        session = requests.Session()
        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
            raise_on_status=False
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.threads * 2,  # Optimized pool size
            pool_maxsize=self.threads * 4,
            pool_block=False
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.verify = self.verify_ssl
        session.timeout = self.timeout
        return session

    def _make_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Optimized request method with better error handling
        """
        try:
            # Set optimized defaults
            if 'timeout' not in kwargs:
                kwargs['timeout'] = self.timeout
            if 'allow_redirects' not in kwargs:
                kwargs['allow_redirects'] = False
                
            with self.lock:
                self.stats['requests_made'] += 1
                
            response = self.session.request(method, url, **kwargs)
            return response
            
        except requests.exceptions.Timeout:
            self.logger.debug(f"Timeout for {method} {url}")
            return None
        except requests.exceptions.ConnectionError:
            self.logger.debug(f"Connection error for {method} {url}")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Request error for {method} {url}: {str(e)}")
            return None
        except Exception as e:
            self.logger.debug(f"Unexpected error for {method} {url}: {str(e)}")
            return None

    def setup_logging(self):
        """Configure logging for the scanner"""
        log_format = f'{Colors.CYAN}%(asctime)s{Colors.END} - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler(f'api_scanner_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Log initial configuration
        self.logger.info(f"""
        Scanner Configuration:
        - Target URL: {self.target_url}
        - Threads: {self.threads}
        - Timeout: {self.timeout}s
        - SSL Verification: {self.verify_ssl}
        - Scan Mode: {self.scan_mode}
        - Start Time: {self.scan_start_time}
        - Author: greenlights00
        """)

    def _load_user_payload_templates(self, file_path: str):
        """Load user-defined payload templates from JSON file"""
        try:
            with open(file_path, 'r') as f:
                user_templates = json.load(f)
            
            # Validate and merge templates
            for path, methods in user_templates.items():
                if not isinstance(methods, dict):
                    self.logger.warning(f"Invalid template format for path {path}")
                    continue
                    
                if path not in self.payload_templates:
                    self.payload_templates[path] = {}
                    
                for method, templates in methods.items():
                    method = method.upper()
                    if method not in COMMON_HTTP_METHODS:
                        self.logger.warning(f"Invalid HTTP method {method} in templates")
                        continue
                        
                    if not isinstance(templates, dict):
                        self.logger.warning(f"Invalid template format for {method} {path}")
                        continue
                        
                    self.payload_templates[path][method] = templates
                    
            self.logger.info(f"[{Colors.GREEN}+{Colors.END}] Loaded {len(user_templates)} custom payload templates")
            
        except FileNotFoundError:
            self.logger.error(f"[{Colors.RED}-{Colors.END}] Template file not found: {file_path}")
        except json.JSONDecodeError:
            self.logger.error(f"[{Colors.RED}-{Colors.END}] Invalid JSON in template file: {file_path}")
        except Exception as e:
            self.logger.error(f"[{Colors.RED}-{Colors.END}] Error loading templates: {str(e)}")

    def get_jwt_token(self) -> Optional[str]:
        """
        Automatically get JWT token through login
        Enhanced with better error handling and multiple auth methods
        """
        if not all([self.login_url, self.username, self.password]):
            self.logger.warning("Login credentials not provided, skipping JWT token acquisition")
            return None
            
        self.logger.info(f"Attempting to get JWT token from {self.login_url}")
        
        # Common login payload formats
        login_payloads = [
            {
                'username': self.username,
                'password': self.password
            },
            {
                'email': self.username,
                'password': self.password
            },
            {
                'user': self.username,
                'pass': self.password
            },
            {
                'login': self.username,
                'password': self.password
            }
        ]
        
        # Common content types
        content_types = [
            'application/json',
            'application/x-www-form-urlencoded',
            'multipart/form-data'
        ]
        
        for payload in login_payloads:
            for content_type in content_types:
                try:
                    headers = {'Content-Type': content_type}
                    
                    if content_type == 'application/x-www-form-urlencoded':
                        data = payload
                        json_data = None
                    else:
                        data = None
                        json_data = payload
                        
                    response = self.session.post(
                        self.login_url,
                        json=json_data,
                        data=data,
                        headers=headers,
                        timeout=self.timeout
                    )
                    
                    if response.status_code == 200:
                        # Try to extract token from various locations
                        token = None
                        
                        # Check JSON response
                        try:
                            json_response = response.json()
                            token = (
                                json_response.get('token') or
                                json_response.get('access_token') or
                                json_response.get('jwt') or
                                json_response.get('id_token') or
                                json_response.get('Bearer') or
                                json_response.get('auth_token')
                            )
                            
                            # Check nested structures
                            if not token and 'data' in json_response:
                                data = json_response['data']
                                if isinstance(data, dict):
                                    token = (
                                        data.get('token') or
                                        data.get('access_token') or
                                        data.get('jwt')
                                    )
                        except json.JSONDecodeError:
                            pass
                            
                        # Check headers
                        if not token:
                            auth_header = response.headers.get('Authorization', '')
                            if auth_header.startswith('Bearer '):
                                token = auth_header.split(' ')[1]
                                
                        # Check cookies
                        if not token:
                            for cookie in response.cookies:
                                if cookie.name.lower() in ['token', 'jwt', 'access_token']:
                                    token = cookie.value
                                    
                        if token:
                            self.session.headers.update({'Authorization': f'Bearer {token}'})
                            self.logger.info(f"[{Colors.GREEN}+{Colors.END}] Successfully obtained JWT token")
                            
                            # Analyze token security
                            self.analyze_jwt_token(token)
                            return token
                            
                except requests.exceptions.RequestException as e:
                    self.logger.error(f"Error during login attempt: {str(e)}")
                    continue
                    
        self.logger.error(f"[{Colors.RED}-{Colors.END}] Failed to obtain JWT token from any login attempt")
        return None

    def start_scan(self):
        """
        Start the API security scan process - OPTIMIZED
        """
        self.logger.info(f"[+] Starting API security scan for {self.target_url}")
        
        try:
            # Step 1: Discover API endpoints
            self.logger.info("[*] Starting endpoint discovery phase")
            self.discover_endpoints()
            
            # Step 2: Test each discovered endpoint
            self.logger.info("[*] Starting security testing phase")
            for endpoint in self.discovered_endpoints:
                self.test_endpoint_security(endpoint)
                
            # Step 3: Analyze authentication mechanisms
            if self.api_key:
                self.logger.info("[*] Testing authentication security")
                self._test_authentication_mechanisms()
                
            # Step 4: Check for common API vulnerabilities
            self.logger.info("[*] Checking for common API vulnerabilities")
            self._check_common_vulnerabilities()
            
            self.logger.info(f"[+] Scan completed successfully! Found {len(self.vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"[-] Scan failed with error: {str(e)}")
            raise

    def _test_authentication_mechanisms(self):
        """Test various authentication mechanisms for vulnerabilities"""
        if not self.api_key:
            return
            
        # Test API key security
        test_cases = [
            {'header': 'X-API-Key', 'value': 'invalid_key'},
            {'header': 'Authorization', 'value': 'Bearer invalid_token'},
            {'header': 'API-Key', 'value': self.api_key + "' OR '1'='1"}
        ]
        
        for test in test_cases:
            try:
                response = self._make_request(
                    method='GET',
                    url=self.target_url,
                    headers={test['header']: test['value']}
                )
                
                if response and response.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'Authentication_Bypass',
                        'severity': 'Critical',
                        'description': f'Possible authentication bypass with invalid {test["header"]}',
                        'recommendation': 'Implement proper authentication validation'
                    })
            except Exception as e:
                self.logger.debug(f"Auth test error: {str(e)}")

    def _check_common_vulnerabilities(self):
        """Check for common API vulnerabilities across all endpoints"""
        # Check for missing security headers
        security_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Content-Security-Policy',
            'Strict-Transport-Security'
        ]
        
        for endpoint in self.discovered_endpoints:
            missing_headers = [
                h for h in security_headers 
                if h not in endpoint.get('headers', {})
            ]
            
            if missing_headers:
                self.vulnerabilities.append({
                    'type': 'Missing_Security_Headers',
                    'severity': 'Medium',
                    'description': f'Missing security headers: {", ".join(missing_headers)}',
                    'url': endpoint['url'],
                    'recommendation': 'Add essential security headers'
                })

    def analyze_jwt_token(self, token: str):
        """
        Enhanced JWT token security analysis
        """
        try:
            # Decode token without verification
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            issues = []
            
            # Check algorithm
            alg = header.get('alg', '')
            if alg == 'none':
                issues.append({
                    'severity': 'Critical',
                    'issue': 'JWT uses "none" algorithm',
                    'impact': 'Token can be forged without signature',
                    'recommendation': 'Use a strong algorithm like RS256 or ES256'
                })
            elif alg in ['HS256', 'HS384', 'HS512']:
                issues.append({
                    'severity': 'Medium',
                    'issue': 'JWT uses HMAC algorithm',
                    'impact': 'Potentially vulnerable to brute force if weak secret is used',
                    'recommendation': 'Consider using asymmetric algorithms like RS256'
                })
                
            # Check expiration
            if 'exp' not in payload:
                issues.append({
                    'severity': 'High',
                    'issue': 'JWT has no expiration claim',
                    'impact': 'Token remains valid indefinitely',
                    'recommendation': 'Add expiration claim (exp)'
                })
            elif 'exp' in payload:
                exp_time = datetime.fromtimestamp(payload['exp'])
                if exp_time < datetime.now():
                    issues.append({
                        'severity': 'Info',
                        'issue': 'JWT has expired',
                        'impact': 'Token is no longer valid',
                        'recommendation': 'Request a new token'
                    })
                    
            # Check other claims
            if 'iat' not in payload:
                issues.append({
                    'severity': 'Low',
                    'issue': 'JWT missing issued at claim',
                    'impact': 'Cannot determine token age',
                    'recommendation': 'Add issued at claim (iat)'
                })
                
            if 'iss' not in payload:
                issues.append({
                    'severity': 'Low',
                    'issue': 'JWT missing issuer claim',
                    'impact': 'Cannot verify token origin',
                    'recommendation': 'Add issuer claim (iss)'
                })
                
            # Check for sensitive data
            sensitive_keys = ['password', 'secret', 'key', 'api_key', 'apikey']
            for key in payload:
                if any(s in key.lower() for s in sensitive_keys):
                    issues.append({
                        'severity': 'High',
                        'issue': f'JWT contains sensitive data in {key}',
                        'impact': 'Sensitive information exposure',
                        'recommendation': 'Remove sensitive data from token payload'
                    })
                    
            # Add findings to vulnerabilities
            for issue in issues:
                self.vulnerabilities.append({
                    'type': 'JWT_Security',
                    'severity': issue['severity'],
                    'confidence': 'Confirmed',
                    'description': issue['issue'],
                    'impact': issue['impact'],
                    'recommendation': issue['recommendation']
                })
                
        except Exception as e:
            self.logger.error(f"Error analyzing JWT token: {str(e)}")

    def discover_endpoints(self) -> List[Dict[str, Any]]:
        """
        OPTIMIZED endpoint discovery with smart path prioritization
        """
        self.logger.info(f"[{Colors.BLUE}INFO{Colors.END}] Starting API endpoint discovery for {self.target_url}...")
        
        # Using a set to track seen URLs and avoid duplicates
        seen_urls = set()
        
        # OPTIMIZED: Prioritized discovery paths based on scan mode
        if self.scan_mode == ScanMode.QUICK:
            common_discovery_paths = [
                # Essential API paths only
                '/api', '/api/v1', '/api/v2', '/rest',
                '/swagger.json', '/openapi.json', '/api-docs',
                '/auth', '/login', '/oauth',
                '/health', '/status', '/version',
                '/users', '/me', '/admin',
                '/graphql'
            ]
        else:
            # Full discovery paths for comprehensive scanning
            common_discovery_paths = [
                # API roots
                '/api', '/rest', '/graphql', '/v1', '/v2', '/v3',
                # Documentation
                '/swagger', '/openapi', '/docs', '/documentation', '/api-docs',
                '/swagger.json', '/openapi.json', '/api-spec.json',
                # Auth endpoints
                '/auth', '/oauth', '/oauth2', '/login', '/authenticate',
                # Common service endpoints
                '/health', '/status', '/metrics', '/version',
                # Management endpoints
                '/admin', '/console', '/dashboard', '/manage',
                # User endpoints
                '/users', '/accounts', '/profiles', '/me',
                # Common resources
                '/posts', '/articles', '/comments', '/products',
                '/orders', '/items', '/categories', '/tags',
                # WebSocket endpoints
                '/ws', '/websocket', '/socket', '/stream',
                # Dev/Debug endpoints
                '/debug', '/dev', '/test', '/sandbox'
            ]
            
            # Add versioned paths for full scan
            versioned_paths = []
            for path in common_discovery_paths:
                if not path.startswith('/api/'):
                    versioned_paths.extend([f'/api{path}', f'/api/v1{path}', f'/api/v2{path}'])
            common_discovery_paths.extend(versioned_paths)
        
        # Remove duplicates while preserving order
        common_discovery_paths = list(dict.fromkeys(common_discovery_paths))
        
        # Discovery queue for tasks
        discovery_queue = Queue()
        
        # Add initial endpoints to queue
        for path in common_discovery_paths:
            discovery_queue.put((urljoin(self.target_url, path), path, None))
            
        # Add homepage and robots.txt
        discovery_queue.put((self.target_url, '/', None))
        discovery_queue.put((urljoin(self.target_url, '/robots.txt'), '/robots.txt', None))
        
        # Progress bar setup
        total_initial_tasks = discovery_queue.qsize()
        pbar = tqdm(
            total=total_initial_tasks,
            desc=f"{Colors.BLUE}Endpoint Discovery{Colors.END}",
            dynamic_ncols=True,
            leave=False
        )
        
        def worker_discover():
            """Optimized worker function for threaded endpoint discovery"""
            while True:
                try:
                    url, path, path_params_map = discovery_queue.get(timeout=1)
                    
                    if url in seen_urls:
                        pbar.update(1)
                        discovery_queue.task_done()
                        continue
                        
                    # OPTIMIZATION: Use HEAD first for faster discovery
                    headers = {
                        'Accept': 'application/json, text/plain, */*',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                    
                    # Try HEAD first for faster discovery
                    response = self._make_request(
                        method="HEAD",
                        url=url,
                        headers=headers,
                        allow_redirects=False
                    )
                    
                    # If HEAD fails or is not informative, try GET
                    if not response or response.status_code in [405, 501]:
                        response = self._make_request(
                            method="GET",
                            url=url,
                            headers=headers,
                            allow_redirects=False
                        )
                    
                    pbar.update(1)
                    
                    if response:
                        self._analyze_discovery_response(response, url, path, discovery_queue, seen_urls, pbar)
                    
                    discovery_queue.task_done()
                    
                except Queue.Empty:
                    break
                except Exception as e:
                    self.logger.error(f"[{Colors.RED}ERROR{Colors.END}] Discovery worker error: {str(e)}")
                    discovery_queue.task_done()
                    
        # Start discovery threads with optimized count
        max_workers = min(self.threads, 5)  # Limit for better performance
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(worker_discover) for _ in range(max_workers)]
            discovery_queue.join()
            pbar.close()
            
        self.logger.info(f"[{Colors.GREEN}COMPLETE{Colors.END}] Endpoint discovery finished. Found {len(self.discovered_endpoints)} unique endpoints.")
        
        # Update statistics
        self.stats['endpoints_discovered'] = len(self.discovered_endpoints)
        
        return self.discovered_endpoints

    def _analyze_discovery_response(self, response: requests.Response, url: str, path: str,
                                  discovery_queue: Queue, seen_urls: set, pbar: tqdm):
        """Analyze response from endpoint discovery"""
        try:
            if response.status_code != 404:
                endpoint_info = {
                    'url': url,
                    'path': path,
                    'method': 'GET',
                    'status_code': response.status_code,
                    'content_type': response.headers.get('content-type', ''),
                    'content_length': len(response.content) if response.content else 0,
                    'headers': dict(response.headers),
                    'server': response.headers.get('server', 'Unknown'),
                    'discovered_time': datetime.utcnow().isoformat()
                }
                
                with self.lock:
                    if url not in seen_urls:
                        self.discovered_endpoints.append(endpoint_info)
                        seen_urls.add(url)
                        
                        status_color = {
                            200: Colors.GREEN,
                            201: Colors.GREEN,
                            401: Colors.YELLOW,
                            403: Colors.YELLOW,
                            500: Colors.RED
                        }.get(response.status_code, Colors.WHITE)
                        
                        self.logger.info(
                            f"[{status_color}FOUND{Colors.END}] {url} "
                            f"(Status: {response.status_code}, "
                            f"Type: {response.headers.get('content-type', 'Unknown')})"
                        )
                
                # OPTIMIZATION: Only analyze content for relevant responses
                if response.status_code == 200 and response.content:
                    content_type = response.headers.get('content-type', '').lower()
                    
                    # Check for API documentation
                    if 'application/json' in content_type and len(response.content) < 100000:  # Size limit
                        try:
                            content = response.text.lower()
                            if 'swagger' in content or 'openapi' in content:
                                self.analyze_api_docs(response.text, path)
                        except:
                            pass
                    
                    # Check for GraphQL endpoint
                    if ('graphql' in path.lower() or
                        'application/graphql' in content_type or
                        '__schema' in response.text[:1000]):  # Check first 1000 chars only
                        self.analyze_graphql_endpoint(url)
                    
                    # Parse JSON responses for HATEOAS links (only if small)
                    if 'application/json' in content_type and len(response.content) < 50000:
                        try:
                            data = response.json()
                            self._extract_links_from_json(data, url, discovery_queue, seen_urls, pbar)
                        except json.JSONDecodeError:
                            pass
                    
                    # Parse HTML responses for API links (only if small)
                    elif 'text/html' in content_type and len(response.content) < 100000:
                        self._extract_links_from_html(response.text[:10000], url, discovery_queue, seen_urls, pbar)  # Limit content
                
                # Check for API version information
                self._check_api_version(response)
                
                # Check for rate limiting headers
                self.analyze_rate_limits(response, url)
                
        except Exception as e:
            self.logger.error(f"Error analyzing discovery response: {str(e)}")

    def _extract_links_from_json(self, data: Any, base_url: str, discovery_queue: Queue,
                                seen_urls: set, pbar: tqdm):
        """Extract links from JSON response"""
        if isinstance(data, dict):
            for key, value in data.items():
                # Check for link fields
                if isinstance(value, str) and any(key.lower().endswith(x) for x in ['url', 'uri', 'href', 'link']):
                    self._add_discovered_url(value, base_url, discovery_queue, seen_urls, pbar)
                    
                # Check for HATEOAS _links field
                elif key == '_links' and isinstance(value, dict):
                    for link_value in value.values():
                        if isinstance(link_value, dict) and 'href' in link_value:
                            self._add_discovered_url(link_value['href'], base_url, discovery_queue, seen_urls, pbar)
                            
                # Recurse into nested structures (with depth limit)
                elif isinstance(value, (dict, list)) and str(key) not in ['data', 'metadata', 'config']:
                    self._extract_links_from_json(value, base_url, discovery_queue, seen_urls, pbar)
                    
        elif isinstance(data, list):
            for item in data[:10]:  # Limit to first 10 items for performance
                if isinstance(item, (dict, list)):
                    self._extract_links_from_json(item, base_url, discovery_queue, seen_urls, pbar)
    
    def _extract_links_from_html(self, html_content: str, base_url: str,
                                discovery_queue: Queue, seen_urls: set, pbar: tqdm):
        """Extract API endpoints from HTML content"""
        # Find API-like links
        api_patterns = [
            r'href=["\']([^"\']*(?:api|graphql|swagger|docs)[^"\']*)["\']',
            r'src=["\']([^"\']*(?:api|graphql|swagger|docs)[^"\']*)["\']',
            r'url:\s*["\']([^"\']*(?:api|graphql|swagger|docs)[^"\']*)["\']',
            r'endpoint:\s*["\']([^"\']*(?:api|graphql|swagger|docs)[^"\']*)["\']',
            r'data-url=["\']([^"\']*(?:api|graphql|swagger|docs)[^"\']*)["\']'
        ]
        
        for pattern in api_patterns:
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                self._add_discovered_url(match.group(1), base_url, discovery_queue, seen_urls, pbar)
                
        # Find JavaScript files that might contain API endpoints
        js_patterns = [
            r'src=["\']([^"\']*\.js)["\']',
            r'data-src=["\']([^"\']*\.js)["\']'
        ]
        
        for pattern in js_patterns:
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                js_url = urljoin(base_url, match.group(1))
                self._analyze_js_file(js_url, discovery_queue, seen_urls, pbar)

    def _analyze_js_file(self, js_url: str, discovery_queue: Queue, seen_urls: set, pbar: tqdm):
        """Analyze JavaScript files for API endpoints"""
        try:
            response = self._make_request("GET", js_url)
            if response and response.status_code == 200 and len(response.content) < 500000:  # Size limit
                js_content = response.text
                
                # Find API endpoints in JavaScript
                api_patterns = [
                    r'(?:url|endpoint|api):\s*["\']([^"\']+)["\']',
                    r'fetch\(["\']([^"\']+)["\']\)',
                    r'axios\.[a-z]+\(["\']([^"\']+)["\']\)',
                    r'\.ajax\({[^}]*url:\s*["\']([^"\']+)["\']'
                ]
                
                for pattern in api_patterns:
                    matches = re.finditer(pattern, js_content, re.IGNORECASE)
                    for match in matches:
                        self._add_discovered_url(match.group(1), js_url, discovery_queue, seen_urls, pbar)
                        
        except Exception as e:
            self.logger.debug(f"Error analyzing JavaScript file {js_url}: {str(e)}")

    def _add_discovered_url(self, url: str, base_url: str, discovery_queue: Queue,
                           seen_urls: set, pbar: tqdm):
        """Add discovered URL to queue if it's valid and not seen"""
        try:
            # Clean and normalize URL
            if url.startswith('//'):
                url = 'https:' + url
            elif url.startswith('/'):
                url = urljoin(base_url, url)
            elif not url.startswith(('http://', 'https://')):
                url = urljoin(base_url, '/' + url)
                
            # Check if URL belongs to target domain
            if urlparse(url).netloc == urlparse(self.target_url).netloc:
                if url not in seen_urls:
                    discovery_queue.put((url, urlparse(url).path, None))
                    seen_urls.add(url)
                    pbar.total += 1
                    pbar.refresh()
                    
        except Exception as e:
            self.logger.debug(f"Error processing URL {url}: {str(e)}")

    def _check_api_version(self, response: requests.Response):
        """Check for API version information in response"""
        version_headers = [
            'X-API-Version',
            'API-Version',
            'X-Version',
            'Version'
        ]
        
        # Check headers
        for header in version_headers:
            if header.lower() in [h.lower() for h in response.headers]:
                version = response.headers[header]
                if version not in self.api_versions:
                    self.api_versions.append(version)
                    self.logger.info(f"[{Colors.BLUE}VERSION{Colors.END}] Found API version: {version}")
                    
        # Check response content (only for small JSON responses)
        try:
            content_type = response.headers.get('content-type', '').lower()
            if 'application/json' in content_type and len(response.content) < 10000:
                data = response.json()
                if isinstance(data, dict):
                    version_keys = ['version', 'apiVersion', 'api_version', 'v']
                    for key in version_keys:
                        if key in data and str(data[key]) not in self.api_versions:
                            self.api_versions.append(str(data[key]))
                            self.logger.info(f"[{Colors.BLUE}VERSION{Colors.END}] Found API version: {data[key]}")
                            
        except json.JSONDecodeError:
            pass

    def analyze_rate_limits(self, response: requests.Response, url: str):
        """Analyze rate limiting headers"""
        rate_limit_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'Retry-After',
            'RateLimit-Limit'
        ]
        
        found_headers = {}
        for header in rate_limit_headers:
            if header in response.headers:
                found_headers[header] = response.headers[header]
                
        if found_headers:
            self.rate_limits[url] = found_headers

    def analyze_api_docs(self, content: str, doc_path: str):
        """
        Enhanced API documentation analysis
        Supports both Swagger and OpenAPI specifications
        """
        try:
            doc_data = json.loads(content)
            
            # Determine API spec version
            if 'swagger' in doc_data:
                version = 'swagger2'
                self.extract_swagger_endpoints(doc_data)
            elif 'openapi' in doc_data:
                version = 'openapi3'
                self.extract_openapi_endpoints(doc_data)
            else:
                self.logger.warning(f"Unknown API documentation format at {doc_path}")
                return
                
            self.logger.info(f"[{Colors.GREEN}DOCS{Colors.END}] Found {version.upper()} documentation at {doc_path}")
            
            # Extract security schemes
            self._analyze_security_schemes(doc_data, version)
            
            # Extract API information
            self._extract_api_info(doc_data, version)
            
        except json.JSONDecodeError:
            self.logger.warning(f"Invalid JSON in API documentation at {doc_path}")
        except Exception as e:
            self.logger.error(f"Error analyzing API docs at {doc_path}: {str(e)}")

    def _analyze_security_schemes(self, doc_data: Dict[str, Any], version: str):
        """Analyze security schemes from API documentation"""
        security_schemes = {}
        
        if version == 'swagger2':
            security_defs = doc_data.get('securityDefinitions', {})
            for name, scheme in security_defs.items():
                security_schemes[name] = scheme
                
        elif version == 'openapi3':
            components = doc_data.get('components', {})
            security_defs = components.get('securitySchemes', {})
            for name, scheme in security_defs.items():
                security_schemes[name] = scheme
                
        # Analyze security schemes
        for name, scheme in security_schemes.items():
            scheme_type = scheme.get('type', '').lower()
            
            if scheme_type == 'apikey':
                self._check_apikey_scheme(name, scheme)
            elif scheme_type == 'oauth2':
                self._check_oauth2_scheme(name, scheme)
            elif scheme_type == 'http':
                self._check_http_scheme(name, scheme)

    def _check_apikey_scheme(self, name: str, scheme: Dict[str, Any]):
        """Check API key security scheme"""
        location = scheme.get('in', '')
        param_name = scheme.get('name', '')
        
        if location == 'query':
            self.vulnerabilities.append({
                'type': 'API_Key_In_Query',
                'severity': 'Medium',
                'confidence': 'Confirmed',
                'description': f'API key "{param_name}" is transmitted in query string',
                'impact': 'API key may be exposed in logs and browser history',
                'recommendation': 'Move API key to header or cookie'
            })

    def _check_oauth2_scheme(self, name: str, scheme: Dict[str, Any]):
        """Check OAuth2 security scheme"""
        flows = scheme.get('flows', {}) if 'flows' in scheme else {'implicit': scheme}
        
        for flow_type, flow_data in flows.items():
            # Check for secure token endpoint
            token_url = flow_data.get('tokenUrl', '')
            if token_url and not token_url.startswith('https://'):
                self.vulnerabilities.append({
                    'type': 'OAuth2_Insecure_Token_Endpoint',
                    'severity': 'High',
                    'confidence': 'Confirmed',
                    'description': f'OAuth2 token endpoint for {flow_type} flow uses insecure HTTP',
                    'impact': 'Token transmission could be intercepted',
                    'recommendation': 'Use HTTPS for token endpoint'
                })
                
            # Check scope definitions
            scopes = flow_data.get('scopes', {})
            if not scopes:
                self.vulnerabilities.append({
                    'type': 'OAuth2_No_Scopes',
                    'severity': 'Medium',
                    'confidence': 'Confirmed',
                    'description': f'OAuth2 {flow_type} flow has no scope definitions',
                    'impact': 'No granular access control',
                    'recommendation': 'Define appropriate OAuth2 scopes'
                })
                
            # Check for implicit flow
            if flow_type == 'implicit':
                self.vulnerabilities.append({
                    'type': 'OAuth2_Implicit_Flow',
                    'severity': 'Medium',
                    'confidence': 'Confirmed',
                    'description': 'OAuth2 implicit flow is deprecated',
                    'impact': 'Less secure token delivery',
                    'recommendation': 'Use authorization code flow with PKCE'
                })

    def _check_http_scheme(self, name: str, scheme: Dict[str, Any]):
        """Check HTTP security scheme"""
        scheme_type = scheme.get('scheme', '').lower()
        
        if scheme_type == 'basic':
            self.vulnerabilities.append({
                'type': 'Basic_Auth_Usage',
                'severity': 'Medium',
                'confidence': 'Confirmed',
                'description': 'API uses HTTP Basic Authentication',
                'impact': 'Credentials sent with every request',
                'recommendation': 'Use token-based authentication'
            })

    def _extract_api_info(self, doc_data: Dict[str, Any], version: str):
        """Extract and analyze API information from documentation"""
        info = doc_data.get('info', {})
        
        # Store API information
        self.api_info = {
            'title': info.get('title', 'Unknown'),
            'version': info.get('version', 'Unknown'),
            'description': info.get('description', ''),
            'spec_version': version,
            'servers': self._get_servers(doc_data, version),
            'contact': info.get('contact', {}),
            'license': info.get('license', {}),
            'terms_of_service': info.get('termsOfService', '')
        }
        
        # Check for security issues
        self._analyze_api_info(self.api_info)

    def _get_servers(self, doc_data: Dict[str, Any], version: str) -> List[str]:
        """Extract server URLs from API documentation"""
        servers = []
        
        if version == 'swagger2':
            schemes = doc_data.get('schemes', ['https'])
            host = doc_data.get('host', '')
            base_path = doc_data.get('basePath', '')
            
            if host:
                for scheme in schemes:
                    servers.append(f"{scheme}://{host}{base_path}")
                    
        elif version == 'openapi3':
            for server in doc_data.get('servers', []):
                url = server.get('url', '')
                variables = server.get('variables', {})
                
                # Handle URL templates
                if variables:
                    for var_name, var_data in variables.items():
                        default = var_data.get('default', '')
                        url = url.replace(f"{{{var_name}}}", default)
                        
                if url:
                    servers.append(url)
                    
        return servers

    def _analyze_api_info(self, api_info: Dict[str, Any]):
        """Analyze API information for potential issues"""
        # Check for missing documentation
        if not api_info['description']:
            self.vulnerabilities.append({
                'type': 'Missing_API_Description',
                'severity': 'Info',
                'confidence': 'Confirmed',
                'description': 'API lacks general description',
                'impact': 'Poor API discoverability and usability',
                'recommendation': 'Add comprehensive API description'
            })
            
        # Check for contact information
        if not api_info['contact']:
            self.vulnerabilities.append({
                'type': 'Missing_Contact_Info',
                'severity': 'Info',
                'confidence': 'Confirmed',
                'description': 'API documentation lacks contact information',
                'impact': 'Difficult to report security issues',
                'recommendation': 'Add security contact information'
            })
            
        # Check server URLs
        for server in api_info['servers']:
            if server.startswith('http://'):
                self.vulnerabilities.append({
                    'type': 'Insecure_Server_URL',
                    'severity': 'High',
                    'confidence': 'Confirmed',
                    'description': f'API server uses insecure HTTP: {server}',
                    'impact': 'Traffic can be intercepted',
                    'recommendation': 'Use HTTPS for all API endpoints'
                })

    def extract_swagger_endpoints(self, swagger_data: Dict[str, Any]):
        """
        Enhanced Swagger/OpenAPI 2.0 endpoint extraction
        """
        base_path = swagger_data.get('basePath', '')
        host = swagger_data.get('host', '')
        schemes = swagger_data.get('schemes', ['https'])
        
        # Build base URLs
        base_urls = []
        if host:
            for scheme in schemes:
                base_urls.append(f"{scheme}://{host}{base_path}")
        else:
            base_urls = [self.target_url]
            
        paths = swagger_data.get('paths', {})
        global_security = swagger_data.get('security', [])
        
        for path, methods in paths.items():
            for method, details in methods.items():
                method = method.upper()
                
                # Skip invalid methods
                if method not in COMMON_HTTP_METHODS:
                    continue
                    
                # Process endpoint security
                security = details.get('security', global_security)
                auth_required = bool(security)
                
                # Process parameters
                parameters = []
                for param in details.get('parameters', []):
                    param_info = {
                        'name': param.get('name', ''),
                        'in': param.get('in', ''),
                        'required': param.get('required', False),
                        'type': param.get('type', 'string'),
                        'description': param.get('description', '')
                    }
                    parameters.append(param_info)
                    
                # Generate request templates
                request_templates = self._generate_request_templates(parameters, details)
                
                # Process response schemas
                responses = {}
                for status_code, response_info in details.get('responses', {}).items():
                    response_schema = response_info.get('schema', {})
                    responses[status_code] = {
                        'description': response_info.get('description', ''),
                        'schema': response_schema,
                        'headers': response_info.get('headers', {}),
                        'example': response_info.get('example')
                    }

                # Create endpoint info for each base URL
                for base_url in base_urls:
                    full_url = urljoin(base_url, path.lstrip('/'))
                    endpoint_info = {
                        'url': full_url,
                        'path': path,
                        'method': method,
                        'summary': details.get('summary', ''),
                        'description': details.get('description', ''),
                        'parameters': parameters,
                        'responses': responses,
                        'auth_required': auth_required,
                        'security': security,
                        'consumes': details.get('consumes', []),
                        'produces': details.get('produces', []),
                        'deprecated': details.get('deprecated', False),
                        'request_templates': request_templates,
                        'source': 'swagger2',
                        'discovered_time': datetime.utcnow().isoformat()
                    }

                    # Add to discovered endpoints if not already present
                    self._add_unique_endpoint(endpoint_info)

                    # Generate test cases
                    self._generate_test_cases(endpoint_info)

    def _generate_request_templates(self, parameters: List[Dict[str, Any]], details: Dict[str, Any]) -> Dict[str, Any]:
        """Generate request templates for different content types"""
        templates = {
            'application/json': None,
            'application/x-www-form-urlencoded': None,
            'multipart/form-data': None
        }

        # Process body parameter
        body_params = [p for p in parameters if p.get('in') == 'body']
        if body_params:
            body_param = body_params[0]
            if 'schema' in body_param:
                schema = body_param['schema']
                json_template = self._generate_template_from_schema(schema)
                if json_template:
                    templates['application/json'] = json_template

        # Process form parameters
        form_params = [p for p in parameters if p.get('in') == 'formData']
        if form_params:
            form_template = {}
            for param in form_params:
                form_template[param['name']] = self._generate_default_value(param)
            
            templates['application/x-www-form-urlencoded'] = form_template
            templates['multipart/form-data'] = form_template

        return templates

    def _generate_template_from_schema(self, schema: Dict[str, Any]) -> Any:
        """Generate template from JSON schema"""
        if not isinstance(schema, dict):
            return None
            
        schema_type = schema.get('type', 'object')
        
        if schema_type == 'object':
            template = {}
            properties = schema.get('properties', {})
            for prop_name, prop_schema in properties.items():
                template[prop_name] = self._generate_template_from_schema(prop_schema)
            return template
        elif schema_type == 'array':
            items = schema.get('items', {})
            return [self._generate_template_from_schema(items)]
        else:
            return self._generate_default_value({'type': schema_type})

    def _generate_default_value(self, param: Dict[str, Any]) -> Any:
        """Generate default value based on parameter type"""
        param_type = param.get('type', 'string')
        format_type = param.get('format', '')
        
        if 'default' in param:
            return param['default']
        elif 'example' in param:
            return param['example']
        elif param_type == 'string':
            if format_type == 'date-time':
                return datetime.utcnow().isoformat()
            elif format_type == 'date':
                return datetime.utcnow().date().isoformat()
            elif format_type == 'email':
                return 'test@example.com'
            elif format_type == 'uuid':
                return '00000000-0000-0000-0000-000000000000'
            return 'string'
        elif param_type == 'integer':
            return 0
        elif param_type == 'number':
            return 0.0
        elif param_type == 'boolean':
            return True
        elif param_type == 'array':
            items = param.get('items', {})
            return [self._generate_default_value({'type': items.get('type', 'string')})]
        elif param_type == 'object':
            return {}
        return None

    def _add_unique_endpoint(self, endpoint_info: Dict[str, Any]):
        """Add endpoint if not already discovered"""
        with self.lock:
            # Check for existing endpoint with same path and method
            existing = next(
                (ep for ep in self.discovered_endpoints 
                 if ep['path'] == endpoint_info['path'] and 
                 ep['method'] == endpoint_info['method']),
                None
            )

            if existing:
                # Update existing endpoint if new info is more detailed
                if len(str(endpoint_info)) > len(str(existing)):
                    existing.update(endpoint_info)
            else:
                self.discovered_endpoints.append(endpoint_info)
                self.logger.info(
                    f"[{Colors.CYAN}DOCS_DISCOVERY{Colors.END}] "
                    f"{endpoint_info['method']} {endpoint_info['path']} "
                    f"({'Authenticated' if endpoint_info['auth_required'] else 'Public'})"
                )

    def _generate_test_cases(self, endpoint_info: Dict[str, Any]):
        """Generate test cases for endpoint"""
        test_cases = []

        # Authentication test cases
        if endpoint_info.get('auth_required'):
            test_cases.extend([
                {
                    'name': 'missing_auth',
                    'description': 'Request without authentication',
                    'headers': {},
                    'expected_status': 401
                },
                {
                    'name': 'invalid_auth',
                    'description': 'Request with invalid authentication',
                    'headers': {'Authorization': 'Bearer invalid_token'},
                    'expected_status': 401
                }
            ])

        # Parameter test cases
        for param in endpoint_info.get('parameters', []):
            if param.get('required'):
                test_cases.append({
                    'name': f'missing_{param["name"]}',
                    'description': f'Request without required parameter {param["name"]}',
                    'parameters': {p['name']: self._generate_default_value(p) 
                                 for p in endpoint_info.get('parameters', []) 
                                 if p['name'] != param['name']},
                    'expected_status': 400
                })

        # Store test cases
        endpoint_info['test_cases'] = test_cases

    def extract_openapi_endpoints(self, openapi_data: Dict[str, Any]):
        """
        Enhanced OpenAPI 3.x endpoint extraction
        """
        servers = openapi_data.get('servers', [{'url': self.target_url}])
        paths = openapi_data.get('paths', {})
        global_security = openapi_data.get('security', [])

        # Process each server
        for server in servers:
            base_url = server['url']
            variables = server.get('variables', {})

            # Handle server variables
            if variables:
                for var_name, var_info in variables.items():
                    default_value = var_info.get('default', '')
                    base_url = base_url.replace(f'{{{var_name}}}', str(default_value))
                    
            # Process each path
            for path, path_item in paths.items():
                # Process common parameters for all methods in this path
                common_parameters = path_item.get('parameters', [])

                # Process each HTTP method
                for method, operation in path_item.items():
                    if method.upper() not in COMMON_HTTP_METHODS:
                        continue

                    method = method.upper()
                    security = operation.get('security', global_security)
                    auth_required = bool(security)

                    # Combine common and operation-specific parameters
                    parameters = common_parameters.copy()
                    parameters.extend(operation.get('parameters', []))

                    # Process request body
                    request_body_info = operation.get('requestBody', {})
                    request_body = self._process_request_body(request_body_info)

                    # Process responses
                    responses = {}
                    for status_code, response_info in operation.get('responses', {}).items():
                        responses[status_code] = {
                            'description': response_info.get('description', ''),
                            'headers': response_info.get('headers', {}),
                            'content': response_info.get('content', {}),
                            'links': response_info.get('links', {})
                        }

                    # Create endpoint info
                    full_url = urljoin(base_url, path.lstrip('/'))
                    endpoint_info = {
                        'url': full_url,
                        'path': path,
                        'method': method,
                        'summary': operation.get('summary', ''),
                        'description': operation.get('description', ''),
                        'parameters': parameters,
                        'request_body': request_body,
                        'responses': responses,
                        'auth_required': auth_required,
                        'security': security,
                        'deprecated': operation.get('deprecated', False),
                        'tags': operation.get('tags', []),
                        'operation_id': operation.get('operationId', ''),
                        'source': 'openapi3',
                        'discovered_time': datetime.utcnow().isoformat(),
                        'servers': operation.get('servers', servers)
                    }

                    # Add to discovered endpoints
                    self._add_unique_endpoint(endpoint_info)

                    # Generate test cases
                    self._generate_test_cases(endpoint_info)

                    # Generate documentation
                    self._generate_endpoint_documentation(endpoint_info)

    def _process_request_body(self, request_body_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process OpenAPI request body information"""
        if not request_body_info:
            return None

        request_body = {
            'description': request_body_info.get('description', ''),
            'required': request_body_info.get('required', False),
            'content': {}
        }

        # Process each content type
        for content_type, content_info in request_body_info.get('content', {}).items():
            schema = content_info.get('schema', {})
            example = content_info.get('example')
            examples = content_info.get('examples', {})

            content_data = {
                'schema': schema,
                'template': self._generate_template_from_schema(schema) if schema else None,
                'example': example,
                'examples': examples
            }

            request_body['content'][content_type] = content_data

        return request_body

    def _generate_endpoint_documentation(self, endpoint_info: Dict[str, Any]):
        """Generate detailed documentation for endpoint"""
        doc = {
            'endpoint': f"{endpoint_info['method']} {endpoint_info['path']}",
            'url': endpoint_info['url'],
            'summary': endpoint_info['summary'],
            'description': endpoint_info['description'],
            'authentication': {
                'required': endpoint_info['auth_required'],
                'schemes': endpoint_info['security']
            },
            'parameters': self._document_parameters(endpoint_info.get('parameters', [])),
            'request_body': self._document_request_body(endpoint_info.get('request_body')),
            'responses': self._document_responses(endpoint_info.get('responses', {})),
            'deprecated': endpoint_info.get('deprecated', False),
            'tags': endpoint_info.get('tags', [])
        }

        # Store documentation
        endpoint_info['documentation'] = doc

    def _document_parameters(self, parameters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate documentation for parameters"""
        docs = []
        for param in parameters:
            param_doc = {
                'name': param.get('name', ''),
                'in': param.get('in', ''),
                'required': param.get('required', False),
                'description': param.get('description', ''),
                'schema': {
                    'type': param.get('schema', {}).get('type', param.get('type', 'string')),
                    'format': param.get('schema', {}).get('format', param.get('format', '')),
                    'enum': param.get('schema', {}).get('enum', param.get('enum', [])),
                    'default': param.get('schema', {}).get('default', param.get('default'))
                }
            }
            docs.append(param_doc)
        return docs

    def _document_request_body(self, request_body: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Generate documentation for request body"""
        if not request_body:
            return None

        return {
            'description': request_body.get('description', ''),
            'required': request_body.get('required', False),
            'content_types': list(request_body.get('content', {}).keys()),
            'schemas': {
                content_type: {
                    'schema': content_info.get('schema'),
                    'example': content_info.get('example'),
                    'template': content_info.get('template')
                }
                for content_type, content_info in request_body.get('content', {}).items()
            }
        }

    def _document_responses(self, responses: Dict[str, Any]) -> Dict[str, Any]:
        """Generate documentation for responses"""
        docs = {}
        for status_code, response_info in responses.items():
            docs[status_code] = {
                'description': response_info.get('description', ''),
                'headers': response_info.get('headers', {}),
                'content_types': list(response_info.get('content', {}).keys()),
                'links': response_info.get('links', {})
            }
        return docs
    
    def test_endpoint_security(self, endpoint_info: Dict[str, Any]):
        """
        Comprehensive security testing for endpoint - OPTIMIZED
        """
        url = endpoint_info['url']
        method = endpoint_info['method']
        parameters = endpoint_info.get('parameters', [])
        auth_required = endpoint_info.get('auth_required', False)

        self.logger.info(f"\n[{Colors.BLUE}TESTING{Colors.END}] {method} {url}")

        test_results = []
        
        # Authentication tests
        if auth_required:
            auth_results = self._test_authentication(endpoint_info)
            test_results.extend(auth_results)

        # Input validation tests (optimized for speed)
        validation_results = self._test_input_validation_optimized(endpoint_info)
        test_results.extend(validation_results)

        # Injection tests (quick check only)
        injection_results = self._test_injections_quick(endpoint_info)
        test_results.extend(injection_results)

        # Rate limiting tests (if scan mode is full)
        if self.scan_mode == ScanMode.FULL:
            rate_limit_results = self._test_rate_limiting(endpoint_info)
            test_results.extend(rate_limit_results)

        # Method-specific tests
        if method in ['POST', 'PUT', 'PATCH']:
            content_type_results = self._test_content_types(endpoint_info)
            test_results.extend(content_type_results)

        # CORS tests (quick check)
        cors_results = self._test_cors_quick(endpoint_info)
        test_results.extend(cors_results)

        # Store results
        endpoint_info['security_test_results'] = test_results
        
        # Update statistics
        critical_high_vulns = [r for r in test_results if r.get('severity') in ['High', 'Critical']]
        self.stats['vulnerabilities_found'] += len(critical_high_vulns)
        self.vulnerabilities.extend(test_results)

        return test_results

    def _test_authentication(self, endpoint_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test authentication security - OPTIMIZED"""
        results = []
        url = endpoint_info['url']
        method = endpoint_info['method']

        # Simplified test cases for speed
        test_cases = [
            {
                'name': 'no_auth',
                'headers': {},
                'expected_status': [401, 403]
            },
            {
                'name': 'invalid_token',
                'headers': {'Authorization': 'Bearer invalid_token_here'},
                'expected_status': [401, 403]
            }
        ]

        for test in test_cases:
            try:
                response = self._make_request(
                    method=method,
                    url=url,
                    headers=test['headers'],
                    allow_redirects=False
                )

                if response and response.status_code not in test['expected_status']:
                    results.append({
                        'type': 'Authentication_Bypass',
                        'severity': 'Critical',
                        'confidence': 'High',
                        'description': f"Authentication bypass possible with {test['name']}",
                        'test_case': test['name'],
                        'status_code': response.status_code,
                        'expected_status': test['expected_status'],
                        'url': url,
                        'method': method,
                        'recommendation': 'Implement proper authentication checks'
                    })

            except Exception as e:
                self.logger.debug(f"Auth test error for {test['name']}: {str(e)}")

        return results

    def _test_input_validation_optimized(self, endpoint_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        OPTIMIZED input validation testing - focus on critical issues only
        """
        results = []
        url = endpoint_info['url']
        method = endpoint_info['method']
        parameters = endpoint_info.get('parameters', [])

        # Reduced payload set for faster testing
        critical_payloads = {
            'sql': ["' OR '1'='1", "1; DROP TABLE users--"],
            'xss': ["<script>alert('XSS')</script>", "javascript:alert('XSS')"],
            'command': ['; ls -la', '`whoami`'],
            'path_traversal': ['../../../etc/passwd', '..\\..\\windows\\system32\\config\\sam']
        }

        for param in parameters[:5]:  # Limit to first 5 parameters for speed
            param_name = param.get('name', '')
            param_location = param.get('in', '')

            # Only test critical injection types
            for injection_type, payloads in critical_payloads.items():
                for payload in payloads[:2]:  # Only test first 2 payloads of each type
                    try:
                        # Prepare request based on parameter location
                        data = {}
                        params = {}
                        headers = {}
                        json_data = None

                        if param_location == 'query':
                            params = {param_name: payload}
                        elif param_location == 'header':
                            headers = {param_name: payload}
                        elif param_location == 'path':
                            url = url.replace(f'{{{param_name}}}', payload)
                        else:  # body or formData
                            if method in ['POST', 'PUT', 'PATCH']:
                                json_data = {param_name: payload}

                        response = self._make_request(
                            method=method,
                            url=url,
                            params=params,
                            headers=headers,
                            data=data,
                            json=json_data,
                            allow_redirects=False
                        )

                        if response:
                            vulnerability = self._analyze_injection_response_quick(
                                response, injection_type, payload, param_name, param_location
                            )
                            if vulnerability:
                                results.append(vulnerability)

                    except Exception as e:
                        self.logger.debug(f"Quick injection test error for {param_name}: {str(e)}")

        return results

    def _analyze_injection_response_quick(self, response: requests.Response, injection_type: str,
                                        payload: str, param_name: str, param_location: str) -> Optional[Dict[str, Any]]:
        """Quick analysis for injection vulnerabilities"""
        # Quick patterns for critical issues
        critical_patterns = {
            'sql': [r'SQL syntax.*MySQL', r'Warning.*SQLite3', r'ORA-[0-9]+'],
            'xss': [r'<script>alert\(.*\)</script>'],
            'command': [r'root:.*:0:0:', r'/bin/bash'],
            'path_traversal': [r'root:.*:0:0:', r'etc/passwd']
        }

        # Check for server errors
        if response.status_code in [500, 503]:
            return {
                'type': f'{injection_type.upper()}_Injection',
                'severity': 'High',
                'confidence': 'Medium',
                'description': f'Potential {injection_type} injection via {param_location} parameter "{param_name}"',
                'evidence': f'Server error triggered with payload: {payload}',
                'status_code': response.status_code,
                'param_name': param_name,
                'param_location': param_location,
                'payload': payload,
                'request': {
                    'method': response.request.method,
                    'url': response.request.url,
                    'headers': dict(response.request.headers),
                    'body': response.request.body.decode() if response.request.body and hasattr(response.request.body, 'decode') else str(response.request.body)
                },
                'response_snippet': response.text[:200],
                'recommendation': f'Implement proper input validation for {param_name}'
            }

        # Quick pattern matching (only check first 5000 chars for speed)
        response_text = response.text[:5000].lower()
        for pattern in critical_patterns.get(injection_type, []):
            if re.search(pattern, response_text, re.IGNORECASE):
                return {
                    'type': f'{injection_type.upper()}_Injection',
                    'severity': 'Critical',
                    'confidence': 'High',
                    'description': f'Confirmed {injection_type} injection via {param_location} parameter "{param_name}"',
                    'evidence': f'Pattern matched in response: {pattern}',
                    'status_code': response.status_code,
                    'param_name': param_name,
                    'param_location': param_location,
                    'payload': payload,
                    'request': {
                        'method': response.request.method,
                        'url': response.request.url,
                        'headers': dict(response.request.headers),
                        'body': response.request.body.decode() if response.request.body and hasattr(response.request.body, 'decode') else str(response.request.body)
                    },
                    'response_snippet': response.text[:200],
                    'recommendation': f'Implement proper input validation and sanitization for {param_name}'
                }

        return None

    def _test_injections_quick(self, endpoint_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Quick injection tests for POST/PUT endpoints"""
        results = []
        url = endpoint_info['url']
        method = endpoint_info['method']

        if method not in ['POST', 'PUT', 'PATCH']:
            return results

        # Quick injection payloads
        quick_payloads = [
            {"test": "' OR '1'='1"},
            {"test": "<script>alert('XSS')</script>"},
            {"test": "'; ls -la"}
        ]

        for payload in quick_payloads:
            try:
                response = self._make_request(
                    method=method,
                    url=url,
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                )

                if response and response.status_code == 500:
                    error_indicators = ['sql', 'mysql', 'error', 'exception', 'stack trace']
                    if any(indicator in response.text.lower() for indicator in error_indicators):
                        results.append({
                            'type': 'Injection_Vulnerability',
                            'severity': 'Critical',
                            'confidence': 'Medium',
                            'description': 'Potential injection vulnerability detected',
                            'url': url,
                            'method': method,
                            'payload': str(payload),
                            'recommendation': 'Implement input validation and error handling'
                        })
                        break  # Found one, no need to test more

            except Exception as e:
                self.logger.debug(f"Quick injection test error: {str(e)}")

        return results

    def _test_rate_limiting(self, endpoint_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        OPTIMIZED rate limiting test - reduced scope for performance
        """
        results = []
        url = endpoint_info['url']
        method = endpoint_info['method']

        # Simplified rate limit test
        responses = []
        for _ in range(20):  # Reduced from 100
            response = self._make_request(method, url)
            if response:
                responses.append(response)
            else:
                break

        # Check for rate limiting indicators
        rate_limited_responses = [r for r in responses if r.status_code == 429]
        rate_limit_headers = [
            'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'Retry-After'
        ]

        has_rate_limit_headers = any(
            any(h in response.headers for h in rate_limit_headers)
            for response in responses
        )

        if not has_rate_limit_headers and not rate_limited_responses and len(responses) >= 15:
            results.append({
                'type': 'Missing_Rate_Limiting',
                'severity': 'Medium',
                'confidence': 'Medium',
                'description': f'No rate limiting detected for {len(responses)} requests',
                'url': url,
                'recommendation': 'Implement rate limiting to prevent abuse'
            })

        return results

    def _test_cors_quick(self, endpoint_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Quick CORS configuration test"""
        results = []
        url = endpoint_info['url']
        method = endpoint_info['method']

        try:
            # Test with evil origin
            response = self._make_request(
                method='OPTIONS',
                url=url,
                headers={
                    'Origin': 'https://evil.com',
                    'Access-Control-Request-Method': method
                }
            )

            if response:
                cors_origin = response.headers.get('Access-Control-Allow-Origin')
                cors_credentials = response.headers.get('Access-Control-Allow-Credentials')

                if cors_origin == '*':
                    results.append({
                        'type': 'CORS_Wildcard_Origin',
                        'severity': 'Medium',
                        'confidence': 'High',
                        'description': 'CORS allows requests from any origin',
                        'url': url,
                        'recommendation': 'Restrict CORS to specific trusted origins'
                    })

                elif cors_origin == 'https://evil.com':
                    results.append({
                        'type': 'CORS_Origin_Reflection',
                        'severity': 'High',
                        'confidence': 'High',
                        'description': 'CORS origin header is reflected',
                        'url': url,
                        'recommendation': 'Implement strict CORS origin validation'
                    })

        except Exception as e:
            self.logger.debug(f"CORS test error: {str(e)}")

        return results

    def _test_content_types(self, endpoint_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        OPTIMIZED content type testing
        """
        results = []
        url = endpoint_info['url']
        method = endpoint_info['method']
        
        if method not in ['POST', 'PUT', 'PATCH']:
            return results

        # Quick content type tests
        test_cases = [
            {
                'name': 'xml_injection',
                'content_type': 'application/xml',
                'data': '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
            },
            {
                'name': 'invalid_content_type',
                'content_type': 'invalid/type',
                'data': 'test data'
            }
        ]

        for test in test_cases:
            try:
                response = self._make_request(
                    method=method,
                    url=url,
                    headers={'Content-Type': test['content_type']},
                    data=test['data']
                )

                if response:
                    if test['name'] == 'xml_injection' and 'root:' in response.text:
                        results.append({
                            'type': 'XXE_Vulnerability',
                            'severity': 'Critical',
                            'confidence': 'High',
                            'description': 'XML External Entity (XXE) vulnerability detected',
                            'url': url,
                            'recommendation': 'Disable XML external entity processing'
                        })

            except Exception as e:
                self.logger.debug(f"Content type test error: {str(e)}")

        return results

    def analyze_graphql_endpoint(self, url: str) -> List[Dict[str, Any]]:
        """
        OPTIMIZED GraphQL security testing
        """
        results = []
        
        # Quick GraphQL tests
        test_queries = {
            'introspection': {
                'query': '{ __schema { types { name } } }',
                'description': 'GraphQL Introspection Query'
            },
            'nested_query': {
                'query': '{ user { friends { friends { name } } } }',
                'description': 'Nested Query Test'
            }
        }

        for test_name, test_data in test_queries.items():
            try:
                response = self._make_request(
                    method='POST',
                    url=url,
                    json={'query': test_data['query']},
                    headers={'Content-Type': 'application/json'}
                )

                if response and response.status_code == 200:
                    try:
                        response_data = response.json()
                        
                        if test_name == 'introspection' and '__schema' in str(response_data):
                            results.append({
                                'type': 'GraphQL_Introspection_Enabled',
                                'severity': 'Medium',
                                'confidence': 'High',
                                'description': 'GraphQL introspection is enabled',
                                'url': url,
                                'recommendation': 'Disable introspection in production'
                            })
                            
                            self.vulnerabilities.append(results[-1])
                            
                    except json.JSONDecodeError:
                        pass

            except Exception as e:
                self.logger.debug(f"GraphQL test error for {test_name}: {str(e)}")

        return results

    def generate_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive security assessment report
        """
        report = {
            'metadata': {
                'scan_id': self.scan_id,
                'target_url': self.target_url,
                'scan_date': datetime.utcnow().isoformat(),
                'scan_duration': round(time.time() - self.start_time, 2),
                'scanner_version': '3.1.0',
                'scan_mode': self.scan_mode,
                'generated_by': 'greenlights00'
            },
            'summary': {
                'endpoints_discovered': len(self.discovered_endpoints),
                'vulnerabilities_found': len(self.vulnerabilities),
                'security_score': self._calculate_security_score(),
                'risk_level': self._determine_risk_level(),
                'api_versions': self.api_versions,
                'requests_made': self.stats['requests_made']
            },
            'endpoints': self._format_endpoints_report(),
            'vulnerabilities': self._format_vulnerabilities_report(),
            'recommendations': self._generate_recommendations(),
            'compliance': self._check_compliance_requirements() if self.scan_mode == ScanMode.FULL else {},
            'statistics': self.stats
        }

        # Add GraphQL specific information if applicable
        if self.graphql_schemas:
            report['graphql_analysis'] = self._format_graphql_report()

        return report

    def _calculate_security_score(self) -> float:
        """Calculate overall security score"""
        base_score = 100.0
        deductions = {
            'Critical': 20.0,
            'High': 10.0,
            'Medium': 5.0,
            'Low': 2.0,
            'Info': 0.5
        }

        # Group vulnerabilities by severity
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Low')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Calculate deductions
        total_deduction = 0.0
        for severity, count in severity_counts.items():
            deduction = deductions.get(severity, 0) * count
            total_deduction += deduction

        # Ensure score doesn't go below 0
        final_score = max(0.0, base_score - total_deduction)
        return round(final_score, 2)

    def _determine_risk_level(self) -> str:
        """Determine overall risk level based on vulnerabilities"""
        severity_weights = {
            'Critical': 100,
            'High': 50,
            'Medium': 20,
            'Low': 5,
            'Info': 1
        }

        total_weight = 0
        for vuln in self.vulnerabilities:
            total_weight += severity_weights.get(vuln.get('severity', 'Low'), 0)

        if total_weight >= 500:
            return 'Critical'
        elif total_weight >= 200:
            return 'High'
        elif total_weight >= 100:
            return 'Medium'
        elif total_weight > 0:
            return 'Low'
        return 'Minimal'

    def _format_endpoints_report(self) -> List[Dict[str, Any]]:
        """Format discovered endpoints for report"""
        formatted_endpoints = []

        for endpoint in self.discovered_endpoints:
            formatted_endpoint = {
                'url': endpoint['url'],
                'method': endpoint['method'],
                'path': endpoint['path'],
                'status_code': endpoint.get('status_code', 'Unknown'),
                'authentication': endpoint.get('auth_required', False),
                'content_type': endpoint.get('content_type', ''),
                'source': endpoint.get('source', 'discovery'),
                'security_issues': len([v for v in self.vulnerabilities if v.get('url') == endpoint['url']])
            }
            formatted_endpoints.append(formatted_endpoint)

        return formatted_endpoints

    def _format_vulnerabilities_report(self) -> Dict[str, List[Dict[str, Any]]]:
        """Format vulnerabilities by severity"""
        formatted_vulns = {
            'Critical': [],
            'High': [],
            'Medium': [],
            'Low': [],
            'Info': []
        }

        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Low')
            formatted_vuln = {
                'type': vuln.get('type', 'Unknown'),
                'description': vuln.get('description', ''),
                'confidence': vuln.get('confidence', 'Medium'),
                'url': vuln.get('url', ''),
                'recommendation': vuln.get('recommendation', '')
            }
            formatted_vulns[severity].append(formatted_vuln)

        return formatted_vulns

    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate prioritized security recommendations"""
        recommendations = []
        
        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = {
                    'count': 1,
                    'severity': vuln.get('severity', 'Low'),
                    'recommendation': vuln.get('recommendation', 'Review and fix this issue')
                }
            else:
                vuln_types[vuln_type]['count'] += 1

        # Priority scoring
        priority_weights = {
            'Critical': 100,
            'High': 75,
            'Medium': 50,
            'Low': 25,
            'Info': 10
        }

        for vuln_type, info in vuln_types.items():
            priority_score = priority_weights[info['severity']] * info['count']
            
            recommendation = {
                'title': f"Fix {vuln_type.replace('_', ' ')}",
                'description': info['recommendation'],
                'severity': info['severity'],
                'affected_count': info['count'],
                'priority_score': priority_score
            }
            
            recommendations.append(recommendation)

        # Sort by priority score
        recommendations.sort(key=lambda x: x['priority_score'], reverse=True)
        return recommendations

    def _check_compliance_requirements(self) -> Dict[str, Any]:
        """Basic compliance checking"""
        compliance = {
            'timestamp': datetime.utcnow().isoformat(),
            'OWASP_API_Security': {
                'score': max(0, 100 - len([v for v in self.vulnerabilities if v.get('severity') in ['Critical', 'High']]) * 10),
                'critical_issues': len([v for v in self.vulnerabilities if v.get('severity') == 'Critical']),
                'high_issues': len([v for v in self.vulnerabilities if v.get('severity') == 'High'])
            }
        }
        return compliance

    def _format_graphql_report(self) -> Dict[str, Any]:
        """Format GraphQL analysis results"""
        return {
            'endpoints_found': len([ep for ep in self.discovered_endpoints if 'graphql' in ep.get('path', '').lower()]),
            'schemas_discovered': len(self.graphql_schemas),
            'introspection_enabled': len([v for v in self.vulnerabilities if v.get('type') == 'GraphQL_Introspection_Enabled']) > 0
        }

    def run(self) -> dict:
        try:
            if not self.silent:
                print(f"[API] Starting API security scan for {self.target_url}")
            self.start_scan()
            report = self.generate_report()
            findings = report.get('vulnerabilities', {})
            errors = []
            # Log each finding
            with open(self.log_file, 'a', encoding='utf-8') as logf:
                # Flatten vulnerabilities by severity
                for severity, vulns in findings.items():
                    for vuln in vulns:
                        logf.write(json.dumps({'module': 'api', 'finding': vuln, 'severity': severity}) + '\n')
            if not self.silent:
                print(f"[API] Scan complete. {report['summary']['vulnerabilities_found']} vulnerabilities found.")
            return {'findings': findings, 'errors': errors, 'full_report': report}
        except Exception as e:
            error_report = {
                'findings': {},
                'errors': [str(e)],
                'full_report': {}
            }
            if not self.silent:
                print(f"[API] Scan failed: {e}")
            return error_report

    @staticmethod
    def main():
        parser = argparse.ArgumentParser(
            description='OPTIMIZED API Security Scanner - Fast and Comprehensive API Security Testing'
        )
        parser.add_argument(
            '--url', 
            type=str, 
            required=True,
            help='Target API URL to scan'
        )
        parser.add_argument(
            '--api-key', 
            type=str, 
            help='API key for authentication'
        )
        parser.add_argument(
            '--output', 
            type=str, 
            default='api_security_report.json',
            help='Output file path (default: api_security_report.json)'
        )
        parser.add_argument(
            '--timeout', 
            type=int, 
            default=DEFAULT_TIMEOUT,
            help=f'Request timeout in seconds (default: {DEFAULT_TIMEOUT})'
        )
        parser.add_argument(
            '--concurrent', 
            type=int, 
            default=DEFAULT_CONCURRENT_REQUESTS,
            help=f'Concurrent requests (default: {DEFAULT_CONCURRENT_REQUESTS})'
        )
        parser.add_argument(
            '--verify-ssl', 
            action='store_true',
            help='Verify SSL certificates (slower but more secure)'
        )
        parser.add_argument(
            '--scan-mode',
            choices=[ScanMode.QUICK, ScanMode.FULL, ScanMode.STEALTH],
            default=ScanMode.FULL,
            help='Scan mode: quick (essential tests), full (comprehensive), stealth (slow but thorough)'
        )
        parser.add_argument(
            '--max-depth',
            type=int,
            default=3,
            help='Maximum discovery depth (default: 3)'
        )

        args = parser.parse_args()

        try:
            scanner = APIScanner(
                target_url=args.url,
                options={
                    "api_key": args.api_key,
                    "timeout": args.timeout,
                    "verify_ssl": args.verify_ssl,
                    "concurrent_requests": args.concurrent,
                    "scan_mode": args.scan_mode,
                    "max_depth": args.max_depth
                }
            )

            scanner.setup_logging()

            print(f"""
╔═══════════════════════════════════════════════╗
║     🚀 OPTIMIZED API Security Scanner 🚀     ║
║         Fast • Comprehensive • Accurate      ║
║            Performance Enhanced v3.1         ║
║              by: greenlights00               ║
╚═══════════════════════════════════════════════╝

🎯 Target: {args.url}
⚡ Mode: {args.scan_mode}
🔧 Timeout: {args.timeout}s
🧵 Threads: {args.concurrent}
🔐 SSL Verify: {args.verify_ssl}
📊 Max Depth: {args.max_depth}
            """)

            start_time = time.time()
            print(f"[{Colors.GREEN}▶{Colors.END}] Starting scan at {datetime.now().strftime('%H:%M:%S')}")
            
            scanner.start_scan()
            
            print(f"\n[{Colors.BLUE}📊{Colors.END}] Generating security report...")
            report = scanner.generate_quick_report() if args.scan_mode == ScanMode.QUICK else scanner.generate_report()
            
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)

            duration = time.time() - start_time
            
            print(f"""
{Colors.GREEN}╔═══ SCAN COMPLETED SUCCESSFULLY ═══╗{Colors.END}
{Colors.GREEN}║{Colors.END} ⏱️  Duration: {duration:.1f} seconds
{Colors.GREEN}║{Colors.END} 🔍 Endpoints: {len(scanner.discovered_endpoints)}
{Colors.GREEN}║{Colors.END} 🛡️  Vulnerabilities: {len(scanner.vulnerabilities)}
{Colors.GREEN}║{Colors.END} 📨 Requests: {scanner.stats['requests_made']}
{Colors.GREEN}║{Colors.END} 📄 Report: {args.output}
{Colors.GREEN}║{Colors.END} 🏆 Security Score: {report['summary'].get('security_score', 'N/A')}/100
{Colors.GREEN}╚═══════════════════════════════════════╝{Colors.END}
            """)

            # Show critical findings
            critical_vulns = [v for v in scanner.vulnerabilities if v.get('severity') in ['Critical', 'High']]
            if critical_vulns:
                print(f"\n{Colors.RED}🚨 CRITICAL/HIGH SEVERITY FINDINGS:{Colors.END}")
                for i, vuln in enumerate(critical_vulns[:5], 1):
                    severity_color = Colors.RED if vuln.get('severity') == 'Critical' else Colors.YELLOW
                    print(f"{severity_color}{i}.{Colors.END} {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")
                if len(critical_vulns) > 5:
                    print(f"   ... and {len(critical_vulns) - 5} more (see report)")
            else:
                print(f"\n{Colors.GREEN}✅ No critical vulnerabilities found!{Colors.END}")

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
            sys.exit(1)
        except Exception as e:
            print(f"\n{Colors.RED}[!] Error: {str(e)}{Colors.END}")
            sys.exit(1)

    def generate_quick_report(self) -> Dict[str, Any]:
        """Generate quick summary report for fast scans"""
        return {
            'scan_summary': {
                'target_url': self.target_url,
                'scan_duration': round(time.time() - self.start_time, 2),
                'scan_mode': self.scan_mode,
                'endpoints_found': len(self.discovered_endpoints),
                'vulnerabilities_found': len(self.vulnerabilities),
                'requests_made': self.stats['requests_made']
            },
            'summary': {
                'endpoints_discovered': len(self.discovered_endpoints),
                'vulnerabilities_found': len(self.vulnerabilities),
                'security_score': self._calculate_security_score(),
                'risk_level': self._determine_risk_level()
            },
            'critical_findings': [
                vuln for vuln in self.vulnerabilities 
                if vuln.get('severity') in ['Critical', 'High']
            ],
            'discovered_endpoints': [
                {
                    'url': ep['url'],
                    'method': ep['method'],
                    'status_code': ep.get('status_code', 'Unknown'),
                    'source': ep.get('source', 'discovery')
                }
                for ep in self.discovered_endpoints
            ],
            'vulnerabilities': self._format_vulnerabilities_report()
        }

if __name__ == "__main__":
    APIScanner.main()
