#!/usr/bin/env python3
"""
PhishingScanner - Free Open Source Security Tool
Main phishing detection and analysis module
"""

import re
import ssl
import socket
import requests
import urllib.parse
import whois
import dns.resolver
import hashlib
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import validators
from cryptography import x509
from cryptography.hazmat.backends import default_backend


@dataclass
class ScanResult:
    """Data structure for scan results"""
    url: str
    timestamp: datetime
    risk_score: int
    is_phishing: bool
    indicators: List[str]
    details: Dict
    response_time: float


class PhishingDetector:
    """Core phishing detection engine"""
    
    def __init__(self, config_path: str = "config.json"):
        self.config = self._load_config(config_path)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PhishingScanner/1.0 Security Tool'
        })
        
        # Known phishing indicators
        self.suspicious_keywords = [
            'urgent', 'verify', 'suspend', 'limited', 'confirm',
            'click here', 'act now', 'winner', 'congratulations',
            'security alert', 'account locked', 'update payment'
        ]
        
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'shorturl.at', 't.co'
        ]
        
        self.trusted_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'github.com', 'stackoverflow.com', 'wikipedia.org'
        ]
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                "thresholds": {
                    "risk_score": 70,
                    "ssl_days_threshold": 30
                },
                "timeouts": {
                    "request_timeout": 10,
                    "dns_timeout": 5
                }
            }
    
    def scan_url(self, url: str) -> ScanResult:
        """Main scanning function"""
        start_time = time.time()
        
        # Validate URL format
        if not validators.url(url):
            return ScanResult(
                url=url,
                timestamp=datetime.now(),
                risk_score=100,
                is_phishing=True,
                indicators=["Invalid URL format"],
                details={"error": "Invalid URL"},
                response_time=time.time() - start_time
            )
        
        indicators = []
        details = {}
        risk_score = 0
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            details['parsed_url'] = {
                'scheme': parsed_url.scheme,
                'domain': parsed_url.netloc,
                'path': parsed_url.path,
                'query': parsed_url.query
            }
            
            # URL structure analysis
            url_risk, url_indicators = self._analyze_url_structure(parsed_url)
            risk_score += url_risk
            indicators.extend(url_indicators)
            
            # Domain analysis
            domain_risk, domain_indicators, domain_details = self._analyze_domain(parsed_url.netloc)
            risk_score += domain_risk
            indicators.extend(domain_indicators)
            details.update(domain_details)
            
            # SSL/TLS analysis
            ssl_risk, ssl_indicators, ssl_details = self._analyze_ssl(parsed_url.netloc)
            risk_score += ssl_risk
            indicators.extend(ssl_indicators)
            details['ssl'] = ssl_details
            
            # HTTP response analysis
            response_risk, response_indicators, response_details = self._analyze_http_response(url)
            risk_score += response_risk
            indicators.extend(response_indicators)
            details['http'] = response_details
            
            # Content analysis
            if 'html_content' in response_details:
                content_risk, content_indicators = self._analyze_content(response_details['html_content'])
                risk_score += content_risk
                indicators.extend(content_indicators)
            
        except Exception as e:
            indicators.append(f"Analysis error: {str(e)}")
            risk_score += 30
            details['error'] = str(e)
        
        # Normalize risk score
        risk_score = min(100, max(0, risk_score))
        is_phishing = risk_score >= self.config.get('thresholds', {}).get('risk_score', 70)
        
        return ScanResult(
            url=url,
            timestamp=datetime.now(),
            risk_score=risk_score,
            is_phishing=is_phishing,
            indicators=indicators,
            details=details,
            response_time=time.time() - start_time
        )
    
    def _analyze_url_structure(self, parsed_url) -> Tuple[int, List[str]]:
        """Analyze URL structure for suspicious patterns"""
        risk_score = 0
        indicators = []
        
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        
        # Check for suspicious URL patterns
        if len(domain) > 50:
            risk_score += 15
            indicators.append("Extremely long domain name")
        
        # Check for IP address instead of domain
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        if re.match(ip_pattern, domain):
            risk_score += 25
            indicators.append("Uses IP address instead of domain name")
        
        # Check for suspicious domain patterns
        if re.search(r'-{2,}', domain):
            risk_score += 10
            indicators.append("Multiple consecutive hyphens in domain")
        
        # Check for homograph attacks
        suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'х', 'у']  # Cyrillic that look like Latin
        if any(char in domain for char in suspicious_chars):
            risk_score += 30
            indicators.append("Potential homograph attack (mixed scripts)")
        
        # Check for URL shorteners
        if any(shortener in domain for shortener in self.suspicious_domains):
            risk_score += 20
            indicators.append("Uses URL shortener service")
        
        # Check for suspicious path patterns
        if re.search(r'(login|signin|account|verify|update|secure)', path):
            risk_score += 15
            indicators.append("Suspicious path keywords")
        
        # Check for excessive subdomains
        subdomain_count = len(domain.split('.')) - 2
        if subdomain_count > 3:
            risk_score += 10
            indicators.append(f"Excessive subdomains ({subdomain_count})")
        
        return risk_score, indicators
    
    def _analyze_domain(self, domain: str) -> Tuple[int, List[str], Dict]:
        """Analyze domain reputation and information"""
        risk_score = 0
        indicators = []
        details = {}
        
        try:
            # WHOIS lookup
            w = whois.whois(domain)
            if w:
                details['whois'] = {
                    'registrar': getattr(w, 'registrar', None),
                    'creation_date': str(getattr(w, 'creation_date', None)),
                    'expiration_date': str(getattr(w, 'expiration_date', None)),
                    'name_servers': getattr(w, 'name_servers', None)
                }
                
                # Check domain age
                creation_date = getattr(w, 'creation_date', None)
                if creation_date:
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    
                    if isinstance(creation_date, datetime):
                        age_days = (datetime.now() - creation_date).days
                        if age_days < 30:
                            risk_score += 25
                            indicators.append(f"Very new domain ({age_days} days old)")
                        elif age_days < 90:
                            risk_score += 15
                            indicators.append(f"Recently created domain ({age_days} days old)")
        
        except Exception as e:
            details['whois_error'] = str(e)
            risk_score += 5
            indicators.append("WHOIS lookup failed")
        
        try:
            # DNS analysis
            dns_info = {}
            
            # A record
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                ips = [str(record) for record in a_records]
                dns_info['A'] = ips
                
                # Check for suspicious IP ranges
                for ip in ips:
                    if ip.startswith(('10.', '192.168.', '172.')):
                        risk_score += 20
                        indicators.append("Domain resolves to private IP address")
            except:
                pass
            
            # MX record
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                dns_info['MX'] = [str(record) for record in mx_records]
            except:
                pass
            
            details['dns'] = dns_info
            
        except Exception as e:
            details['dns_error'] = str(e)
            risk_score += 10
            indicators.append("DNS resolution failed")
        
        # Check against trusted domains
        if any(trusted in domain for trusted in self.trusted_domains):
            risk_score = max(0, risk_score - 20)
            indicators.append("Domain appears to be from trusted source")
        
        return risk_score, indicators, details
    
    def _analyze_ssl(self, domain: str) -> Tuple[int, List[str], Dict]:
        """Analyze SSL certificate"""
        risk_score = 0
        indicators = []
        details = {}
        
        try:
            # Get SSL certificate
            context = ssl.create_default_context()
            sock = socket.create_connection((domain, 443), timeout=5)
            ssock = context.wrap_socket(sock, server_hostname=domain)
            
            cert_der = ssock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Certificate details
            details['certificate'] = {
                'subject': str(cert.subject),
                'issuer': str(cert.issuer),
                'not_valid_before': cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.isoformat(),
                'not_valid_after': cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.isoformat(),
                'serial_number': str(cert.serial_number)
            }
            
            # Check certificate validity
            from datetime import timezone
            now = datetime.now(timezone.utc)
            
            # Use UTC versions if available, otherwise convert to UTC
            if hasattr(cert, 'not_valid_after_utc'):
                not_valid_after = cert.not_valid_after_utc
                not_valid_before = cert.not_valid_before_utc
            else:
                # Convert naive datetime to UTC for comparison
                not_valid_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
                not_valid_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            
            if not_valid_after < now:
                risk_score += 40
                indicators.append("SSL certificate has expired")
            elif (not_valid_after - now).days < 7:
                risk_score += 20
                indicators.append("SSL certificate expires soon")
            
            # Check if certificate is self-signed
            if cert.issuer == cert.subject:
                risk_score += 30
                indicators.append("Self-signed SSL certificate")
            
            # Check certificate age
            cert_age = (now - not_valid_before).days
            if cert_age < 7:
                risk_score += 25
                indicators.append("Very new SSL certificate")
            
            ssock.close()
            
        except ssl.SSLError as e:
            risk_score += 35
            indicators.append(f"SSL/TLS error: {str(e)}")
            details['ssl_error'] = str(e)
        except socket.timeout:
            risk_score += 15
            indicators.append("SSL connection timeout")
        except Exception as e:
            risk_score += 20
            indicators.append(f"SSL analysis failed: {str(e)}")
            details['ssl_error'] = str(e)
        
        return risk_score, indicators, details
    
    def _analyze_http_response(self, url: str) -> Tuple[int, List[str], Dict]:
        """Analyze HTTP response"""
        risk_score = 0
        indicators = []
        details = {}
        
        try:
            response = self.session.get(
                url, 
                timeout=self.config.get('timeouts', {}).get('request_timeout', 10),
                allow_redirects=True
            )
            
            details['status_code'] = response.status_code
            details['headers'] = dict(response.headers)
            details['final_url'] = response.url
            details['redirect_count'] = len(response.history)
            
            # Check for excessive redirects
            if len(response.history) > 3:
                risk_score += 15
                indicators.append(f"Excessive redirects ({len(response.history)})")
            
            # Check for suspicious headers
            headers = response.headers
            
            # Missing security headers
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']
            missing_headers = [h for h in security_headers if h not in headers]
            if missing_headers:
                risk_score += len(missing_headers) * 5
                indicators.append(f"Missing security headers: {', '.join(missing_headers)}")
            
            # Check content type
            content_type = headers.get('Content-Type', '').lower()
            if 'text/html' in content_type:
                details['html_content'] = response.text
            
            # Check for suspicious status codes
            if response.status_code in [301, 302, 307, 308]:
                redirect_url = headers.get('Location', '')
                if redirect_url and urlparse(redirect_url).netloc != urlparse(url).netloc:
                    risk_score += 10
                    indicators.append("Redirects to different domain")
            
        except requests.exceptions.SSLError:
            risk_score += 25
            indicators.append("SSL certificate verification failed")
        except requests.exceptions.Timeout:
            risk_score += 15
            indicators.append("Request timeout")
        except requests.exceptions.ConnectionError:
            risk_score += 20
            indicators.append("Connection failed")
        except Exception as e:
            risk_score += 15
            indicators.append(f"HTTP analysis failed: {str(e)}")
            details['http_error'] = str(e)
        
        return risk_score, indicators, details
    
    def _analyze_content(self, html_content: str) -> Tuple[int, List[str]]:
        """Analyze webpage content for phishing indicators"""
        risk_score = 0
        indicators = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            text = soup.get_text().lower()
            
            # Check for suspicious keywords
            suspicious_count = sum(1 for keyword in self.suspicious_keywords if keyword in text)
            if suspicious_count > 3:
                risk_score += 20
                indicators.append(f"Multiple suspicious keywords ({suspicious_count})")
            elif suspicious_count > 0:
                risk_score += 10
                indicators.append(f"Contains suspicious keywords ({suspicious_count})")
            
            # Check for forms
            forms = soup.find_all('form')
            for form in forms:
                # Check for password/login forms
                password_inputs = form.find_all('input', {'type': 'password'})
                if password_inputs:
                    action = form.get('action', '')
                    method = form.get('method', 'get').lower()
                    
                    if not action or action.startswith('javascript:'):
                        risk_score += 25
                        indicators.append("Login form with suspicious action")
                    elif method == 'get':
                        risk_score += 15
                        indicators.append("Password form using GET method")
            
            # Check for hidden iframes
            iframes = soup.find_all('iframe')
            for iframe in iframes:
                style = iframe.get('style', '')
                if 'display:none' in style.replace(' ', '') or 'visibility:hidden' in style.replace(' ', ''):
                    risk_score += 20
                    indicators.append("Hidden iframe detected")
            
            # Check for suspicious JavaScript
            scripts = soup.find_all('script')
            js_content = ' '.join([script.get_text() for script in scripts if script.get_text()])
            
            suspicious_js_patterns = ['eval(', 'document.write(', 'window.open(', 'location.replace(']
            for pattern in suspicious_js_patterns:
                if pattern in js_content:
                    risk_score += 10
                    indicators.append(f"Suspicious JavaScript pattern: {pattern}")
                    break
            
            # Check for urgency indicators
            urgency_words = ['urgent', 'immediate', 'expires today', 'act now', 'limited time']
            urgency_count = sum(1 for word in urgency_words if word in text)
            if urgency_count > 2:
                risk_score += 15
                indicators.append("Multiple urgency indicators")
            
        except Exception as e:
            risk_score += 5
            indicators.append(f"Content analysis error: {str(e)}")
        
        return risk_score, indicators


if __name__ == "__main__":
    # Example usage
    detector = PhishingDetector()
    
    test_urls = [
        "https://github.com",
        "https://google.com",
        "http://suspicious-site-example.com"
    ]
    
    for url in test_urls:
        print(f"\nScanning: {url}")
        result = detector.scan_url(url)
        print(f"Risk Score: {result.risk_score}/100")
        print(f"Is Phishing: {result.is_phishing}")
        print(f"Indicators: {', '.join(result.indicators)}")
