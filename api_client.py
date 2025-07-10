#!/usr/bin/env python3
"""
PhishingScanner API Client
Python client library for the PhishingScanner API
"""

import requests
import json
from typing import List, Dict, Optional
from datetime import datetime


class PhishingScannerClient:
    """Client for interacting with PhishingScanner API"""
    
    def __init__(self, base_url: str = "http://localhost:5000", timeout: int = 30):
        """
        Initialize the API client
        
        Args:
            base_url: Base URL of the PhishingScanner server
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'PhishingScanner-Client/1.0'
        })
    
    def scan_url(self, url: str) -> Dict:
        """
        Scan a single URL for phishing indicators
        
        Args:
            url: URL to scan
            
        Returns:
            Dict containing scan results
            
        Raises:
            requests.RequestException: If the request fails
        """
        endpoint = f"{self.base_url}/api/scan"
        
        try:
            response = self.session.post(
                endpoint,
                json={'url': url},
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
            
        except requests.RequestException as e:
            raise Exception(f"Failed to scan URL: {e}")
    
    def batch_scan(self, urls: List[str]) -> Dict:
        """
        Scan multiple URLs for phishing indicators
        
        Args:
            urls: List of URLs to scan (max 50)
            
        Returns:
            Dict containing batch scan results
            
        Raises:
            requests.RequestException: If the request fails
            ValueError: If too many URLs provided
        """
        if len(urls) > 50:
            raise ValueError("Maximum 50 URLs allowed per batch")
        
        endpoint = f"{self.base_url}/api/batch-scan"
        
        try:
            response = self.session.post(
                endpoint,
                json={'urls': urls},
                timeout=self.timeout * 2  # Longer timeout for batch
            )
            response.raise_for_status()
            return response.json()
            
        except requests.RequestException as e:
            raise Exception(f"Failed to batch scan URLs: {e}")
    
    def get_history(self) -> List[Dict]:
        """
        Get recent scan history
        
        Returns:
            List of recent scan results
            
        Raises:
            requests.RequestException: If the request fails
        """
        endpoint = f"{self.base_url}/api/history"
        
        try:
            response = self.session.get(endpoint, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
            
        except requests.RequestException as e:
            raise Exception(f"Failed to get history: {e}")
    
    def get_stats(self) -> Dict:
        """
        Get scanning statistics
        
        Returns:
            Dict containing statistics
            
        Raises:
            requests.RequestException: If the request fails
        """
        endpoint = f"{self.base_url}/api/stats"
        
        try:
            response = self.session.get(endpoint, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
            
        except requests.RequestException as e:
            raise Exception(f"Failed to get stats: {e}")
    
    def export_data(self, format: str = 'json') -> bytes:
        """
        Export scan history data
        
        Args:
            format: Export format ('json' or 'csv')
            
        Returns:
            Exported data as bytes
            
        Raises:
            requests.RequestException: If the request fails
            ValueError: If invalid format specified
        """
        if format not in ['json', 'csv']:
            raise ValueError("Format must be 'json' or 'csv'")
        
        endpoint = f"{self.base_url}/export/{format}"
        
        try:
            response = self.session.get(endpoint, timeout=self.timeout)
            response.raise_for_status()
            return response.content
            
        except requests.RequestException as e:
            raise Exception(f"Failed to export data: {e}")
    
    def is_server_online(self) -> bool:
        """
        Check if the PhishingScanner server is online
        
        Returns:
            True if server is responding, False otherwise
        """
        try:
            response = self.session.get(
                f"{self.base_url}/api/stats", 
                timeout=5
            )
            return response.status_code == 200
        except:
            return False
    
    def scan_and_wait(self, url: str, verbose: bool = False) -> Dict:
        """
        Scan a URL and display progress (for CLI usage)
        
        Args:
            url: URL to scan
            verbose: Whether to print progress
            
        Returns:
            Scan results
        """
        if verbose:
            print(f"Scanning: {url}")
        
        try:
            result = self.scan_url(url)
            
            if verbose:
                self._print_result(result)
            
            return result
            
        except Exception as e:
            if verbose:
                print(f"Error: {e}")
            raise
    
    def _print_result(self, result: Dict):
        """Print scan result in a formatted way"""
        print(f"\nResults for: {result['url']}")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Status: {'PHISHING' if result['is_phishing'] else 'SAFE'}")
        print(f"Response Time: {result['response_time']}s")
        
        if result.get('indicators'):
            print("Indicators:")
            for indicator in result['indicators']:
                print(f"  - {indicator}")


# Convenience functions
def quick_scan(url: str, server_url: str = "http://localhost:5000") -> Dict:
    """
    Quick scan function for simple usage
    
    Args:
        url: URL to scan
        server_url: PhishingScanner server URL
        
    Returns:
        Scan results
    """
    client = PhishingScannerClient(server_url)
    return client.scan_url(url)


def batch_scan_from_file(
    file_path: str, 
    server_url: str = "http://localhost:5000"
) -> Dict:
    """
    Scan URLs from a file
    
    Args:
        file_path: Path to file containing URLs (one per line)
        server_url: PhishingScanner server URL
        
    Returns:
        Batch scan results
    """
    with open(file_path, 'r') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    client = PhishingScannerClient(server_url)
    return client.batch_scan(urls)


# Example usage
if __name__ == "__main__":
    # Example 1: Simple scan
    try:
        result = quick_scan("https://github.com")
        print(f"GitHub risk score: {result['risk_score']}/100")
    except Exception as e:
        print(f"Error: {e}")
    
    # Example 2: Using client class
    client = PhishingScannerClient()
    
    if client.is_server_online():
        print("Server is online")
        
        # Scan a URL
        try:
            result = client.scan_and_wait("https://google.com", verbose=True)
        except Exception as e:
            print(f"Scan failed: {e}")
        
        # Get statistics
        try:
            stats = client.get_stats()
            print(f"\nTotal scans: {stats['total_scans']}")
            print(f"Phishing detected: {stats['phishing_detected']}")
        except Exception as e:
            print(f"Failed to get stats: {e}")
    else:
        print("Server is offline. Start it with: python app.py")
