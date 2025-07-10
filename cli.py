#!/usr/bin/env python3
"""
PhishingScanner CLI - Command Line Interface
"""

import click
import json
import csv
import sys
from datetime import datetime
from pathlib import Path
from typing import List
import colorama
from colorama import Fore, Style
from tqdm import tqdm

from phishing_scanner import PhishingDetector, ScanResult

# Initialize colorama for Windows support
colorama.init()


class PhishingScannerCLI:
    """Command line interface for PhishingScanner"""
    
    def __init__(self):
        self.detector = PhishingDetector()
    
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Fore.CYAN}
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝ 
██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
                                                          
███████╗ ██████╗ █████╗ ███╗   ███╗███╗   ██╗███████╗██████╗ 
██╔════╝██╔════╝██╔══██╗████╗ ████║████╗  ██║██╔════╝██╔══██╗
███████╗██║     ███████║██╔████╔██║██╔██╗ ██║█████╗  ██████╔╝
╚════██║██║     ██╔══██║██║╚██╔╝██║██║╚██╗██║██╔══╝  ██╔══██╗
███████║╚██████╗██║  ██║██║ ╚═╝ ██║██║ ╚████║███████╗██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.GREEN}🛡️  Free Open Source Security Tool v1.0{Style.RESET_ALL}
{Fore.YELLOW}⚡ Advanced Phishing Detection & Analysis{Style.RESET_ALL}
        """
        print(banner)
    
    def format_risk_level(self, risk_score: int) -> str:
        """Format risk level with colors"""
        if risk_score >= 80:
            return f"{Fore.RED}CRITICAL ({risk_score}/100){Style.RESET_ALL}"
        elif risk_score >= 60:
            return f"{Fore.MAGENTA}HIGH ({risk_score}/100){Style.RESET_ALL}"
        elif risk_score >= 40:
            return f"{Fore.YELLOW}MEDIUM ({risk_score}/100){Style.RESET_ALL}"
        elif risk_score >= 20:
            return f"{Fore.BLUE}LOW ({risk_score}/100){Style.RESET_ALL}"
        else:
            return f"{Fore.GREEN}SAFE ({risk_score}/100){Style.RESET_ALL}"
    
    def print_scan_result(self, result: ScanResult, verbose: bool = False):
        """Print formatted scan result"""
        print(f"\n{Fore.CYAN}📊 SCAN RESULTS{Style.RESET_ALL}")
        print("=" * 60)
        print(f"🌐 URL: {result.url}")
        print(f"⏰ Scan Time: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"⚡ Response Time: {result.response_time:.2f}s")
        print(f"🎯 Risk Level: {self.format_risk_level(result.risk_score)}")
        
        if result.is_phishing:
            print(f"🚨 Status: {Fore.RED}POTENTIAL PHISHING DETECTED{Style.RESET_ALL}")
        else:
            print(f"✅ Status: {Fore.GREEN}APPEARS SAFE{Style.RESET_ALL}")
        
        if result.indicators:
            print(f"\n{Fore.YELLOW}⚠️  SECURITY INDICATORS:{Style.RESET_ALL}")
            for i, indicator in enumerate(result.indicators, 1):
                print(f"   {i}. {indicator}")
        
        if verbose and result.details:
            print(f"\n{Fore.CYAN}🔍 DETAILED ANALYSIS:{Style.RESET_ALL}")
            self._print_details(result.details)
        
        print("=" * 60)
    
    def _print_details(self, details: dict, indent: int = 0):
        """Print detailed analysis results"""
        for key, value in details.items():
            if isinstance(value, dict):
                print("  " * indent + f"{key}:")
                self._print_details(value, indent + 1)
            elif isinstance(value, list):
                print("  " * indent + f"{key}: {', '.join(map(str, value))}")
            else:
                print("  " * indent + f"{key}: {value}")
    
    def scan_single_url(self, url: str, verbose: bool = False):
        """Scan a single URL"""
        print(f"{Fore.CYAN}🔍 Scanning URL: {url}{Style.RESET_ALL}")
        
        with tqdm(total=100, desc="Scanning", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
            pbar.update(20)  # URL validation
            result = self.detector.scan_url(url)
            pbar.update(80)  # Complete scan
        
        self.print_scan_result(result, verbose)
        return result
    
    def scan_multiple_urls(self, urls: List[str], output_file: str = None, verbose: bool = False):
        """Scan multiple URLs"""
        results = []
        
        print(f"{Fore.CYAN}🔍 Scanning {len(urls)} URLs...{Style.RESET_ALL}")
        
        with tqdm(total=len(urls), desc="URLs processed") as pbar:
            for url in urls:
                try:
                    result = self.detector.scan_url(url)
                    results.append(result)
                    
                    # Show quick result
                    status = f"{Fore.RED}PHISHING" if result.is_phishing else f"{Fore.GREEN}SAFE"
                    tqdm.write(f"  {url} - {status} ({result.risk_score}/100){Style.RESET_ALL}")
                    
                except Exception as e:
                    tqdm.write(f"  {Fore.RED}ERROR scanning {url}: {e}{Style.RESET_ALL}")
                
                pbar.update(1)
        
        # Print summary
        self.print_batch_summary(results)
        
        # Save results if requested
        if output_file:
            self.save_results(results, output_file)
        
        # Show detailed results if verbose
        if verbose:
            for result in results:
                self.print_scan_result(result, True)
        
        return results
    
    def print_batch_summary(self, results: List[ScanResult]):
        """Print summary of batch scan results"""
        if not results:
            return
        
        total = len(results)
        phishing_count = sum(1 for r in results if r.is_phishing)
        safe_count = total - phishing_count
        avg_risk = sum(r.risk_score for r in results) / total
        
        print(f"\n{Fore.CYAN}📈 BATCH SCAN SUMMARY{Style.RESET_ALL}")
        print("=" * 40)
        print(f"Total URLs scanned: {total}")
        print(f"🚨 Potential phishing: {Fore.RED}{phishing_count}{Style.RESET_ALL}")
        print(f"✅ Appears safe: {Fore.GREEN}{safe_count}{Style.RESET_ALL}")
        print(f"📊 Average risk score: {avg_risk:.1f}/100")
        print("=" * 40)
    
    def save_results(self, results: List[ScanResult], output_file: str):
        """Save scan results to file"""
        file_path = Path(output_file)
        file_ext = file_path.suffix.lower()
        
        try:
            if file_ext == '.json':
                self._save_json(results, file_path)
            elif file_ext == '.csv':
                self._save_csv(results, file_path)
            else:
                print(f"{Fore.RED}Unsupported file format. Use .json or .csv{Style.RESET_ALL}")
                return
            
            print(f"{Fore.GREEN}✅ Results saved to: {output_file}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}Error saving results: {e}{Style.RESET_ALL}")
    
    def _save_json(self, results: List[ScanResult], file_path: Path):
        """Save results as JSON"""
        json_data = []
        for result in results:
            data = {
                'url': result.url,
                'timestamp': result.timestamp.isoformat(),
                'risk_score': result.risk_score,
                'is_phishing': result.is_phishing,
                'indicators': result.indicators,
                'response_time': result.response_time,
                'details': result.details
            }
            json_data.append(data)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
    
    def _save_csv(self, results: List[ScanResult], file_path: Path):
        """Save results as CSV"""
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'URL', 'Timestamp', 'Risk Score', 'Is Phishing', 
                'Indicators', 'Response Time'
            ])
            
            for result in results:
                writer.writerow([
                    result.url,
                    result.timestamp.isoformat(),
                    result.risk_score,
                    result.is_phishing,
                    '; '.join(result.indicators),
                    f"{result.response_time:.2f}"
                ])


@click.group()
@click.version_option(version='1.0', prog_name='PhishingScanner')
def cli():
    """🛡️ PhishingScanner - Free Open Source Security Tool"""
    pass


@cli.command()
@click.option('--url', '-u', required=True, help='URL to scan for phishing indicators')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed analysis results')
@click.option('--output', '-o', help='Save results to file (JSON or CSV)')
def scan(url: str, verbose: bool, output: str):
    """Scan a single URL for phishing indicators"""
    scanner = PhishingScannerCLI()
    scanner.print_banner()
    
    result = scanner.scan_single_url(url, verbose)
    
    if output:
        scanner.save_results([result], output)


@cli.command()
@click.option('--file', '-f', required=True, type=click.Path(exists=True), 
              help='File containing URLs to scan (one per line)')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed analysis results')
@click.option('--output', '-o', help='Save results to file (JSON or CSV)')
def batch(file: str, verbose: bool, output: str):
    """Scan multiple URLs from a file"""
    scanner = PhishingScannerCLI()
    scanner.print_banner()
    
    # Read URLs from file
    try:
        with open(file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        click.echo(f"Error reading file: {e}", err=True)
        sys.exit(1)
    
    if not urls:
        click.echo("No URLs found in file", err=True)
        sys.exit(1)
    
    scanner.scan_multiple_urls(urls, output, verbose)


@cli.command()
def interactive():
    """Interactive scanning mode"""
    scanner = PhishingScannerCLI()
    scanner.print_banner()
    
    print(f"{Fore.CYAN}🔄 Interactive Mode - Enter URLs to scan (type 'quit' to exit){Style.RESET_ALL}")
    
    while True:
        try:
            url = input(f"\n{Fore.YELLOW}Enter URL: {Style.RESET_ALL}").strip()
            
            if url.lower() in ['quit', 'exit', 'q']:
                print(f"{Fore.GREEN}👋 Goodbye!{Style.RESET_ALL}")
                break
            
            if not url:
                continue
            
            scanner.scan_single_url(url, verbose=True)
            
        except KeyboardInterrupt:
            print(f"\n{Fore.GREEN}👋 Goodbye!{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")


@cli.command()
def demo():
    """Run demo with sample URLs"""
    scanner = PhishingScannerCLI()
    scanner.print_banner()
    
    demo_urls = [
        "https://github.com",
        "https://google.com",
        "https://microsoft.com",
        "http://phishing-demo-site-123456.com"  # This will likely fail as expected
    ]
    
    print(f"{Fore.CYAN}🚀 Running demo with sample URLs...{Style.RESET_ALL}")
    scanner.scan_multiple_urls(demo_urls, verbose=True)


if __name__ == '__main__':
    cli()
