#!/usr/bin/env python3
"""
PhishingScanner Quick Start Script
Easy launcher for different components
"""

import sys
import subprocess
import argparse
from pathlib import Path


def run_setup():
    """Run the setup script"""
    print("🛡️ Running PhishingScanner setup...")
    subprocess.run([sys.executable, "setup.py"])


def run_web_app():
    """Start the web application"""
    print("🌐 Starting PhishingScanner web interface...")
    print("📊 Dashboard will be available at: http://localhost:5000")
    subprocess.run([sys.executable, "app.py"])


def run_cli():
    """Start CLI in interactive mode"""
    print("💻 Starting PhishingScanner CLI in interactive mode...")
    subprocess.run([sys.executable, "cli.py", "interactive"])


def run_demo():
    """Run demo scan"""
    print("🚀 Running PhishingScanner demo...")
    subprocess.run([sys.executable, "cli.py", "demo"])


def scan_url(url):
    """Scan a single URL"""
    print(f"🔍 Scanning URL: {url}")
    subprocess.run([sys.executable, "cli.py", "scan", "--url", url, "--verbose"])


def main():
    parser = argparse.ArgumentParser(
        description="PhishingScanner Quick Start",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py setup          # Run initial setup
  python run.py web            # Start web interface
  python run.py cli            # Start interactive CLI
  python run.py demo           # Run demo scan
  python run.py scan <URL>     # Scan specific URL
        """
    )
    
    parser.add_argument(
        'command',
        choices=['setup', 'web', 'cli', 'demo', 'scan'],
        help='Command to run'
    )
    
    parser.add_argument(
        'url',
        nargs='?',
        help='URL to scan (required for scan command)'
    )
    
    args = parser.parse_args()
    
    # Check if we're in the right directory
    if not Path("phishing_scanner.py").exists():
        print("❌ Error: Please run this script from the PhishingScanner directory")
        sys.exit(1)
    
    if args.command == 'setup':
        run_setup()
    elif args.command == 'web':
        run_web_app()
    elif args.command == 'cli':
        run_cli()
    elif args.command == 'demo':
        run_demo()
    elif args.command == 'scan':
        if not args.url:
            print("❌ Error: URL is required for scan command")
            print("Usage: python run.py scan <URL>")
            sys.exit(1)
        scan_url(args.url)


if __name__ == "__main__":
    main()
