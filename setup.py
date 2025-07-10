#!/usr/bin/env python3
"""
PhishingScanner Setup Script
Handles initial setup and configuration
"""

import os
import sys
import json
import sqlite3
from pathlib import Path
import subprocess


class PhishingScannerSetup:
    """Setup and configuration manager"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.config_file = self.project_root / "config.json"
        self.db_file = self.project_root / "phishing_scanner.db"
    
    def check_python_version(self):
        """Check if Python version is compatible"""
        if sys.version_info < (3, 8):
            print("❌ Error: Python 3.8 or higher is required")
            print(f"Current version: {sys.version}")
            sys.exit(1)
        print(f"✅ Python version check passed: {sys.version}")
    
    def install_dependencies(self):
        """Install required Python packages"""
        print("📦 Installing dependencies...")
        
        requirements_file = self.project_root / "requirements.txt"
        if not requirements_file.exists():
            print("❌ requirements.txt not found")
            return False
        
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
            ])
            print("✅ Dependencies installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            return False
    
    def create_database(self):
        """Create SQLite database for storing scan history"""
        print("🗄️ Setting up database...")
        
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Create scan_history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    risk_score INTEGER NOT NULL,
                    is_phishing BOOLEAN NOT NULL,
                    indicators TEXT,
                    response_time REAL,
                    details TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create configuration table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS configuration (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create index for better performance
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp 
                ON scan_history(timestamp)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_scan_history_url 
                ON scan_history(url)
            ''')
            
            conn.commit()
            conn.close()
            
            print(f"✅ Database created: {self.db_file}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to create database: {e}")
            return False
    
    def create_directories(self):
        """Create necessary directories"""
        print("📁 Creating directories...")
        
        directories = [
            "logs",
            "exports",
            "static",
            "temp"
        ]
        
        for directory in directories:
            dir_path = self.project_root / directory
            dir_path.mkdir(exist_ok=True)
            print(f"✅ Created directory: {directory}")
    
    def validate_config(self):
        """Validate configuration file"""
        print("⚙️ Validating configuration...")
        
        if not self.config_file.exists():
            print("❌ config.json not found")
            return False
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            
            required_sections = [
                'scanner', 'thresholds', 'timeouts', 'features'
            ]
            
            for section in required_sections:
                if section not in config:
                    print(f"❌ Missing configuration section: {section}")
                    return False
            
            print("✅ Configuration validated")
            return True
            
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in config.json: {e}")
            return False
        except Exception as e:
            print(f"❌ Error reading config.json: {e}")
            return False
    
    def test_imports(self):
        """Test if all required modules can be imported"""
        print("🔍 Testing imports...")
        
        required_modules = [
            'requests', 'beautifulsoup4', 'flask', 'validators',
            'dnspython', 'cryptography', 'PIL', 'whois'
        ]
        
        failed_imports = []
        
        for module in required_modules:
            try:
                if module == 'beautifulsoup4':
                    import bs4
                elif module == 'PIL':
                    from PIL import Image
                elif module == 'dnspython':
                    import dns.resolver
                else:
                    __import__(module)
                print(f"✅ {module}")
            except ImportError:
                print(f"❌ {module}")
                failed_imports.append(module)
        
        if failed_imports:
            print(f"\n❌ Failed to import: {', '.join(failed_imports)}")
            print("Run: pip install -r requirements.txt")
            return False
        
        print("✅ All imports successful")
        return True
    
    def create_sample_files(self):
        """Create sample files for testing"""
        print("📄 Creating sample files...")
        
        # Sample URLs file
        sample_urls = [
            "https://github.com",
            "https://google.com",
            "https://microsoft.com",
            "https://stackoverflow.com",
            "https://python.org"
        ]
        
        urls_file = self.project_root / "sample_urls.txt"
        with open(urls_file, 'w') as f:
            f.write('\n'.join(sample_urls))
        
        print(f"✅ Created sample URLs file: {urls_file}")
        
        # .env file for environment variables
        env_file = self.project_root / ".env"
        if not env_file.exists():
            with open(env_file, 'w') as f:
                f.write("""# PhishingScanner Environment Variables
FLASK_ENV=development
FLASK_DEBUG=True
SECRET_KEY=change-this-in-production

# API Keys (optional)
VIRUSTOTAL_API_KEY=
URLVOID_API_KEY=

# Database
DATABASE_URL=sqlite:///phishing_scanner.db

# Logging
LOG_LEVEL=INFO
""")
            print(f"✅ Created .env file: {env_file}")
    
    def print_usage_instructions(self):
        """Print usage instructions"""
        print("\n" + "="*60)
        print("🎉 SETUP COMPLETE!")
        print("="*60)
        print("\n📋 How to use PhishingScanner:")
        print("\n1. Command Line Interface:")
        print("   python cli.py --url https://example.com")
        print("   python cli.py --file sample_urls.txt")
        print("   python cli.py interactive")
        print("   python cli.py demo")
        
        print("\n2. Web Interface:")
        print("   python app.py")
        print("   Then open: http://localhost:5000")
        
        print("\n3. Direct Python API:")
        print("   from phishing_scanner import PhishingDetector")
        print("   detector = PhishingDetector()")
        print("   result = detector.scan_url('https://example.com')")
        
        print("\n📚 Documentation:")
        print("   Web API docs: http://localhost:5000/api")
        print("   Dashboard: http://localhost:5000/dashboard")
        
        print("\n🔧 Configuration:")
        print(f"   Edit: {self.config_file}")
        print(f"   Database: {self.db_file}")
        
        print("\n🎯 Sample Commands:")
        print("   python cli.py demo")
        print("   python app.py")
        
        print("\n🛡️ Stay Safe Online!")
        print("="*60)
    
    def run_setup(self):
        """Run the complete setup process"""
        print("🛡️ PhishingScanner Setup")
        print("="*40)
        
        steps = [
            ("Checking Python version", self.check_python_version),
            ("Installing dependencies", self.install_dependencies),
            ("Creating directories", self.create_directories),
            ("Validating configuration", self.validate_config),
            ("Creating database", self.create_database),
            ("Testing imports", self.test_imports),
            ("Creating sample files", self.create_sample_files)
        ]
        
        for step_name, step_func in steps:
            print(f"\n{step_name}...")
            if not step_func():
                print(f"\n❌ Setup failed at: {step_name}")
                sys.exit(1)
        
        self.print_usage_instructions()


if __name__ == "__main__":
    setup = PhishingScannerSetup()
    setup.run_setup()
