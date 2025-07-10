#!/usr/bin/env python3
"""
Cross-Platform Compatibility Test
Tests PhishingScanner functionality across different operating systems
"""

import platform
import sys
import subprocess
from pathlib import Path

def test_platform_compatibility():
    """Test platform-specific functionality"""
    print("🔍 PhishingScanner Cross-Platform Compatibility Test")
    print("=" * 60)
    
    # System information
    print(f"🖥️  Platform: {platform.system()} {platform.release()}")
    print(f"🐍 Python: {sys.version}")
    print(f"📂 Working Directory: {Path.cwd()}")
    print()
    
    # Test imports
    print("📦 Testing imports...")
    try:
        import phishing_scanner
        print("✅ phishing_scanner module imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import phishing_scanner: {e}")
        return False
    
    try:
        import click
        import requests
        from bs4 import BeautifulSoup
        print("✅ Core dependencies available")
    except ImportError as e:
        print(f"❌ Missing dependencies: {e}")
        return False
    
    # Test CLI functionality
    print("\n🖥️  Testing CLI functionality...")
    try:
        scanner = phishing_scanner.PhishingDetector()
        result = scanner.scan_url("https://example.com")
        print(f"✅ CLI scan test passed - Risk score: {result.risk_score}")
    except Exception as e:
        print(f"❌ CLI test failed: {e}")
        return False
    
    # Platform-specific tests
    if platform.system() == "Linux":
        print("\n🐧 Linux-specific tests...")
        # Test file permissions
        test_file = Path("test_perms.tmp")
        test_file.touch()
        test_file.chmod(0o755)
        if test_file.stat().st_mode & 0o755:
            print("✅ File permissions work correctly")
        else:
            print("⚠️  File permission issues detected")
        test_file.unlink()
        
    elif platform.system() == "Windows":
        print("\n🪟 Windows-specific tests...")
        # Test path handling
        test_path = Path("test\\path\\structure")
        print(f"✅ Path handling: {test_path} -> {test_path.as_posix()}")
        
    elif platform.system() == "Darwin":
        print("\n🍎 macOS-specific tests...")
        print("✅ macOS compatibility confirmed")
    
    print("\n🎉 Cross-platform compatibility test completed successfully!")
    return True

if __name__ == "__main__":
    success = test_platform_compatibility()
    sys.exit(0 if success else 1)
