#!/usr/bin/env python3
"""
PhishingScanner Test Suite
Basic tests to verify functionality
"""

import unittest
import sys
import time
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from phishing_scanner import PhishingDetector
from api_client import PhishingScannerClient


class TestPhishingDetector(unittest.TestCase):
    """Test the core phishing detection engine"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.detector = PhishingDetector()
        self.safe_urls = [
            "https://github.com",
            "https://google.com",
            "https://microsoft.com"
        ]
        
    def test_detector_initialization(self):
        """Test that detector initializes properly"""
        self.assertIsNotNone(self.detector)
        self.assertIsNotNone(self.detector.config)
        self.assertIsNotNone(self.detector.session)
    
    def test_url_structure_analysis(self):
        """Test URL structure analysis"""
        from urllib.parse import urlparse
        
        # Test safe URL
        parsed_url = urlparse("https://github.com")
        risk_score, indicators = self.detector._analyze_url_structure(parsed_url)
        self.assertIsInstance(risk_score, int)
        self.assertIsInstance(indicators, list)
        
        # Test suspicious patterns
        parsed_url = urlparse("http://192.168.1.1/login")
        risk_score, indicators = self.detector._analyze_url_structure(parsed_url)
        self.assertGreater(risk_score, 0)  # Should have some risk
        
    def test_scan_valid_url(self):
        """Test scanning a valid URL"""
        url = "https://github.com"
        result = self.detector.scan_url(url)
        
        self.assertEqual(result.url, url)
        self.assertIsInstance(result.risk_score, int)
        self.assertIsInstance(result.is_phishing, bool)
        self.assertIsInstance(result.indicators, list)
        self.assertIsInstance(result.response_time, float)
        self.assertGreater(result.response_time, 0)
    
    def test_scan_invalid_url(self):
        """Test scanning an invalid URL"""
        result = self.detector.scan_url("not-a-valid-url")
        self.assertEqual(result.risk_score, 100)
        self.assertTrue(result.is_phishing)
        self.assertIn("Invalid URL format", result.indicators)
    
    def test_batch_scanning(self):
        """Test scanning multiple URLs"""
        results = []
        for url in self.safe_urls:
            result = self.detector.scan_url(url)
            results.append(result)
        
        self.assertEqual(len(results), len(self.safe_urls))
        for result in results:
            self.assertIsInstance(result.risk_score, int)
            self.assertLessEqual(result.risk_score, 100)
            self.assertGreaterEqual(result.risk_score, 0)


class TestAPIClient(unittest.TestCase):
    """Test the API client (requires running server)"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.client = PhishingScannerClient()
        self.test_url = "https://github.com"
    
    def test_client_initialization(self):
        """Test that client initializes properly"""
        self.assertIsNotNone(self.client)
        self.assertEqual(self.client.base_url, "http://localhost:5000")
    
    def test_server_connection(self):
        """Test if we can connect to the server"""
        # This test will be skipped if server is not running
        try:
            is_online = self.client.is_server_online()
            if not is_online:
                self.skipTest("Server is not running")
        except:
            self.skipTest("Cannot connect to server")
    
    def test_api_scan(self):
        """Test API scanning (requires running server)"""
        try:
            if not self.client.is_server_online():
                self.skipTest("Server is not running")
            
            result = self.client.scan_url(self.test_url)
            self.assertIn('url', result)
            self.assertIn('risk_score', result)
            self.assertIn('is_phishing', result)
            
        except Exception as e:
            self.skipTest(f"API test failed: {e}")


class TestConfiguration(unittest.TestCase):
    """Test configuration loading and validation"""
    
    def test_config_file_exists(self):
        """Test that config file exists"""
        config_path = Path("config.json")
        self.assertTrue(config_path.exists(), "config.json not found")
    
    def test_config_loading(self):
        """Test that configuration loads properly"""
        detector = PhishingDetector()
        config = detector.config
        
        self.assertIsInstance(config, dict)
        # Test for required sections
        required_sections = ['thresholds', 'timeouts']
        for section in required_sections:
            self.assertIn(section, config, f"Missing config section: {section}")


def run_performance_test():
    """Run a basic performance test"""
    print("\n🚀 Running Performance Test...")
    
    detector = PhishingDetector()
    test_urls = [
        "https://github.com",
        "https://google.com",
        "https://microsoft.com"
    ]
    
    start_time = time.time()
    
    for url in test_urls:
        result = detector.scan_url(url)
        print(f"  {url}: {result.risk_score}/100 ({result.response_time:.2f}s)")
    
    total_time = time.time() - start_time
    avg_time = total_time / len(test_urls)
    
    print(f"\n📊 Performance Results:")
    print(f"  Total time: {total_time:.2f}s")
    print(f"  Average per URL: {avg_time:.2f}s")
    print(f"  URLs per minute: {60/avg_time:.1f}")
    
    return avg_time < 5.0  # Pass if average time is under 5 seconds


def main():
    """Run all tests"""
    print("🛡️ PhishingScanner Test Suite")
    print("="*50)
    
    # Run unit tests
    print("\n🧪 Running Unit Tests...")
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestPhishingDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestConfiguration))
    suite.addTests(loader.loadTestsFromTestCase(TestAPIClient))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Run performance test
    perf_passed = run_performance_test()
    
    # Summary
    print("\n📋 Test Summary:")
    print(f"  Unit tests: {'✅ PASSED' if result.wasSuccessful() else '❌ FAILED'}")
    print(f"  Performance: {'✅ PASSED' if perf_passed else '❌ FAILED'}")
    
    if result.wasSuccessful() and perf_passed:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print("\n❌ Some tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
