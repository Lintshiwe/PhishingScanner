#!/bin/bash
# PhishingScanner Linux Setup and Test Script
# Built by Slade for the cybersecurity community

echo "🛡️ PhishingScanner Linux Setup & Test"
echo "======================================"

# Check Python version
echo "🐍 Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Installing..."
    sudo apt update
    sudo apt install -y python3 python3-pip
else
    echo "✅ Python 3 found: $(python3 --version)"
fi

# Check pip
if ! command -v pip3 &> /dev/null; then
    echo "📦 Installing pip..."
    sudo apt install -y python3-pip
fi

# Install dependencies
echo "📦 Installing dependencies..."
pip3 install -r requirements.txt

# Make scripts executable
chmod +x cli.py
chmod +x test_compatibility.py

# Run compatibility test
echo "🔍 Running compatibility test..."
python3 test_compatibility.py

# Test CLI scanner
echo "🛡️ Testing CLI scanner..."
python3 cli.py scan -u https://google.com

# Test web interface (in background)
echo "🌐 Starting web interface..."
echo "Visit http://localhost:5000 in your browser"
echo "Press Ctrl+C to stop the web server"
python3 app.py

echo "✅ Linux setup complete!"
echo "🚀 PhishingScanner is ready to use on Linux!"
