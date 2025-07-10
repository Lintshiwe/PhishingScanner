# PhishingScanner PowerShell Launcher
# Quick start script for Windows users

param(
    [Parameter(Position=0)]
    [ValidateSet("setup", "web", "cli", "demo", "scan", "help")]
    [string]$Command = "help",
    
    [Parameter(Position=1)]
    [string]$Url = ""
)

function Show-Banner {
    Write-Host @"
████████████████████████████████████████████████████████████████
█                                                              █
█  🛡️  PhishingScanner - Free Open Source Security Tool       █
█     Advanced Phishing Detection & Analysis                  █
█                                                              █
████████████████████████████████████████████████████████████████
"@ -ForegroundColor Cyan
}

function Show-Help {
    Write-Host "PhishingScanner Quick Start" -ForegroundColor Green
    Write-Host "Usage: .\start.ps1 <command> [url]" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Commands:" -ForegroundColor White
    Write-Host "  setup    - Run initial setup and install dependencies" -ForegroundColor Gray
    Write-Host "  web      - Start web interface (recommended)" -ForegroundColor Gray  
    Write-Host "  cli      - Start interactive command line interface" -ForegroundColor Gray
    Write-Host "  demo     - Run demo with sample URLs" -ForegroundColor Gray
    Write-Host "  scan     - Scan a specific URL" -ForegroundColor Gray
    Write-Host "  help     - Show this help message" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor White
    Write-Host "  .\start.ps1 setup" -ForegroundColor Green
    Write-Host "  .\start.ps1 web" -ForegroundColor Green
    Write-Host "  .\start.ps1 scan https://example.com" -ForegroundColor Green
    Write-Host ""
}

function Test-PythonInstallation {
    try {
        $pythonVersion = python --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Python found: $pythonVersion" -ForegroundColor Green
            return $true
        }
    }
    catch {
        Write-Host "❌ Python not found in PATH" -ForegroundColor Red
        Write-Host "Please install Python 3.8+ from https://python.org" -ForegroundColor Yellow
        return $false
    }
    return $false
}

function Test-ProjectFiles {
    $requiredFiles = @("phishing_scanner.py", "app.py", "cli.py", "requirements.txt")
    
    foreach ($file in $requiredFiles) {
        if (-not (Test-Path $file)) {
            Write-Host "❌ Missing required file: $file" -ForegroundColor Red
            return $false
        }
    }
    
    Write-Host "✅ All required files found" -ForegroundColor Green
    return $true
}

function Start-Setup {
    Write-Host "🔧 Running PhishingScanner setup..." -ForegroundColor Cyan
    python setup.py
}

function Start-WebInterface {
    Write-Host "🌐 Starting PhishingScanner web interface..." -ForegroundColor Cyan
    Write-Host "📊 Dashboard will be available at: http://localhost:5000" -ForegroundColor Yellow
    Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Gray
    Write-Host ""
    python app.py
}

function Start-CLI {
    Write-Host "💻 Starting PhishingScanner CLI..." -ForegroundColor Cyan
    python cli.py interactive
}

function Start-Demo {
    Write-Host "🚀 Running PhishingScanner demo..." -ForegroundColor Cyan
    python cli.py demo
}

function Start-Scan {
    param([string]$ScanUrl)
    
    if ([string]::IsNullOrWhiteSpace($ScanUrl)) {
        Write-Host "❌ Error: URL is required for scan command" -ForegroundColor Red
        Write-Host "Usage: .\start.ps1 scan <URL>" -ForegroundColor Yellow
        return
    }
    
    Write-Host "🔍 Scanning URL: $ScanUrl" -ForegroundColor Cyan
    python cli.py scan --url $ScanUrl --verbose
}

# Main script execution
Show-Banner

# Check if Python is installed
if (-not (Test-PythonInstallation)) {
    exit 1
}

# Check if we're in the right directory
if (-not (Test-ProjectFiles)) {
    Write-Host "❌ Please run this script from the PhishingScanner directory" -ForegroundColor Red
    exit 1
}

# Execute command
switch ($Command.ToLower()) {
    "setup" {
        Start-Setup
    }
    "web" {
        Start-WebInterface
    }
    "cli" {
        Start-CLI
    }
    "demo" {
        Start-Demo
    }
    "scan" {
        Start-Scan -ScanUrl $Url
    }
    "help" {
        Show-Help
    }
    default {
        Show-Help
    }
}

Write-Host ""
Write-Host "🛡️ Stay Safe Online!" -ForegroundColor Green
