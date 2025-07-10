#!/usr/bin/env python3
"""
PhishingScanner Web Application
Flask-based web interface for the phishing scanner
"""

from flask import Flask, render_template, request, jsonify, send_file
import json
import io
import csv
from datetime import datetime
from typing import List
import threading
import time

from phishing_scanner import PhishingDetector, ScanResult

app = Flask(__name__)
app.config['SECRET_KEY'] = 'phishing-scanner-secret-key-change-in-production'

# Global detector instance
detector = PhishingDetector()

# Store scan history (in production, use a proper database)
scan_history = []
scan_lock = threading.Lock()


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for scanning URLs"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Perform scan
        result = detector.scan_url(url)
        
        # Store in history
        with scan_lock:
            scan_history.append(result)
            # Keep only last 100 scans
            if len(scan_history) > 100:
                scan_history.pop(0)
        
        # Convert result to dict for JSON response
        result_dict = {
            'url': result.url,
            'timestamp': result.timestamp.isoformat(),
            'risk_score': result.risk_score,
            'is_phishing': result.is_phishing,
            'indicators': result.indicators,
            'response_time': round(result.response_time, 2),
            'details': result.details
        }
        
        return jsonify(result_dict)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/batch-scan', methods=['POST'])
def api_batch_scan():
    """API endpoint for batch scanning multiple URLs"""
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls:
            return jsonify({'error': 'URLs list is required'}), 400
        
        if len(urls) > 50:  # Limit batch size
            return jsonify({'error': 'Maximum 50 URLs allowed per batch'}), 400
        
        results = []
        for url in urls:
            if url.strip():
                try:
                    result = detector.scan_url(url.strip())
                    result_dict = {
                        'url': result.url,
                        'timestamp': result.timestamp.isoformat(),
                        'risk_score': result.risk_score,
                        'is_phishing': result.is_phishing,
                        'indicators': result.indicators,
                        'response_time': round(result.response_time, 2)
                    }
                    results.append(result_dict)
                    
                    # Store in history
                    with scan_lock:
                        scan_history.append(result)
                        
                except Exception as e:
                    results.append({
                        'url': url.strip(),
                        'error': str(e),
                        'risk_score': 100,
                        'is_phishing': True
                    })
        
        # Clean up history
        with scan_lock:
            if len(scan_history) > 100:
                scan_history[:] = scan_history[-100:]
        
        return jsonify({'results': results})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/history')
def api_history():
    """Get scan history"""
    with scan_lock:
        history_data = []
        for result in scan_history[-20:]:  # Last 20 scans
            history_data.append({
                'url': result.url,
                'timestamp': result.timestamp.isoformat(),
                'risk_score': result.risk_score,
                'is_phishing': result.is_phishing,
                'response_time': round(result.response_time, 2)
            })
    
    return jsonify(history_data)


@app.route('/api/stats')
def api_stats():
    """Get scanning statistics"""
    with scan_lock:
        if not scan_history:
            return jsonify({
                'total_scans': 0,
                'phishing_detected': 0,
                'average_risk_score': 0,
                'average_response_time': 0
            })
        
        total = len(scan_history)
        phishing_count = sum(1 for r in scan_history if r.is_phishing)
        avg_risk = sum(r.risk_score for r in scan_history) / total
        avg_response_time = sum(r.response_time for r in scan_history) / total
        
        stats = {
            'total_scans': total,
            'phishing_detected': phishing_count,
            'safe_sites': total - phishing_count,
            'average_risk_score': round(avg_risk, 1),
            'average_response_time': round(avg_response_time, 2)
        }
    
    return jsonify(stats)


@app.route('/export/<format>')
def export_history(format):
    """Export scan history in different formats"""
    with scan_lock:
        history_copy = scan_history.copy()
    
    if format == 'json':
        # Create JSON export
        export_data = []
        for result in history_copy:
            export_data.append({
                'url': result.url,
                'timestamp': result.timestamp.isoformat(),
                'risk_score': result.risk_score,
                'is_phishing': result.is_phishing,
                'indicators': result.indicators,
                'response_time': result.response_time,
                'details': result.details
            })
        
        output = io.StringIO()
        json.dump(export_data, output, indent=2)
        output.seek(0)
        
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype='application/json',
            as_attachment=True,
            download_name=f'phishing_scan_history_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        )
    
    elif format == 'csv':
        # Create CSV export
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['URL', 'Timestamp', 'Risk Score', 'Is Phishing', 'Indicators', 'Response Time'])
        
        for result in history_copy:
            writer.writerow([
                result.url,
                result.timestamp.isoformat(),
                result.risk_score,
                result.is_phishing,
                '; '.join(result.indicators),
                f"{result.response_time:.2f}"
            ])
        
        output.seek(0)
        
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'phishing_scan_history_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
    
    else:
        return jsonify({'error': 'Invalid format. Use json or csv'}), 400


@app.route('/dashboard')
def dashboard():
    """Analytics dashboard page"""
    return render_template('dashboard.html')


@app.route('/api')
def api_docs():
    """API documentation page"""
    return render_template('api_docs.html')


@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500


if __name__ == '__main__':
    print("🛡️ PhishingScanner Web Interface Starting...")
    print("📊 Dashboard: http://localhost:5000")
    print("📈 Analytics: http://localhost:5000/dashboard")
    print("🔧 API Docs: http://localhost:5000/api")
    print("\n🚀 Server running on http://localhost:5000")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
