#!/usr/bin/env python3
import os
import glob
import datetime
import webbrowser
import time
import shutil
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Directory paths
base_dir = os.path.expanduser('~/zeek-analysis')
vis_dir = os.path.join(base_dir, 'visualizations')
report_dir = os.path.join(base_dir, 'reports')
anomaly_dir = os.path.join(base_dir, 'detected_anomalies')
dashboard_dir = os.path.join(base_dir, 'dashboard')

# Create directories if they don't exist
for directory in [vis_dir, report_dir, anomaly_dir, dashboard_dir]:
    os.makedirs(directory, exist_ok=True)

# Custom HTTP handler that handles favicon requests and adds cache-busting headers
class DashboardHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # Ignore favicon requests
        if self.path == '/favicon.ico':
            self.send_response(204)  # No Content
            self.end_headers()
            return
            
        # Add cache-busting headers to all responses
        self.protocol_version = 'HTTP/1.1'
        super().do_GET()
        
    def send_response_only(self, code, message=None):
        super().send_response_only(code, message)
        if code == 200:
            # Add cache-control headers to prevent caching
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')

# Function to force update dashboard visualizations with fresh copies
def update_dashboard_visualizations():
    """Force fresh copies of visualizations with new timestamps"""
    src_dir = os.path.expanduser('~/zeek-analysis/visualizations')
    dst_dir = os.path.join(dashboard_dir, 'vis')
    os.makedirs(dst_dir, exist_ok=True)
    
    # Copy with new timestamps to force browser refresh
    vis_count = 0
    for vis_file in glob.glob(os.path.join(src_dir, '*.png')):
        dst_file = os.path.join(dst_dir, os.path.basename(vis_file))
        
        # Force copy even if destination exists
        try:
            shutil.copy2(vis_file, dst_file)
            
            # Touch the file to update its timestamp
            os.utime(dst_file, None)
            vis_count += 1
        except Exception as e:
            print(f"Error copying {vis_file}: {e}")
    
    print(f"Updated {vis_count} visualizations with fresh copies")
    return vis_count

# Function to create dashboard HTML
def generate_dashboard():
    print("Generating dashboard...")
    
    # Update visualizations with fresh copies
    update_dashboard_visualizations()
    
    # Create a simple favicon to avoid 404 errors
    favicon_path = os.path.join(dashboard_dir, 'favicon.ico')
    if not os.path.exists(favicon_path):
        try:
            # Create an empty file if PIL not available
            with open(favicon_path, 'wb') as f:
                f.write(b'')
        except Exception as e:
            print(f"Error creating favicon: {e}")
    
    # Copy visualizations to dashboard directory
    dashboard_vis_dir = os.path.join(dashboard_dir, 'vis')
    os.makedirs(dashboard_vis_dir, exist_ok=True)
    
    # Get reports
    reports = glob.glob(os.path.join(report_dir, '*.html'))
    reports.sort(reverse=True)
    
    # Create dashboard HTML
    timestamp = int(time.time())  # Current timestamp for cache busting
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zeek Network Analysis Dashboard</title>
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <link rel="icon" href="favicon.ico">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            width: 90%;
            margin: 20px auto;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
            border-radius: 5px 5px 0 0;
        }
        .section {
            background-color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1, h2 {
            margin-top: 0;
        }
        .visualization {
            margin-bottom: 30px;
            text-align: center;
        }
        .visualization img {
            max-width: 100%;
            height: auto;
            border: 1px solid #ddd;
            border-radius: 5px;
            cursor: pointer;
            transition: transform 0.3s ease;
        }
        .visualization img:hover {
            transform: scale(1.02);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .explanation {
            background-color: #e7f3fe;
            border-left: 6px solid #2196F3;
            padding: 10px 15px;
            margin: 15px 0;
            font-size: 14px;
            line-height: 1.5;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .button {
            display: inline-block;
            padding: 10px 15px;
            background-color: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background-color 0.3s;
            border: none;
            cursor: pointer;
            font-size: 14px;
            margin: 5px;
        }
        .fullscreen-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.9);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        .fullscreen-overlay img {
            max-width: 90%;
            max-height: 90%;
            object-fit: contain;
        }
        .close-btn {
            position: absolute;
            top: 20px;
            right: 30px;
            font-size: 30px;
            color: white;
            cursor: pointer;
        }
        .refresh-bar {
            display: flex;
            justify-content: flex-end;
            align-items: center;
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        .alert-box {
            background-color: #ffecb3;
            border-left: 6px solid #ffc107;
            padding: 10px 15px;
            margin-bottom: 15px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Zeek Network Analysis Dashboard</h1>
            <p>Last updated: """ + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
        </div>
        
        <div class="refresh-bar">
            <button onclick="forceRefresh()" class="button">Refresh Dashboard</button>
        </div>
        
        <div class="section">
            <div class="alert-box">
                <h3>Dashboard Information</h3>
                <p>This dashboard provides a simple view of Zeek monitoring data. To see the latest data, press the Refresh button above.</p>
                <p>Commands to use in the terminal:</p>
                <ul>
                    <li><code>cd ~/zeek-analysis && python enhanced_monitor_final.py</code> - Start monitoring</li>
                    <li><code>cd ~/zeek-analysis && python visualize_anomalies.py</code> - Update visualizations</li>
                    <li><code>cd ~/zeek-analysis && python simple_dashboard.py</code> - Start this dashboard</li>
                </ul>
            </div>
        </div>
"""
    
    # Add visualizations section
    vis_files = glob.glob(os.path.join(dashboard_vis_dir, '*.png'))
    if vis_files:
        html += """
        <div class="section">
            <h2>Network Analysis Visualizations</h2>
"""

        # Check for specific visualization files
        time_series = next((f for f in vis_files if 'time' in f.lower()), None)
        protocol_dist = next((f for f in vis_files if 'protocol' in f.lower()), None)
        anomaly_scores = next((f for f in vis_files if 'score' in f.lower()), None)
        tsne_vis = next((f for f in vis_files if 'tsne' in f.lower()), None)
        
        # Add time series visualization
        if time_series:
            vis_name = os.path.basename(time_series)
            vis_path = f'vis/{vis_name}?t={timestamp}'  # Add timestamp parameter
            html += f"""
            <div class="visualization">
                <h3>Network Anomalies Over Time</h3>
                <img src="{vis_path}" alt="Anomalies Over Time" onclick="showFullSize('{vis_path}')">
                <div class="explanation">
                    <p><strong>What this shows:</strong> This chart displays the number of detected anomalies over time. 
                    Spikes indicate time periods with high anomaly activity, which could suggest active attacks or unusual network behavior.</p>
                </div>
            </div>
"""
        
        # Add protocol distribution
        if protocol_dist:
            vis_name = os.path.basename(protocol_dist)
            vis_path = f'vis/{vis_name}?t={timestamp}'  # Add timestamp parameter
            html += f"""
            <div class="visualization">
                <h3>Protocol Distribution in Anomalies</h3>
                <img src="{vis_path}" alt="Protocol Distribution" onclick="showFullSize('{vis_path}')">
                <div class="explanation">
                    <p><strong>What this shows:</strong> This chart shows the distribution of network protocols in anomalous traffic.
                    High TCP counts often indicate port scans or connection floods. High UDP may suggest UDP flood attacks.</p>
                </div>
            </div>
"""
        
        # Add anomaly scores
        if anomaly_scores:
            vis_name = os.path.basename(anomaly_scores)
            vis_path = f'vis/{vis_name}?t={timestamp}'  # Add timestamp parameter
            html += f"""
            <div class="visualization">
                <h3>Anomaly Scores Distribution</h3>
                <img src="{vis_path}" alt="Anomaly Scores" onclick="showFullSize('{vis_path}')">
                <div class="explanation">
                    <p><strong>What this shows:</strong> This chart ranks anomalies by their anomaly score. Higher scores (closer to 1.0) 
                    indicate more unusual network activity that is likely malicious or highly abnormal.</p>
                </div>
            </div>
"""
        
        # Add t-SNE visualization
        if tsne_vis:
            vis_name = os.path.basename(tsne_vis)
            vis_path = f'vis/{vis_name}?t={timestamp}'  # Add timestamp parameter
            html += f"""
            <div class="visualization">
                <h3>t-SNE Projection of Network Anomalies</h3>
                <img src="{vis_path}" alt="t-SNE Projection" onclick="showFullSize('{vis_path}')">
                <div class="explanation">
                    <p><strong>What this shows:</strong> t-SNE is a technique that visualizes high-dimensional data in 2D space, 
                    clustering similar anomalies together. Different clusters often represent different attack types or patterns.</p>
                </div>
            </div>
"""
        html += "</div>"  # Close visualization section
    
    # Add reports section
    html += """
        <div class="section">
            <h2>Anomaly Reports</h2>
            <table>
                <tr>
                    <th>Report Name</th>
                    <th>Date Generated</th>
                    <th>Actions</th>
                </tr>
"""
    
    if reports:
        for report in reports:
            report_name = os.path.basename(report)
            report_date = report_name.replace('anomaly_report_', '').replace('.html', '')
            report_date = report_date.replace('-', ' ').replace('_', ':')
            
            # Create a copy in the dashboard directory for access
            dashboard_report = os.path.join(dashboard_dir, report_name)
            shutil.copy(report, dashboard_report)
            
            # Add timestamp for cache busting
            report_link = f"{report_name}?t={timestamp}"
            
            html += f"""
                <tr>
                    <td>{report_name}</td>
                    <td>{report_date}</td>
                    <td><a href="{report_link}" target="_blank" class="button">View Report</a></td>
                </tr>
"""
    else:
        html += """
                <tr>
                    <td colspan="3">No reports available yet. Run the enhanced monitor to generate reports.</td>
                </tr>
"""
    
    html += """
            </table>
        </div>
        
        <div class="section">
            <h2>Raw Anomaly Data</h2>
            <table>
                <tr>
                    <th>Filename</th>
                    <th>Records</th>
                    <th>Size</th>
                </tr>
"""
    
    # Add anomaly files
    anomaly_files = glob.glob(os.path.join(anomaly_dir, '*.csv'))
    anomaly_files.sort(reverse=True)
    
    if anomaly_files:
        for file in anomaly_files[:10]:  # Show just the 10 most recent
            file_name = os.path.basename(file)
            try:
                with open(file, 'r') as f:
                    record_count = sum(1 for _ in f) - 1  # Subtract header
            except:
                record_count = "Unknown"
            
            file_size = os.path.getsize(file) / 1024  # KB
            
            html += f"""
                <tr>
                    <td>{file_name}</td>
                    <td>{record_count}</td>
                    <td>{file_size:.1f} KB</td>
                </tr>
"""
    else:
        html += """
                <tr>
                    <td colspan="3">No anomaly data files found. Start monitoring to collect anomalies.</td>
                </tr>
"""
    
    html += """
            </table>
        </div>
    </div>
    
    <div id="fullscreen-overlay" class="fullscreen-overlay">
        <span class="close-btn" onclick="closeFullSize()">&times;</span>
        <img id="fullscreen-image" src="" alt="Fullscreen visualization">
    </div>
    
    <script>
        // Show fullsize image
        function showFullSize(src) {
            document.getElementById('fullscreen-image').src = src;
            document.getElementById('fullscreen-overlay').style.display = 'flex';
        }
        
        // Close fullsize image
        function closeFullSize() {
            document.getElementById('fullscreen-overlay').style.display = 'none';
        }
        
        // Close fullscreen when Escape key is pressed
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeFullSize();
            }
        });
        
        // Force refresh with cache-busting
        function forceRefresh() {
            window.location.href = window.location.href.split('?')[0] + '?t=' + Date.now();
        }
    </script>
</body>
</html>
"""
    
    # Write dashboard to file
    index_file = os.path.join(dashboard_dir, 'index.html')
    with open(index_file, 'w') as f:
        f.write(html)
    
    print(f"Dashboard generated at {index_file}")

# Function to start HTTP server
def start_server(port=8080):
    os.chdir(dashboard_dir)
    
    # Try to bind to the port, use alternative if busy
    server = None
    server_port = port
    
    while server_port < port + 10:  # Try up to 10 ports
        try:
            server = HTTPServer(('localhost', server_port), DashboardHandler)
            break
        except OSError:
            print(f"Port {server_port} is in use, trying next port...")
            server_port += 1
    
    if not server:
        print("Could not find an available port. Please close some applications and try again.")
        return
    
    print(f"\nStarting Zeek Anomaly Dashboard on http://localhost:{server_port}")
    print("Press Ctrl+C to stop the server")
    
    # Open browser
    webbrowser.open(f'http://localhost:{server_port}')
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.server_close()
        print("Server stopped")

def main():
    # Generate the dashboard HTML
    generate_dashboard()
    
    # Start the HTTP server
    start_server()

if __name__ == "__main__":
    main()