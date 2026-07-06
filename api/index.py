import os
import io
import dpkt
import socket
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
import pandas as pd
import numpy as np

app = Flask(__name__)
CORS(app)

ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def analyze_pcap(file_stream, filename):
    try:
        if filename.endswith('.pcapng'):
            pcap = dpkt.pcapng.Reader(file_stream)
        else:
            pcap = dpkt.pcap.Reader(file_stream)
    except Exception as e:
        raise Exception(f"Failed to parse pcap file: {str(e)}")

    packets_data = []
    
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            # Make sure it's IP
            if not isinstance(eth.data, dpkt.ip.IP) and not isinstance(eth.data, dpkt.ip6.IP6):
                continue
            
            ip = eth.data
            src_ip = inet_to_str(ip.src)
            dst_ip = inet_to_str(ip.dst)
            
            # Identify protocol
            proto = "Unknown"
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                proto = "TCP"
            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                proto = "UDP"
            elif ip.p == dpkt.ip.IP_PROTO_ICMP:
                proto = "ICMP"
            
            packets_data.append({
                'timestamp': float(ts),
                'protocol': proto,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'length': len(buf),
                'flow_key': f"{src_ip}-{dst_ip}-{proto}" # simplified flow key
            })
        except Exception:
            pass # Ignore malformed packets

    if not packets_data:
        return {'error': 'No IP packets found in the capture file'}

    df = pd.DataFrame(packets_data)
    
    metrics = {
        'total_packets': len(df),
        'protocols': df['protocol'].value_counts().to_dict(),
        'unique_ips': {
            'sources': df['src_ip'].nunique(),
            'destinations': df['dst_ip'].nunique()
        }
    }
    
    # Calculate delays per flow
    df.sort_values(by=['flow_key', 'timestamp'], inplace=True)
    df['delay'] = df.groupby('flow_key')['timestamp'].diff()
    
    # Jitter is absolute difference of delays within the same flow
    df['jitter'] = df.groupby('flow_key')['delay'].diff().abs()

    def safe_mean(series):
        val = series.mean()
        return None if pd.isna(val) else val
        
    def safe_median(series):
        val = series.median()
        return None if pd.isna(val) else val

    def safe_std(series):
        val = series.std()
        return None if pd.isna(val) else val

    metrics['latency'] = {
        'mean': safe_mean(df['delay']),
        'median': safe_median(df['delay']),
        'std': safe_std(df['delay'])
    }
    
    metrics['jitter'] = {
        'mean': safe_mean(df['jitter']),
        'median': safe_median(df['jitter']),
        'std': safe_std(df['jitter'])
    }

    # Sort back by timestamp for timeline
    df.sort_values(by='timestamp', inplace=True)
    
    # Replace NaNs with None for JSON serialization
    df = df.replace({np.nan: None})
    
    # Take up to 1000 packets for the timeline to prevent browser crash
    metrics['packets'] = df.head(1000).to_dict('records')
    
    return metrics

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        try:
            # Pass the file stream directly to avoid saving to disk
            analysis_results = analyze_pcap(file, file.filename)
            if 'error' in analysis_results:
                return jsonify(analysis_results), 400
            return jsonify(analysis_results)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    return jsonify({'error': 'Invalid file type. Only .pcap and .pcapng are allowed.'}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
