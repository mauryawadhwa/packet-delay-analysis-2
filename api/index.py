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

def extract_ip_data(buf, datalink):
    # Helper to attempt unnesting VLANs and validating IP
    def validate_and_unwrap(data):
        while getattr(data, '__class__', None) and 'VLAN' in data.__class__.__name__:
            data = data.data
        if isinstance(data, dpkt.ip.IP) or isinstance(data, dpkt.ip6.IP6):
            return data
        return None

    try:
        if datalink == 113: # DLT_LINUX_SLL
            sll = dpkt.sll.SLL(buf)
            return validate_and_unwrap(sll.data)
        elif datalink == 0: # DLT_NULL
            loop = dpkt.loopback.Loopback(buf)
            return validate_and_unwrap(loop.data)
        elif datalink is not None:
            # Assume Ethernet for standard DLT_EN10MB (1) or others
            eth = dpkt.ethernet.Ethernet(buf)
            return validate_and_unwrap(eth.data)
        else:
            # If datalink is unknown (pcapng), brute force guess
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = validate_and_unwrap(eth.data)
                if ip: return ip
            except Exception:
                pass
            
            try:
                sll = dpkt.sll.SLL(buf)
                ip = validate_and_unwrap(sll.data)
                if ip: return ip
            except Exception:
                pass
                
            try:
                loop = dpkt.loopback.Loopback(buf)
                ip = validate_and_unwrap(loop.data)
                if ip: return ip
            except Exception:
                pass
    except Exception:
        pass
    
    return None

def analyze_pcap(file_stream, filename):
    # Read fully into memory buffer for Serverless environment safety
    file_bytes = file_stream.read()
    mem_stream = io.BytesIO(file_bytes)
    
    datalink = None
    try:
        pcap = dpkt.pcap.Reader(mem_stream)
        datalink = pcap.datalink()
    except Exception:
        try:
            mem_stream.seek(0)
            pcap = dpkt.pcapng.Reader(mem_stream)
        except Exception as e:
            raise Exception(f"Failed to parse pcap file: {str(e)}")

    packets_data = []
    
    for ts, buf in pcap:
        try:
            ip = extract_ip_data(buf, datalink)
            if not ip:
                continue
                
            src_ip = inet_to_str(ip.src)
            dst_ip = inet_to_str(ip.dst)
            
            # Identify protocol and extract ports
            proto = "Unknown"
            sport = 0
            dport = 0
            
            if hasattr(ip, 'p'):
                proto_num = ip.p
            else:
                proto_num = getattr(ip, 'nxt', 0)
                
            if proto_num == dpkt.ip.IP_PROTO_TCP:
                proto = "TCP"
                if hasattr(ip, 'data') and hasattr(ip.data, 'sport'):
                    sport = ip.data.sport
                    dport = ip.data.dport
            elif proto_num == dpkt.ip.IP_PROTO_UDP:
                proto = "UDP"
                if hasattr(ip, 'data') and hasattr(ip.data, 'sport'):
                    sport = ip.data.sport
                    dport = ip.data.dport
            elif proto_num == dpkt.ip.IP_PROTO_ICMP:
                proto = "ICMP"
            else:
                proto = f"Unknown({proto_num})"
            
            end1 = f"{src_ip}:{sport}"
            end2 = f"{dst_ip}:{dport}"
            packets_data.append({
                'timestamp': float(ts),
                'protocol': proto,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'length': len(buf),
                'flow_key': f"{min(end1, end2)}-{max(end1, end2)}-{proto}"
            })
        except Exception:
            pass 

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
    df['delay'] = df.groupby('flow_key')['timestamp'].diff() * 1000 # To ms
    
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
    
    # Dynamic Categories Heuristic
    mean_delay = df['delay'].mean()
    min_delay = df['delay'].min()
    mean_jitter = df['jitter'].mean()
    
    if pd.isna(mean_delay):
        mean_delay = min_delay = mean_jitter = 0
        
    prop_val = min_delay if pd.notnull(min_delay) else 0
    queue_val = mean_jitter if pd.notnull(mean_jitter) else 0
    congestion_val = max(0, max(0, mean_delay - prop_val) - queue_val)
    routing_val = prop_val * 0.2
    
    q95 = df['delay'].quantile(0.95) if not df['delay'].empty else 0
    retrans_val = max(0, q95 - mean_delay) if pd.notnull(q95) else 0
    
    total_factors = congestion_val + queue_val + routing_val + retrans_val
    if total_factors == 0:
        total_factors = 1
        
    cong_pct = int((congestion_val / total_factors) * 100)
    queue_pct = int((queue_val / total_factors) * 100)
    rout_pct = int((routing_val / total_factors) * 100)
    retrans_pct = 100 - (cong_pct + queue_pct + rout_pct)
    
    def get_level(pct):
        if pct < 20: return 'low'
        if pct < 50: return 'medium'
        if pct < 80: return 'high'
        return 'critical'
        
    metrics.update({
        'congestionLevel': get_level(cong_pct), 'congestionPercentage': cong_pct,
        'queuingLevel': get_level(queue_pct), 'queuingPercentage': queue_pct,
        'routingLevel': get_level(rout_pct), 'routingPercentage': rout_pct,
        'retransmissionLevel': get_level(retrans_pct), 'retransmissionPercentage': retrans_pct,
    })

    # Sort back by timestamp for timeline
    df.sort_values(by='timestamp', inplace=True)
    
    # Replace NaNs with None for JSON serialization safely
    df = df.astype(object).where(pd.notnull(df), None)
    
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
            analysis_results = analyze_pcap(file, file.filename)
            if 'error' in analysis_results:
                return jsonify(analysis_results), 400
            return jsonify(analysis_results)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    return jsonify({'error': 'Invalid file type. Only .pcap and .pcapng are allowed.'}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
