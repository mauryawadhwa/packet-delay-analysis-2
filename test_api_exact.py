import sys
import os

# Add the api directory to the path so we can import index.py
sys.path.insert(0, os.path.abspath('.'))

from api.index import analyze_pcap

with open('complex.pcap', 'rb') as f:
    results = analyze_pcap(f, 'complex.pcap')
    
print("Total Packets:", results.get('total_packets'))
print("Latency:", results.get('latency'))
print("Jitter:", results.get('jitter'))
