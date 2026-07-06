import sys
sys.path.insert(0, 'api')
import index
import io
from werkzeug.datastructures import FileStorage
import pandas as pd

with open('complex.pcap', 'rb') as f:
    data = f.read()

fs = FileStorage(stream=io.BytesIO(data), filename='complex.pcap')
res = index.analyze_pcap(fs, 'complex.pcap')

df = pd.DataFrame(res['packets'])
for flow, group in df.groupby('flow_key'):
    if len(group) > 2:
        print(f'\nFlow: {flow}')
        print(f'  Packets: {len(group)}')
        print(f'  Delay Mean: {group["delay"].mean():.4f}')
        print(f'  Jitter Mean: {group["jitter"].mean():.4f}')
