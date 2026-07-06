import urllib.request
import urllib.parse
boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
body = b'--' + boundary.encode() + b'\r\nContent-Disposition: form-data; name="file"; filename="http.pcap"\r\nContent-Type: application/vnd.tcpdump.pcap\r\n\r\n'
body += open('http.pcap', 'rb').read()
body += b'\r\n--' + boundary.encode() + b'--\r\n'
req = urllib.request.Request('http://localhost:5000/api/upload', data=body)
req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
try:
    with urllib.request.urlopen(req) as r: print(r.read().decode())
except Exception as e:
    print(e)
    print(e.read().decode() if hasattr(e, 'read') else '')
