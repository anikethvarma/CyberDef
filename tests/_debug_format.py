import re

raw1 = '<150>Mar 24 12:11:10 INMUPA0009LSG02 httpd[173876]: 10.61.63.169 - - search.ultimatix.net - - [24/Mar/2026:12:11:10 +0530] "GET /search HTTP/1.1" 302 - 0 "-" "-"'
raw2 = '<150>Mar 24 12:11:05 INMUPA0009LSG01 httpd[162527]: 10.61.63.174 - - search.ultimatix.net - - [24/Mar/2026:12:11:05 +0530] "GET /search HTTP/1.1" 302 - 0 "-" "-"'

print("=== Token analysis ===")
for raw in [raw1, raw2]:
    after_pid = re.search(r'httpd\[\d+\]:\s+(.*)', raw)
    tokens = after_pid.group(1).split() if after_pid else []
    print("Tokens after PID:", tokens[:8])

    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', raw)
    print("IPs found in order:", ips)
    print()
