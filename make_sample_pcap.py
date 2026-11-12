"""Creates sample.pcap with a port scan, SSH brute force, DNS anomaly and normal HTTP."""
import random, string
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
random.seed(1); pk = []; t = 1_700_000_000.0
def add(p):
    global t
    t += 0.05; p.time = t; pk.append(p)
for port in range(1, 101):                       # port scan
    add(Ether()/IP(src="10.0.0.66", dst="10.0.0.5")/TCP(sport=4444, dport=port, flags="S"))
for i in range(40):                              # SSH brute force
    add(Ether()/IP(src="10.0.0.77", dst="10.0.0.5")/TCP(sport=5000+i, dport=22, flags="S"))
for i in range(15):                              # DNS anomaly
    n = "".join(random.choices(string.ascii_lowercase+string.digits, k=30))
    add(Ether()/IP(src="10.0.0.12", dst="8.8.8.8")/UDP(sport=5353+i, dport=53)/DNS(rd=1, qd=DNSQR(qname=f"{n}.evil-c2.xyz")))
for i in range(5):                               # normal traffic
    add(Ether()/IP(src="10.0.0.20", dst="93.184.216.34")/TCP(sport=6000+i, dport=80, flags="PA")/
        Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))
    add(Ether()/IP(src="10.0.0.20", dst="8.8.8.8")/UDP(sport=7000+i, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com")))
wrpcap("sample.pcap", pk); print("sample.pcap written")
