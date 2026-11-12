"""Packet extraction, protocol analysis, suspicious-traffic detection, IOC extraction."""
import math, re
from collections import Counter
import pandas as pd
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw

AUTH_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB", 3306: "MySQL", 5900: "VNC"}
HTTP_RE = re.compile(rb"^(GET|POST|PUT|HEAD|DELETE|OPTIONS) (\S+) HTTP/1\.[01]\r\n(?:.*\r\n)*?Host: ([^\r\n]+)", re.I)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def extract(packets) -> pd.DataFrame:
    """Module 2 + 3: source/dest IP, ports, protocol, timestamp + DNS/HTTP fields."""
    rows = []
    for p in packets:
        if IP not in p:
            continue
        r = dict(time=float(p.time), src=p[IP].src, dst=p[IP].dst, sport=None, dport=None,
                 proto="OTHER", flags="", dns_query="", http_url="", length=len(p))
        if TCP in p:
            r.update(proto="TCP", sport=p[TCP].sport, dport=p[TCP].dport, flags=str(p[TCP].flags))
            if Raw in p:
                m = HTTP_RE.match(bytes(p[Raw].load))
                if m:
                    r["proto"] = "HTTP"
                    r["http_url"] = f"http://{m.group(3).decode(errors='ignore').strip()}{m.group(2).decode(errors='ignore')}"
        elif UDP in p:
            r.update(proto="UDP", sport=p[UDP].sport, dport=p[UDP].dport)
        elif ICMP in p:
            r["proto"] = "ICMP"
        if DNS in p and DNSQR in p and p[DNS].qr == 0:
            r["proto"] = "DNS"
            r["dns_query"] = p[DNSQR].qname.decode(errors="ignore").rstrip(".").lower()
        rows.append(r)
    df = pd.DataFrame(rows)
    if not df.empty:
        df["datetime"] = pd.to_datetime(df["time"], unit="s")
    return df


COLS = ["type", "severity", "source", "target", "rule", "behavior", "reason", "count", "first_seen", "last_seen"]


def detect(df: pd.DataFrame, scan_ports=15, brute_attempts=20, dns_queries=50, rate_pps=100):
    """Module 3/4: rule-based detection. Every alert records the rule, the observed behavior and the reason."""
    F = []
    if df.empty:
        return pd.DataFrame(columns=COLS)
    tcp = df[df.proto.isin(["TCP", "HTTP"])]
    syn = tcp[tcp["flags"] == "S"]

    # Rule 1 - port scan: one IP -> many distinct ports on one target
    for (src, dst), g in syn.groupby(["src", "dst"]):
        n = g.dport.nunique()
        if n >= scan_ports:
            F.append(("Possible Port Scan", "High", src, dst,
                      f"R1: >= {scan_ports} distinct destination ports from one source to one target",
                      f"{n} distinct ports probed with SYN packets",
                      "Scanners probe many ports to find open services",
                      len(g), g.datetime.min(), g.datetime.max()))

    # Rule 2 - brute force: repeated connection attempts to one login service
    for (src, dst, port), g in syn[syn.dport.isin(AUTH_PORTS)].groupby(["src", "dst", "dport"]):
        if len(g) >= brute_attempts:
            F.append(("Possible Brute Force", "High", src, dst,
                      f"R2: >= {brute_attempts} connection attempts to one login port",
                      f"{len(g)} connection attempts to {AUTH_PORTS[int(port)]} (port {int(port)})",
                      "Repeated attempts to one login service suggest password guessing",
                      len(g), g.datetime.min(), g.datetime.max()))

    # Rule 3 - DNS anomaly: query flood, or long / high-entropy names
    dns = df[df.dns_query != ""].copy()
    if not dns.empty:
        dns["label"] = dns.dns_query.str.split(".").str[0]
        dns["odd"] = (dns.label.str.len() >= 25) | ((dns.label.str.len() >= 10) & (dns.label.map(entropy) > 3.5))
        for src, g in dns.groupby("src"):
            odd = int(g.odd.sum())
            if len(g) >= dns_queries or odd >= 5:
                F.append(("Suspicious DNS Activity", "Medium", src, "DNS resolver",
                          f"R3: >= {dns_queries} DNS queries, or >= 5 long/random-looking names",
                          f"{len(g)} queries, {g.dns_query.nunique()} unique, {odd} look random/long",
                          "Random or very long names can indicate malware (DGA) or DNS tunnelling",
                          len(g), g.datetime.min(), g.datetime.max()))

    # Rule 4 - high packet rate: packets per second from one source
    d = df.copy()
    d["sec"] = d.datetime.dt.floor("1s")
    rate = d.groupby(["src", "sec"]).size().reset_index(name="pps")
    for src, g in rate[rate.pps >= rate_pps].groupby("src"):
        peak = g.loc[g.pps.idxmax()]
        F.append(("High Packet Rate", "Medium", src, "multiple",
                  f"R4: >= {rate_pps} packets per second from one source",
                  f"peak of {int(peak.pps)} packets/sec at {peak.sec}",
                  "Very high rates can indicate flooding, scanning tools or data transfer abuse",
                  int(g.pps.sum()), g.sec.min(), g.sec.max()))
    return pd.DataFrame(F, columns=COLS).sort_values("first_seen").reset_index(drop=True)


def extract_iocs(df: pd.DataFrame, findings: pd.DataFrame) -> dict:
    """Module 5: IPs, domains, URLs, ports."""
    ips = sorted(set(findings.source)) if not findings.empty else []
    domains, ports = [], []
    if not df.empty:
        dns = df[df.dns_query != ""].copy()
        if not dns.empty:
            dns["label"] = dns.dns_query.str.split(".").str[0]
            bad = dns[(dns.label.str.len() >= 25) | ((dns.label.str.len() >= 10) & (dns.label.map(entropy) > 3.5))]
            domains = sorted(set(bad.dns_query))
        urls = sorted(set(df[df.http_url != ""].http_url))
        if not findings.empty:
            bad_src = set(findings.source)
            s = df[df.src.isin(bad_src) & (df["flags"] == "S") & df.dport.notna()]
            ports = sorted(int(x) for x in s.dport.unique())
    else:
        urls = []
    return {"ips": ips, "domains": domains, "urls": urls, "ports": ports}


def build_report(df, findings, iocs) -> str:
    L = ["# Network Investigation Report", ""]
    if df.empty:
        return "\n".join(L + ["No IP traffic found."])
    L += [f"- Packets analysed: {len(df)}", f"- Capture window: {df.datetime.min()} → {df.datetime.max()}",
          f"- Protocol mix: {dict(df.proto.value_counts())}", "", "## Findings", ""]
    if findings.empty:
        L.append("No suspicious activity detected.")
    for _, f in findings.iterrows():
        L.append(f"- **{f.type}** [{f.severity}] {f.source} → {f.target}: {f.behavior}. Rule: {f.rule}. "
                 f"Reason: {f.reason}. ({f.first_seen} to {f.last_seen})")
    L += ["", "## Indicators of Compromise", "",
          f"- IPs: {', '.join(iocs['ips']) or '-'}",
          f"- Domains: {', '.join(iocs['domains'][:50]) or '-'}",
          f"- URLs: {', '.join(iocs['urls'][:50]) or '-'}",
          f"- Ports: {', '.join(map(str, iocs['ports'][:100])) or '-'}",
          "", "_Validate findings manually in Wireshark before acting on them._"]
    return "\n".join(L)
