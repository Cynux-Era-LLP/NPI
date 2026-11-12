import tempfile
import pandas as pd
import streamlit as st
from scapy.all import rdpcap, sniff
from analyzer import extract, detect, extract_iocs, build_report

st.set_page_config(page_title="Packet Investigator", layout="wide")
st.title("🔍 Network Packet Investigation & Suspicious Traffic Detection")

with st.sidebar:
    st.header("Input")
    mode = st.radio("Source", ["Upload PCAP", "Live capture"])
    st.header("Thresholds")
    scan_ports = st.slider("Port scan: distinct ports", 5, 200, 15)
    brute = st.slider("Brute force: attempts", 5, 200, 20)
    dnsq = st.slider("DNS flood: queries per host", 10, 500, 50)
    rate = st.slider("High packet rate: packets/sec per source", 5, 2000, 100)

packets = None
if mode == "Upload PCAP":
    up = st.file_uploader("Upload a .pcap / .pcapng file", type=["pcap", "pcapng", "cap"])
    if up:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as t:
            t.write(up.getbuffer())
        packets = rdpcap(t.name)
else:
    st.caption("Needs admin/root privileges (and Npcap on Windows).")
    secs = st.number_input("Seconds", 5, 300, 20)
    iface = st.text_input("Interface (blank = default)")
    if st.button("Start capture"):
        with st.spinner("Capturing..."):
            packets = sniff(timeout=int(secs), iface=iface or None)

if packets is None:
    st.info("Upload a PCAP or start a capture to begin.")
    st.stop()

df = extract(packets)
if df.empty:
    st.warning("No IP packets found.")
    st.stop()
findings = detect(df, scan_ports, brute, dnsq, rate)
iocs = extract_iocs(df, findings)

c = st.columns(4)
c[0].metric("Packets", len(df))
c[1].metric("Unique IPs", len(set(df.src) | set(df.dst)))
c[2].metric("Findings", len(findings))
c[3].metric("Suspicious IPs", len(iocs["ips"]))

for _, f in findings.iterrows():
    msg = f"**{f.type}** — {f.source} → {f.target}: {f.behavior}  |  Rule: {f.rule}  |  Reason: {f.reason}"
    (st.error if f.severity == "High" else st.warning)(msg)
if findings.empty:
    st.success("No suspicious activity detected.")

t1, t2, t3, t4, t5 = st.tabs(["Timeline", "Protocols", "Packets", "IOCs", "Report"])
with t1:
    st.subheader("Traffic over time")
    st.line_chart(df.set_index("datetime").resample("1s").size().rename("packets/sec"))
    st.subheader("Event timeline")
    st.dataframe(findings, use_container_width=True)
    st.download_button("Download alerts (CSV)", findings.to_csv(index=False), "alerts.csv")
with t2:
    a, b = st.columns(2)
    a.bar_chart(df.proto.value_counts())
    b.write("Top talkers"); b.dataframe(df.src.value_counts().head(10))
    st.write("DNS queries"); st.dataframe(df[df.dns_query != ""][["datetime", "src", "dns_query"]], use_container_width=True)
    st.write("HTTP requests"); st.dataframe(df[df.http_url != ""][["datetime", "src", "dst", "http_url"]], use_container_width=True)
with t3:
    ip = st.text_input("Filter by IP")
    view = df[(df.src == ip) | (df.dst == ip)] if ip else df
    st.dataframe(view.drop(columns="time"), use_container_width=True)
    st.download_button("Download CSV", view.to_csv(index=False), "packets.csv")
with t4:
    for k, label in [("ips", "Suspicious IPs"), ("domains", "Suspicious domains"), ("urls", "URLs"), ("ports", "Ports")]:
        st.write(f"**{label}**"); st.dataframe(pd.DataFrame({k: list(iocs[k])}), use_container_width=True)
with t5:
    rep = build_report(df, findings, iocs)
    st.markdown(rep)
    st.download_button("Download report (.md)", rep, "investigation_report.md")
