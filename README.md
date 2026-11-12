# Network Packet Investigation & Suspicious Traffic Detection

## Run
    pip install -r requirements.txt
    python -m streamlit run app.py
Open http://localhost:8501 and upload sample.pcap (or your own .pcap/.pcapng).

## Files
- app.py – Streamlit dashboard
- analyzer.py – extraction, detection (port scan, brute force, DNS anomaly), IOCs, report
- make_sample_pcap.py – regenerates sample.pcap
- sample.pcap – demo capture with simulated attacks
- Network_Packet_Investigation_Documentation.docx – project documentation

Live capture needs admin rights (and Npcap on Windows).

## Detection rules
- R1 Port scan, R2 Brute force, R3 Suspicious DNS, R4 High packet rate (all thresholds adjustable in the sidebar)
- Every alert shows: source, target, rule, observed behavior, reason, count, first/last seen
- Downloads: packets (CSV), alerts (CSV), investigation report (Markdown)

## One-click start
    python run.py        (or double-click run.bat on Windows)
For live capture, run it from a terminal opened as Administrator (Npcap needed on Windows).
