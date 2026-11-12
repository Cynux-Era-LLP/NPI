"""One-click launcher: python run.py  (works from any folder)."""
import os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)  # so app.py and sample.pcap are always found

missing = []
for mod in ("scapy", "pandas", "streamlit"):
    try:
        __import__(mod)
    except ImportError:
        missing.append(mod)

if missing:
    print("Installing missing packages:", ", ".join(missing))
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-cache-dir", *missing])

print("Starting the dashboard at http://localhost:8501  (press Ctrl+C to stop)")
try:
    subprocess.run([sys.executable, "-m", "streamlit", "run", "app.py"], check=False)
except KeyboardInterrupt:
    print("Stopped.")
