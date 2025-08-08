# netsec-audit-tool

> Authorized network video device audit helper with nmap fingerprinting, basic ONVIF probe, and image-quality checks—**for consented environments only**.

## ⚠️ Legal & Ethical Notice

This project is for **defensive security** and **IT asset inventory** on **systems you own or are explicitly authorized to assess**.  
Attempting to access devices without permission can be illegal. By using this tool, you agree to the [Responsible Use](#responsible-use) terms.

## Features
- Classifies IPv4 address ranges (A/B/C).
- Runs targeted `nmap` scans (if installed on host).
- Lightweight ONVIF *endpoint existence* probe on common ports.
- Optional frame capture from authorized RTSP URLs for basic image-quality metrics (resolution, brightness, sharpness, SSIM self-check).

## Quickstart

```bash
# 1) Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 2) Install (choose one)
pip install -r requirements.txt
# or
pip install -e .

# 3) Make sure nmap is installed on your system, e.g.
#    Ubuntu/Debian: sudo apt-get install nmap
#    macOS (brew):  brew install nmap
#    Windows:       https://nmap.org/download.html

# 4) Run help
netsec-audit --help
```

### Examples

```bash
# Scan a couple of IPs with an allowlist file and NO default credential attempts
netsec-audit --ips 192.168.1.10,192.168.1.20   --allowlist allowlist.txt   --output-dir ./captures   --disable-default-credentials

# Read IPs from a file
netsec-audit --ip-file targets.txt --allowlist allowlist.txt --output-dir ./captures --disable-default-credentials

# Provide an explicit RTSP URL (authorized only) to capture a single frame and analyze
netsec-audit --rtsp rtsp://user:pass@192.168.1.10:554 --output-dir ./captures --analyze-only
```

> **Note**: Default-credential attempts are **disabled by default** and can only be enabled with explicit flags **and** allowlist confirmation. This is to prevent misuse.

## Responsible Use

- Operate only on assets you own or have **written authorization** to test.
- Respect rate limits, maintenance windows, and local policy.
- Keep logs and consent records.
- Disable any intrusive behavior unless strictly necessary and approved.

## Limitations

- `nmap` must be installed separately on your system.
- Some features (e.g., ARP/MAC lookups with scapy) may require elevated privileges or proper interface selection.
- ONVIF probe here checks for an endpoint signature only; it does not authenticate or enumerate capabilities.

## License
MIT
