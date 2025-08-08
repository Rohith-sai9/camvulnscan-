import os
import cv2
import numpy as np
import subprocess
import requests
from datetime import datetime
from typing import List, Optional, Tuple, Iterable

try:
    from skimage.metrics import structural_similarity as ssim
except Exception:  # pragma: no cover
    ssim = None

# scapy import may require elevated privileges and proper network interface permissions
try:
    from scapy.all import ARP, Ether, srp
except Exception:  # pragma: no cover
    ARP = Ether = srp = None


def classify_ip(ip: str) -> str:
    try:
        first_octet = int(ip.split(".")[0])
        if 1 <= first_octet <= 127:
            return "Class A"
        elif 128 <= first_octet <= 191:
            return "Class B"
        elif 192 <= first_octet <= 223:
            return "Class C"
        else:
            return "Reserved or Multicast (Class D/E)"
    except (ValueError, IndexError):
        return "Invalid IP"


def run_nmap_scan(ip: str) -> Tuple[int, str, str]:
    """
    Run an nmap scan using -A -sV and the 'vulners' script if available.
    Returns (returncode, stdout, stderr).
    Note: Requires nmap installed on host.
    """
    cmd = ["nmap", "-A", "-sV", "--script", "vulners", ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError as e:
        return 127, "", f"nmap not found: {e}"
    except Exception as e:
        return 1, "", str(e)


def check_onvif(ip: str, timeout: float = 3.0) -> Optional[int]:
    """
    Probe common HTTP ports for an ONVIF device_service endpoint signature.
    Returns the port if likely found, else None.
    """
    ports = [80, 8000, 8080, 8888]
    for port in ports:
        url = f"http://{ip}:{port}/onvif/device_service"
        try:
            resp = requests.get(url, timeout=timeout)
            t = resp.text.lower()
            if "onvif" in t or "soap" in t:
                return port
        except requests.exceptions.RequestException:
            continue
    return None


def get_mac_address(ip: str, timeout: int = 2) -> Optional[str]:
    """
    Attempt ARP request to get MAC; requires scapy and proper privileges.
    """
    if ARP is None or Ether is None or srp is None:
        return None
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        reply = srp(arp_request_broadcast, timeout=timeout, verbose=0)[0]
        if reply:
            return reply[0][1].hwsrc
    except Exception:
        return None
    return None


def try_default_credentials_for_url(ip: str, enabled: bool = False) -> Optional[str]:
    """
    Disabled by default. If enabled=True, tries very common default RTSP credentials **only**
    for targets present in an explicit allowlist controlled by the CLI.
    """
    if not enabled:
        return None
    defaults = [("admin", "admin"), ("admin", ""), ("root", "root"), ("admin", "12345")]
    for user, pwd in defaults:
        url = f"rtsp://{user}:{pwd}@{ip}:554"
        cap = cv2.VideoCapture(url)
        try:
            if cap.isOpened():
                cap.release()
                return url
        finally:
            cap.release()
    return None


def capture_and_analyze_frame(rtsp_url: str, output_dir: str) -> Optional[str]:
    """
    Captures a single frame and saves a JPEG to output_dir, then prints basic IQA metrics.
    Returns the saved file path, or None.
    """
    os.makedirs(output_dir, exist_ok=True)
    cap = cv2.VideoCapture(rtsp_url)
    ret, frame = cap.read()
    cap.release()
    if not ret or frame is None:
        return None

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    ip_part = rtsp_url.split("@")[-1].replace(":", "_").replace("/", "_")
    save_path = os.path.join(output_dir, f"cctv_screenshot_{ip_part}_{timestamp}.jpg")
    cv2.imwrite(save_path, frame)

    # Basic analysis (printed)
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    h, w = gray.shape
    brightness = float(np.mean(gray))
    lap_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
    if ssim is not None:
        ssim_index = float(ssim(gray, gray, data_range=gray.max() - gray.min())) if gray.max() > gray.min() else 1.0
    else:
        ssim_index = float("nan")

    print(f"Resolution: {w}x{h}")
    print(f"Brightness: {brightness:.2f} (0-255)")
    print(f"Sharpness (Laplacian Var): {lap_var:.2f}")
    print(f"SSIM self-check: {ssim_index:.4f}")

    return save_path
