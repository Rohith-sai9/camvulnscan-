import argparse
import sys
from typing import List, Optional, Set
from .scanner import (
    classify_ip,
    run_nmap_scan,
    check_onvif,
    get_mac_address,
    try_default_credentials_for_url,
    capture_and_analyze_frame,
)

def read_list_arg(arg: str) -> List[str]:
    return [x.strip() for x in arg.split(",") if x.strip()]

def load_file_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip()]

def ensure_allowlisted(targets: List[str], allowlist: Set[str]) -> List[str]:
    return [t for t in targets if t in allowlist]

def main():
    p = argparse.ArgumentParser(
        prog="netsec-audit",
        description="Authorized network video device audit helper (nmap, ONVIF probe, optional RTSP frame capture).",
    )
    g_in = p.add_argument_group("Targets")
    g_in.add_argument("--ips", help="Comma-separated IPs to assess, e.g. 192.168.1.10,192.168.1.11")
    g_in.add_argument("--ip-file", help="File containing one IP per line.")
    g_in.add_argument("--rtsp", help="Explicit RTSP URL (authorized only) for frame capture+analysis.")

    g_safe = p.add_argument_group("Safety & Policy")
    g_safe.add_argument("--allowlist", help="Path to allowlist file (one IP per line). REQUIRED to enable default credentials attempts.")
    g_safe.add_argument("--enable-default-credentials", action="store_true", help="Allow trying common default RTSP creds for allowlisted IPs only.")
    g_safe.add_argument("--disable-default-credentials", action="store_true", help="Force-disable default creds attempts (default).")

    g_ops = p.add_argument_group("Operations")
    g_ops.add_argument("--output-dir", default="captures", help="Directory to write captured frames.")
    g_ops.add_argument("--skip-nmap", action="store_true", help="Skip running nmap.")
    g_ops.add_argument("--skip-onvif", action="store_true", help="Skip ONVIF probe.")
    g_ops.add_argument("--skip-mac", action="store_true", help="Skip ARP/MAC lookup.")

    g_misc = p.add_argument_group("Misc")
    g_misc.add_argument("--analyze-only", action="store_true", help="Only analyze RTSP (no scans).")

    args = p.parse_args()

    # Gather targets
    targets: List[str] = []
    if args.ips:
        targets.extend(read_list_arg(args.ips))
    if args.ip_file:
        targets.extend(load_file_lines(args.ip_file))
    targets = [t for t in targets if t]

    # Safety: manage default creds
    default_creds_enabled = False
    allowlist: Set[str] = set()
    if args.enable_default_credentials:
        if not args.allowlist:
            print("Refusing to try default credentials without an --allowlist. Aborting.", file=sys.stderr)
            sys.exit(2)
        allowlist = set(load_file_lines(args.allowlist))
        if not allowlist:
            print("Allowlist is empty; refusing to enable default credentials.", file=sys.stderr)
            sys.exit(2)
        # limit targets to allowlist for default creds
        default_creds_enabled = True

    # If analyze-only with explicit RTSP
    if args.analyze_only and args.rtsp:
        saved = capture_and_analyze_frame(args.rtsp, args.output_dir)
        if saved:
            print(f"Saved frame: {saved}")
        else:
            print("Failed to capture frame from RTSP URL.")
        return

    # Process each IP
    for ip in targets:
        print(f"\n=== Target: {ip} ===")
        print(f"Class: {classify_ip(ip)}")

        if not args.skip_nmap and not args.analyze_only:
            rc, out, err = run_nmap_scan(ip)
            if rc == 0:
                print("[nmap] Done.\n" + out)
            else:
                print(f"[nmap] Error (rc={rc}). {err}")

        if not args.skip_onvif and not args.analyze_only:
            port = check_onvif(ip)
            if port:
                print(f"[onvif] Likely ONVIF endpoint on port {port}")
            else:
                print("[onvif] No endpoint detected on common ports.")

        if not args.skip_mac and not args.analyze_only:
            mac = get_mac_address(ip)
            if mac:
                print(f"[mac] {mac}")
            else:
                print("[mac] Unavailable (requires privileges or host unreachable).")

        # Optional default credentials attempt, strictly allowlisted
        if default_creds_enabled and ip in allowlist:
            url = try_default_credentials_for_url(ip, enabled=True)
            if url:
                print(f"[rtsp] Accessible with common default credentials: {url}")
                saved = capture_and_analyze_frame(url, args.output_dir)
                if saved:
                    print(f"[rtsp] Saved frame: {saved}")
            else:
                print("[rtsp] Default credentials did not work (or device not RTSP-enabled).")

    # If explicit RTSP provided outside analyze-only, you can capture too
    if args.rtsp and not args.analyze_only:
        saved = capture_and_analyze_frame(args.rtsp, args.output_dir)
        if saved:
            print(f"Saved frame: {saved}")
        else:
            print("Failed to capture frame from RTSP URL.")
