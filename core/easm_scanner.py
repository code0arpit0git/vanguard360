import socket
from typing import Dict, List, Any
import requests


class EASMScanner:
    """
    Outside-In External Attack Surface & Header Auditor.
    Supports both Local Host Verification and 100% Offline Viva Demo Mode.
    """
    COMMON_PORTS = {
        22: "SSH Remote Admin",
        80: "HTTP Web Server",
        443: "HTTPS Secure Web",
        3306: "MySQL Database",
        5000: "Flask/Python App Server",
        8080: "HTTP Proxy / Alt Web",
        8545: "Ethereum / Web3 JSON-RPC Node"
    }

    def __init__(self, target_host: str = "127.0.0.1", offline_demo_mode: bool = True):
        self.target_host = target_host
        self.offline_demo_mode = offline_demo_mode
        self.open_ports: List[int] = []
        self.findings: List[Dict[str, Any]] = []

    def scan_ports(self, extra_ports: List[int] = None):
        ports_to_check = dict(self.COMMON_PORTS)
        if extra_ports:
            for p in extra_ports:
                if p not in ports_to_check:
                    ports_to_check[p] = "Container Declared Port"

        if self.offline_demo_mode:
            simulated_open = [22, 5000, 8545]
            for port in simulated_open:
                self.open_ports.append(port)
                service = ports_to_check.get(port, "Active Service")
                severity = "Critical" if port in [22, 8545] else "Medium"
                self.findings.append({
                    "module": "EASM (External Network)",
                    "severity": severity,
                    "category": f"Exposed Network Port ({port}/{service})",
                    "file": f"Host: {self.target_host}",
                    "line": port,
                    "port": port,
                    "issue": f"Port {port} ({service}) is reachable from the external network interface.",
                    "remediation": f"Restrict port {port} via firewall rules or bind the service to 127.0.0.1."
                })
            return

        for port, service in ports_to_check.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.6)
                    result = s.connect_ex((self.target_host, port))
                    if result == 0:
                        self.open_ports.append(port)
                        severity = "High" if port in [22, 3306, 8545] else "Medium"
                        self.findings.append({
                            "module": "EASM (External Network)",
                            "severity": severity,
                            "category": f"Open Network Port ({port}/{service})",
                            "file": f"Host: {self.target_host}",
                            "line": port,
                            "port": port,
                            "issue": f"Service listener detected on {self.target_host}:{port} ({service}).",
                            "remediation": f"Close port {port} on the perimeter firewall if external access is unnecessary."
                        })
            except Exception:
                continue

    def audit_http_headers(self):
        if self.offline_demo_mode:
            self.findings.append({
                "module": "EASM (Web Surface)",
                "severity": "Medium",
                "category": "Missing HTTP Security Headers (CSP & HSTS)",
                "file": f"http://{self.target_host}:5000",
                "line": 5000,
                "port": 5000,
                "issue": "HTTP response lacks Content-Security-Policy and X-Frame-Options headers.",
                "remediation": "Configure reverse proxy or application middleware to enforce security headers."
            })
            return

        for port in [80, 443, 5000, 8080]:
            if port in self.open_ports:
                proto = "https" if port == 443 else "http"
                url = f"{proto}://{self.target_host}:{port}"
                try:
                    # allow_redirects=False prevents SSRF bounce attacks
                    # stream=True avoids downloading massive response bodies into memory
                    with requests.get(url, timeout=1.5, verify=False, allow_redirects=False, stream=True) as resp:
                        headers = resp.headers

                    missing = [
                        h for h in ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"]
                        if h not in headers
                    ]
                    if missing:
                        self.findings.append({
                            "module": "EASM (Web Surface)",
                            "severity": "Medium",
                            "category": "Missing HTTP Security Headers",
                            "file": url,
                            "line": port,
                            "port": port,
                            "issue": f"Endpoint missing hardening headers: {', '.join(missing)}.",
                            "remediation": "Add security headers in web server or application middleware."
                        })
                except Exception:
                    continue

    def run_full_scan(self, declared_ports: List[int] = None) -> Dict[str, Any]:
        self.open_ports.clear()
        self.findings.clear()
        self.scan_ports(declared_ports)
        self.audit_http_headers()
        return {
            "open_ports": sorted(list(set(self.open_ports))),
            "total_findings": len(self.findings),
            "findings": self.findings
        }