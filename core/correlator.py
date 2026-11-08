import hashlib
from typing import Dict, List, Any


class ThreatCorrelator:
    """
    Correlates Inside-Out (DevSecOps/Web3) findings with Outside-In (EASM) open ports
    and assigns a SHA-256 fingerprint to each finding so sensitive data remains hashed.
    """
    SEVERITY_WEIGHTS = {
        "Critical": 20,
        "High": 12,
        "Medium": 6,
        "Low": 2
    }

    @staticmethod
    def hash_finding_fingerprint(finding: Dict[str, Any]) -> str:
        raw_signature = f"{finding.get('file')}:{finding.get('line')}:{finding.get('category')}"
        return hashlib.sha256(raw_signature.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def correlate(
        cls,
        devsecops_result: Dict[str, Any],
        easm_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        inside_findings = devsecops_result.get("findings", [])
        outside_findings = easm_result.get("findings", [])
        declared_ports = set(devsecops_result.get("declared_ports", []))
        open_ports = set(easm_result.get("open_ports", []))

        correlated_chains: List[Dict[str, Any]] = []

        exposed_and_open = declared_ports.intersection(open_ports)
        for port in exposed_and_open:
            related_inside = [f for f in inside_findings if f.get("port") == port]
            if related_inside:
                categories = ", ".join(set(f["category"] for f in related_inside))
                correlated_chains.append({
                    "module": "CTEM Correlator (Attack Path)",
                    "severity": "Critical",
                    "category": f"Verified Exposure Chain on Port {port}",
                    "file": "Inside-Out + Outside-In Correlation",
                    "line": port,
                    "port": port,
                    "issue": (
                        f"Port {port} is declared in Dockerfile, linked to internal finding ({categories}), "
                        f"AND confirmed reachable by external surface check."
                    ),
                    "remediation": (
                        f"Restrict external access to port {port} and remediate internal findings ({categories})."
                    )
                })

        all_findings = correlated_chains + inside_findings + outside_findings

        # Attach SHA-256 hashed fingerprint to each finding
        for item in all_findings:
            item["finding_hash"] = cls.hash_finding_fingerprint(item)

        raw_score = sum(cls.SEVERITY_WEIGHTS.get(f.get("severity", "Low"), 2) for f in all_findings)
        risk_score = min(100, raw_score)

        return {
            "risk_score": risk_score,
            "correlated_chains": correlated_chains,
            "all_findings": all_findings,
            "exposed_and_open_ports": sorted(list(exposed_and_open))
        }