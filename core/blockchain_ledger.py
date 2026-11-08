import hashlib
import json
import os
import re
import time
import hmac
from typing import Dict, List, Any


class ImmutableAuditChain:
    
    """
    Portable, zero-dependency Proof-of-Work (PoW) Blockchain Ledger
    that cryptographically seals VAPT & DevSecOps scan reports.
    """
    def __init__(self, ledger_path: str = "audit_chain.json", difficulty: int = 3):
        self.secret_key = os.environ.get("VANGUARD_HMAC_KEY", "vanguard360-internal-master-key").encode("utf-8")
            
        self.ledger_path = ledger_path
        self.difficulty = difficulty
        self.chain: List[Dict[str, Any]] = []
        self.load_or_init_chain()

    def calculate_hash(self, block: Dict[str, Any]) -> str:
     block_copy = {k: v for k, v in block.items() if k != "block_hash"}
     block_string = json.dumps(block_copy, sort_keys=True).encode("utf-8")
     return hmac.new(self.secret_key, block_string, hashlib.sha256).hexdigest()

    def load_or_init_chain(self):
        if os.path.exists(self.ledger_path):
            try:
                with open(self.ledger_path, "r", encoding="utf-8") as f:
                    self.chain = json.load(f)
                if self.chain:
                    return
            except Exception:
                pass

        genesis_block = {
            "index": 0,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "target": "GENESIS_BLOCK",
            "findings_hash": "0" * 64,
            "total_findings": 0,
            "risk_score": 0,
            "previous_hash": "0" * 64,
            "nonce": 0
        }
        genesis_block["block_hash"] = self.mine_block(genesis_block)
        self.chain = [genesis_block]
        self.save_chain()

    def mine_block(self, block: Dict[str, Any]) -> str:
        prefix = "0" * self.difficulty
        while True:
            computed_hash = self.calculate_hash(block)
            if computed_hash.startswith(prefix):
                return computed_hash
            block["nonce"] += 1

    def record_scan(self, target: str, findings: List[Dict[str, Any]], risk_score: int) -> Dict[str, Any]:
        findings_serialized = json.dumps(findings, sort_keys=True).encode("utf-8")
        findings_hash = hashlib.sha256(findings_serialized).hexdigest()

        prev_block = self.chain[-1]
        new_block = {
            "index": len(self.chain),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "target": target,
            "findings_hash": findings_hash,
            "total_findings": len(findings),
            "risk_score": risk_score,
            "previous_hash": prev_block["block_hash"],
            "nonce": 0
        }
        new_block["block_hash"] = self.mine_block(new_block)
        self.chain.append(new_block)
        self.save_chain()
        return new_block

    def verify_chain_integrity(self) -> Dict[str, Any]:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            recalculated_hash = self.calculate_hash(current)
            if current.get("block_hash") != recalculated_hash:
                return {
                    "valid": False,
                    "compromised_block": i,
                    "reason": (
                        f"CRITICAL TAMPER ALERT: Block #{i} payload was modified after signing! "
                        f"Stored Hash: {current.get('block_hash')[:12]}... != "
                        f"Computed Hash: {recalculated_hash[:12]}..."
                    )
                }

            if current.get("previous_hash") != previous.get("block_hash"):
                return {
                    "valid": False,
                    "compromised_block": i,
                    "reason": f"CRITICAL CHAIN BREAK: Block #{i} previous_hash does not match Block #{i-1}!"
                }

        return {
            "valid": True,
            "total_blocks": len(self.chain),
            "reason": "All blocks cryptographically verified via SHA-256 Proof-of-Work. Zero tampering detected."
        }

    def simulate_rogue_tamper(self) -> bool:
        if len(self.chain) < 2:
            return False
        self.chain[-1]["risk_score"] = 0
        self.chain[-1]["total_findings"] = 0
        self.save_chain()
        return True

    def repair_chain(self):
        for i in range(1, len(self.chain)):
            self.chain[i]["previous_hash"] = self.chain[i - 1]["block_hash"]
            self.chain[i]["nonce"] = 0
            self.chain[i]["block_hash"] = self.mine_block(self.chain[i])
        self.save_chain()

    def save_chain(self):
        with open(self.ledger_path, "w", encoding="utf-8") as f:
            json.dump(self.chain, f, indent=4)


class Web3SecurityAuditor:
    """Audits Solidity (.sol) Smart Contracts for known Web3 vulnerabilities."""
    @staticmethod
    def scan_solidity_file(filepath: str, base_dir: str) -> List[Dict[str, Any]]:
        findings = []
        rel_path = os.path.relpath(filepath, base_dir)

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        solidity_rules = {
            "Smart Contract Reentrancy Risk (.call{value})": (
                r"\.call\s*\{?\s*value\s*:",
                "Critical",
                "External Ether transfer via .call{value}() before state update enables Reentrancy drains. Apply Checks-Effects-Interactions or ReentrancyGuard."
            ),
            "Phishing Authorization Flaw (tx.origin)": (
                r"tx\.origin\s*==",
                "High",
                "Using tx.origin for authentication allows malicious contracts to impersonate owners. Use msg.sender instead."
            ),
            "Unprotected Contract Destruction (selfdestruct)": (
                r"\b(selfdestruct|suicide)\s*\(",
                "Critical",
                "Remove selfdestruct() or protect it behind a multi-sig timelock."
            )
        }

        for line_num, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("//"):
                continue

            for category, (pattern, severity, remediation) in solidity_rules.items():
                if re.search(pattern, line):
                    findings.append({
                        "module": "Web3 Smart Contract (SAST)",
                        "severity": severity,
                        "category": category,
                        "file": rel_path,
                        "line": line_num,
                        "port": 8545,
                        "issue": f"Vulnerable Solidity code pattern: '{line[:65]}'",
                        "remediation": remediation
                    })

        return findings