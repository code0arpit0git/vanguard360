import os
import re
import math
import ast
from typing import Dict, List, Any
from core.blockchain_ledger import Web3SecurityAuditor


class DevSecOpsScanner:
    def scan_python_ast(self, filepath: str):
        """Uses Abstract Syntax Tree (AST) parsing to catch multi-line evasions."""
        rel_path = os.path.relpath(filepath, self.target_dir)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                tree = ast.parse(f.read(), filename=rel_path)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Catch multi-line eval() or exec()
                if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                    self.findings.append({
                        "module": "DevSecOps (AST Engine)",
                        "severity": "High",
                        "category": f"AST Verified Arbitrary Execution ({node.func.id})",
                        "file": rel_path,
                        "line": getattr(node, "lineno", 1),
                        "port": None,
                        "issue": f"AST parser confirmed call to dangerous function '{node.func.id}()' (immune to multi-line formatting bypass).",
                        "remediation": "Remove dynamic code execution and use safe parsing."
                    })

                # Catch multi-line subprocess(..., shell=True)
                for kw in getattr(node, "keywords", []):
                 if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append({
                        "module": "DevSecOps (AST Engine)",
                        "severity": "High",
                        "category": "AST Verified Command Injection",
                        "file": rel_path,
                        "line": getattr(node, "lineno", 1),
                        "port": None,
                        "issue": "subprocess called with shell=True.",
                        "remediation": "Set shell=False."
                    })
    def __init__(self, target_dir: str):
        self.target_dir = target_dir
        self.findings: List[Dict[str, Any]] = []
        self.declared_ports: List[int] = []

    def calculate_shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            entropy += -p_x * math.log(p_x, 2)
        return entropy

    def scan_dockerfile(self, filepath: str):
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        has_user_instruction = False
        rel_path = os.path.relpath(filepath, self.target_dir)

        for line_num, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if line.upper().startswith("FROM") and ":latest" in line.lower():
                self.findings.append({
                    "module": "DevSecOps (Container)",
                    "severity": "Medium",
                    "category": "Unpinned Container Base Image",
                    "file": rel_path,
                    "line": line_num,
                    "port": None,
                    "issue": f"Image uses mutable ':latest' tag ({line}), risking supply-chain drift.",
                    "remediation": "Pin image to a minimal version tag (e.g., python:3.11-slim)."
                })

            if line.upper().startswith("USER"):
                parts = line.split()
                if len(parts) > 1 and parts[1].lower() not in ["root", "0"]:
                    has_user_instruction = True

            if line.upper().startswith("EXPOSE"):
                for part in line.split()[1:]:
                    port_str = re.sub(r"[^0-9]", "", part)
                    if port_str.isdigit():
                        port = int(port_str)
                        self.declared_ports.append(port)
                        if port in [22, 23, 3389, 8545]:
                            self.findings.append({
                                "module": "DevSecOps (Container)",
                                "severity": "High",
                                "category": "Sensitive Port Exposed in Dockerfile",
                                "file": rel_path,
                                "line": line_num,
                                "port": port,
                                "issue": f"Dockerfile explicitly exposes high-risk port {port} (SSH/Admin/Web3 RPC).",
                                "remediation": f"Remove port {port} from EXPOSE and restrict access to internal Docker networks."
                            })

        if not has_user_instruction:
            self.findings.append({
                "module": "DevSecOps (Container)",
                "severity": "High",
                "category": "Container Running as Root User",
                "file": rel_path,
                "line": 1,
                "port": None,
                "issue": "No non-root USER instruction found in Dockerfile. Container defaults to root.",
                "remediation": "Add 'RUN useradd -m appuser && USER appuser' before CMD."
            })

    def scan_source_file(self, filepath: str):
        secret_patterns = {
            "Hardcoded AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Exposed Web3 / Ethereum Private Key": r"0x[a-fA-F0-9]{64}",
            "Hardcoded Password / Secret Token": r"(?i)(password|secret|api_key|token)\s*=\s*['\"]([^'\"]{8,})['\"]"
        }

        sast_patterns = {
            "OS Command Injection (shell=True)": (
                r"subprocess\.(Popen|call|run)\(.*shell\s*=\s*True",
                "High",
                None,
                "Pass command arguments as a list with shell=False to prevent command injection."
            ),
            "Arbitrary Code Execution (eval/exec)": (
                r"\b(eval|exec)\s*\(",
                "High",
                None,
                "Replace eval()/exec() with safe parsers like ast.literal_eval() or json.loads()."
            ),
            "Debug Mode Enabled in Application": (
                r"(?i)debug\s*=\s*True",
                "Medium",
                5000,
                "Set DEBUG=False in production to prevent interactive Werkzeug/stack-trace RCE on port 5000."
            )
        }

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        rel_path = os.path.relpath(filepath, self.target_dir)

        for line_num, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            for label, pattern in secret_patterns.items():
                match = re.search(pattern, line)
                if match:
                    entropy = self.calculate_shannon_entropy(match.group(0))
                    self.findings.append({
                        "module": "DevSecOps (Secrets)",
                        "severity": "Critical",
                        "category": label,
                        "file": rel_path,
                        "line": line_num,
                        "port": 8545 if "Web3" in label else None,
                        "issue": f"Hardcoded credential detected in source (Shannon Entropy: {entropy:.2f}).",
                        "remediation": "Inject secrets at runtime via environment variables or a vault manager."
                    })

            for category, (pattern, severity, assoc_port, remediation) in sast_patterns.items():
                if re.search(pattern, line):
                    self.findings.append({
                        "module": "DevSecOps (SAST)",
                        "severity": severity,
                        "category": category,
                        "file": rel_path,
                        "line": line_num,
                        "port": assoc_port,
                        "issue": f"Dangerous code construct: '{line[:65]}'",
                        "remediation": remediation
                    })

    def run_full_scan(self) -> Dict[str, Any]:
        self.findings.clear()
        self.declared_ports.clear()

        ignored_dirs = {"venv", ".venv", ".git", "node_modules", "__pycache__"}
        max_file_size = 2 * 1024 * 1024  # 2 MB DoS protection limit

        for root, dirs, files in os.walk(self.target_dir):
            
            dirs[:] = [d for d in dirs if d not in ignored_dirs]

            for file in files:
                full_path = os.path.join(root, file)
                try:
                    if os.path.getsize(full_path) > max_file_size:
                        continue
                except OSError:
                    continue

                if file.lower() == "dockerfile":
                    self.scan_dockerfile(full_path)
                elif file.endswith(".sol"):
                    sol_findings = Web3SecurityAuditor.scan_solidity_file(full_path, self.target_dir)
                    self.findings.extend(sol_findings)
                elif file.endswith((".py", ".js", ".env", ".yml", ".yaml")):
                    self.scan_source_file(full_path)
                    if file.endswith(".py"):
                        self.scan_python_ast(full_path)

        return {
            "total_findings": len(self.findings),
            "declared_ports": sorted(list(set(self.declared_ports))),
            "findings": self.findings
        }