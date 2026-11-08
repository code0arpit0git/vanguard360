# 🛡️ Vanguard360: Hybrid CTEM & Blockchain Security Suite

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED.svg)
![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)
![Security](https://img.shields.io/badge/Security-DevSecOps%20%7C%20EASM-success.svg)

**Vanguard360** is a highly portable, containerized **Continuous Threat Exposure Management (CTEM)** platform. It bridges the gap between pre-deployment source code auditing and post-deployment network reconnaissance by correlating internal vulnerabilities with external attack surfaces.

To ensure compliance integrity, all VAPT (Vulnerability Assessment and Penetration Testing) reports are cryptographically sealed using an **HMAC-SHA256 Proof-of-Work (PoW) Blockchain Ledger**, preventing unauthorized log tampering.

---

## 🏗️ Architecture & Data Flow Diagram (DFD)

```mermaid
graph TD
    subgraph "Input Layer"
        T1[Local Source Code / Dockerfile]
        T2[Target IP / Domain]
    end

    subgraph "Phase 1: Dual Scanning Engine"
        DSO[Module 1: DevSecOps Scanner<br/>- AST Code Analysis<br/>- Secret Entropy Engine<br/>- Docker Hardening]
        EASM[Module 2: EASM Scanner<br/>- Async Port Probing<br/>- Web3 JSON-RPC Audit<br/>- HTTP Header Checks]
        
        T1 --> DSO
        T2 --> EASM
    end

    subgraph "Phase 2: Intelligence & Correlation"
        COR{Module 3: Threat Correlator}
        DSO -->|Internal Flaws & Declared Ports| COR
        EASM -->|Active Network Exposures| COR
    end

    subgraph "Phase 3: Cryptographic Ledger & Reporting"
        LEDGER[(Module 4: HMAC-SHA256 PoW Blockchain)]
        REP[Executive PDF Report Generation]
        
        COR -->|Unified Risk Score| LEDGER
        LEDGER -->|Immutable Block Hash| REP
    end

    Installation & Portable Setup
Vanguard360 is designed for maximum portability. It requires zero host-level dependencies other than Docker.

Method 1: Docker (Recommended for Portability)
Run the entire suite securely isolated inside a container.

Bash
# 1. Clone the repository
git clone https://github.com/code0arpit0git/vanguard360.git
cd vanguard360

# 2. Spin up the environment
docker compose up --build
The dashboard will automatically be available at http://localhost:8501.

Method 2: Local Python Virtual Environment
If you prefer running it natively for development:

Bash
# 1. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate # macOS/Linux

# 2. Install requirements
pip install -r requirements.txt

# 3. Launch the Streamlit dashboard
streamlit run app.py
🔐 Security & Credential Management
No Hardcoded Secrets: This repository strictly enforces a .gitignore policy. Configuration files containing local variables, audit_chain.json state files, and virtual environments are never pushed to version control.

Blockchain Signature Key: The HMAC ledger relies on a server-side secret key. In production, pass this via an environment variable (VANGUARD_HMAC_KEY) rather than hardcoding it into the application.

Credential Hasher Utility: The built-in dashboard includes a PBKDF2-HMAC-SHA256 hashing utility to convert raw APIs and passwords into salted database-safe fingerprints.

📁 Project Structure
Plaintext
vanguard360/
├── app.py                      # Main Streamlit Dashboard & UI Hub
├── Dockerfile                  # Containerization blueprints
├── docker-compose.yml          # Portable deployment orchestrator
├── requirements.txt            # Python dependencies
├── core/
│   ├── devsecops_scanner.py    # AST, Secrets, and Dockerfile auditor
│   ├── easm_scanner.py         # Network and HTTP header recon
│   ├── correlator.py           # Unified risk correlation logic
│   └── blockchain_ledger.py    # HMAC-SHA256 PoW audit trail
├── utils/
│   └── pdf_generator.py        # Executive VAPT report exporter
└── sample_targets/             # Built-in vulnerable codebase for offline testing