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