import os
import hashlib
import secrets
import sys
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
import streamlit as st
import pandas as pd
import plotly.express as px

from core.devsecops_scanner import DevSecOpsScanner
from core.easm_scanner import EASMScanner
from core.correlator import ThreatCorrelator
from core.blockchain_ledger import ImmutableAuditChain
from utils.pdf_generator import generate_pdf_report

st.set_page_config(
    page_title="Vanguard360 | Hybrid CTEM & Blockchain Security Suite",
    page_icon="🛡️",
    layout="wide"
)

ledger = ImmutableAuditChain()

st.title("🛡️ Vanguard360: Hybrid DevSecOps, EASM & Blockchain Audit Suite")
st.caption(
    "Inside-Out Code/Container/Smart-Contract SAST + Outside-In EASM + "
    "Salted Credential Hashing + Proof-of-Work Audit Ledger"
)

with st.sidebar:
    st.header("⚙️ Scan Configuration")
    default_demo_path = os.path.join("sample_targets", "vulnerable_demo_app")
    target_dir = st.text_input("Local Project Directory (Inside-Out)", value=default_demo_path)
    target_host = st.text_input("Target Host / IP (Outside-In EASM)", value="127.0.0.1")
    offline_mode = st.toggle(
        "Offline Viva Demo Mode (Simulated EASM)",
        value=True,
        help="Works 100% offline without internet or firewall interference."
    )

    run_btn = st.button("🚀 Run Full Hybrid Security Audit", type="primary", use_container_width=True)

    st.divider()
    st.subheader("⛓️ Blockchain Integrity Gate")
    integrity = ledger.verify_chain_integrity()
    if integrity["valid"]:
        st.success(f"Ledger Verified ({integrity['total_blocks']} Blocks)")
    else:
        st.error(integrity["reason"])

    col_t1, col_t2 = st.columns(2)
    with col_t1:
        if st.button("💥 Simulate Tamper", use_container_width=True):
            if ledger.simulate_rogue_tamper():
                st.rerun()
            else:
                st.warning("Run at least 1 scan first!")
    with col_t2:
        if st.button("🔧 Repair Chain", use_container_width=True):
            ledger.repair_chain()
            st.rerun()

if run_btn:
    if not os.path.exists(target_dir):
        st.error(f"Directory not found: {target_dir}")
    else:
        with st.spinner("Scanning Code, Dockerfile, Smart Contracts, Network Ports & Mining PoW Block..."):
            dev_scanner = DevSecOpsScanner(target_dir)
            dev_res = dev_scanner.run_full_scan()

            easm_scanner = EASMScanner(target_host=target_host, offline_demo_mode=offline_mode)
            easm_res = easm_scanner.run_full_scan(declared_ports=dev_res["declared_ports"])

            corr_res = ThreatCorrelator.correlate(dev_res, easm_res)

            mined_block = ledger.record_scan(
                target=f"{target_dir} @ {target_host}",
                findings=corr_res["all_findings"],
                risk_score=corr_res["risk_score"]
            )

            st.session_state["last_scan"] = {
                "target": f"{target_dir} ({target_host})",
                "dev_res": dev_res,
                "easm_res": easm_res,
                "corr_res": corr_res,
                "block": mined_block
            }
        st.rerun()

if "last_scan" in st.session_state:
    scan = st.session_state["last_scan"]
    corr = scan["corr_res"]
    all_findings = corr["all_findings"]
    df = pd.DataFrame(all_findings)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Unified Risk Score", f"{corr['risk_score']} / 100")
    m2.metric("Total Findings", len(all_findings))
    m3.metric("Correlated Exploit Chains", len(corr["correlated_chains"]))
    m4.metric("Sealed Block Hash", f"#{scan['block']['index']} ({scan['block']['block_hash'][:10]}...)")

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔥 Correlated Findings",
        "📊 Visual Analytics",
        "⛓️ Immutable Blockchain Ledger",
        "🔐 Token & Password Hasher",
        "📄 Executive PDF Report"
    ])

    with tab1:
        if corr["correlated_chains"]:
            st.error(f"🚨 {len(corr['correlated_chains'])} Active Inside-Out + Outside-In Exploit Chain(s) Verified!")
            for chain in corr["correlated_chains"]:
                st.warning(
                    f"**{chain['category']}** (Hash ID: `{chain['finding_hash']}`)\n\n"
                    f"{chain['issue']}\n\n*Remediation:* {chain['remediation']}"
                )

        st.subheader("All Security Findings (Plaintext Secrets Masked via SHA-256 Fingerprints)")
        st.dataframe(
            df[["finding_hash", "severity", "module", "category", "file", "line", "issue", "remediation"]],
            use_container_width=True,
            hide_index=True
        )

    with tab2:
        c1, c2 = st.columns(2)
        with c1:
            fig_sev = px.pie(
                df, names="severity", title="Findings by Severity", hole=0.4,
                color="severity",
                color_discrete_map={
                    "Critical": "#ff4b4b", "High": "#ffa421",
                    "Medium": "#faca2b", "Low": "#21c354"
                }
            )
            st.plotly_chart(fig_sev, use_container_width=True)
        with c2:
            mod_counts = df.groupby("module").size().reset_index(name="count")
            fig_mod = px.bar(
                mod_counts, x="module", y="count", color="module",
                title="Findings by Security Module"
            )
            st.plotly_chart(fig_mod, use_container_width=True)

    with tab3:
        st.subheader("Proof-of-Work Cryptographic Audit Trail (`audit_chain.json`)")
        st.info(
            "Every scan report is hashed with SHA-256 and mined into a PoW block. "
            "Use 'Simulate Tamper' in the sidebar to test tamper detection."
        )
        st.json(ledger.chain)

    with tab4:
        st.subheader("Cryptographic Credential & Token Hashing Utility (PBKDF2-HMAC-SHA256)")
        st.write(
            "Convert plaintext passwords, API tokens, or keys into salted cryptographic hashes "
            "so raw secrets are never stored in configuration files or databases."
        )
        raw_secret = st.text_input("Enter Plaintext Password / API Token / Key to Hash:", type="password")
        custom_salt = st.text_input("Optional Custom Salt (leave blank to auto-generate 16-byte cryptographic salt):")

        if st.button("Generate Cryptographic Hashes") and raw_secret:
            salt_hex = custom_salt.encode("utf-8").hex() if custom_salt else secrets.token_hex(16)
            sha256_digest = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()
            pbkdf2_digest = hashlib.pbkdf2_hmac(
                "sha256",
                raw_secret.encode("utf-8"),
                bytes.fromhex(salt_hex),
                100000
            ).hex()

            st.code(
                f"# 1. Fast Token Fingerprint (SHA-256):\n{sha256_digest}\n\n"
                f"# 2. Salted Password Storage Format (PBKDF2-HMAC-SHA256, 100k iterations):\n"
                f"pbkdf2_sha256$100000${salt_hex}${pbkdf2_digest}",
                language="bash"
            )

    with tab5:
        st.subheader("Download Signed VAPT Assessment Report")
        pdf_bytes = generate_pdf_report(
            target_name=scan["target"],
            risk_score=corr["risk_score"],
            block_record=scan["block"],
            findings=all_findings
        )
        st.download_button(
            label="📥 Download Official PDF Security Report",
            data=pdf_bytes,
            file_name="Vanguard360_VAPT_Report.pdf",
            mime="application/pdf",
            type="primary"
        )
else:
    st.info("👈 Click **'Run Full Hybrid Security Audit'** in the sidebar to scan the built-in vulnerable target offline!")