from fpdf import FPDF
from typing import List, Dict, Any


class VAPTReportPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.cell(
            0, 10,
            "Vanguard360 - Executive CTEM & VAPT Security Report",
            align="C", new_x="LMARGIN", new_y="NEXT"
        )
        self.set_font("Helvetica", "I", 9)
        self.cell(
            0, 6,
            "Inside-Out DevSecOps | Outside-In EASM | SHA-256 Blockchain Sealed",
            align="C", new_x="LMARGIN", new_y="NEXT"
        )
        self.ln(4)


def clean_text(text: Any) -> str:
    """Ensures text is Latin-1 compatible for standard PDF rendering."""
    return str(text).encode("latin-1", "replace").decode("latin-1")


def generate_pdf_report(
    target_name: str,
    risk_score: int,
    block_record: Dict[str, Any],
    findings: List[Dict[str, Any]]
) -> bytes:
    pdf = VAPTReportPDF()
    pdf.add_page()

    # Executive Summary Box
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, clean_text(f"Target Audited: {target_name}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Unified Threat Exposure Score: {risk_score} / 100", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Courier", "", 9)
    pdf.cell(0, 6, f"Blockchain Block Index : #{block_record.get('index')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Timestamp (UTC)        : {block_record.get('timestamp')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Report Findings SHA256 : {block_record.get('findings_hash')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Immutable Block Hash   : {block_record.get('block_hash')}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # Detailed Findings Section
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, f"Detailed Security Findings ({len(findings)} Total)", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    for idx, item in enumerate(findings, start=1):
        pdf.set_font("Helvetica", "B", 10)
        title = clean_text(
            f"{idx}. [{item.get('severity', 'LOW').upper()}] {item.get('category')} ({item.get('module')})"
        )
        pdf.multi_cell(0, 6, title, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Courier", "", 8)
        f_hash = item.get("finding_hash", "N/A")
        pdf.multi_cell(0, 5, f"Finding SHA-256 Fingerprint: {f_hash}", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 9)
        loc = clean_text(f"Location: {item.get('file')} (Line/Port: {item.get('line')})")
        pdf.multi_cell(0, 5, loc, new_x="LMARGIN", new_y="NEXT")
        pdf.multi_cell(0, 5, clean_text(f"Issue: {item.get('issue')}"), new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "I", 9)
        pdf.multi_cell(0, 5, clean_text(f"Remediation: {item.get('remediation')}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    return bytes(pdf.output())