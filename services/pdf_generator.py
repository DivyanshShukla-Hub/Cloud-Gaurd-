import io
from datetime import datetime
from fpdf import FPDF


def clean_text(text: str) -> str:
    """Sanitizes text to safe Latin-1 for standard PDF fonts."""
    if not text:
        return ""
    replacements = {
        "\u2014": " - ",
        "\u2013": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u2022": "*",
        "\u201c": '"',
        "\u201d": '"',
        "\u2026": "...",
        "\u00a0": " ",
        "–": "-",
        "—": " - ",
        "’": "'",
        "‘": "'",
        "“": '"',
        "”": '"',
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    return text.encode("latin-1", "replace").decode("latin-1")


# Map rule names to clear security threat explanations ("what are the possibilities / what can go wrong")
THREAT_IMPACT_MAP = {
    "Public Blob Access": "Anonymous internet users can browse, read, and exfiltrate sensitive cloud data without authentication.",
    "HTTPS Not Enforced": "Traffic travels in plaintext; vulnerable to Man-in-the-Middle (MITM) network eavesdropping and packet sniffing.",
    "No Database Firewall": "Database port is exposed to the public internet; susceptible to unauthorized brute-force and DDoS attacks.",
    "Weak TLS Version": "Outdated protocols (TLS 1.0/1.1) contain known cryptographic flaws (POODLE, BEAST) allowing session hijacking.",
    "Encryption at Rest Disabled": "Stored data on disk is not encrypted with AES-256; physical compromise or unauthorized disk snapshots leak data.",
    "Default Network Rule Allow": "Permits all inbound internet traffic by default, violating least-privilege network isolation baselines.",
    "SSH Port 22 Open to Public": "Virtual machines can be directly targeted by automated botnet SSH brute-force scanners and credential stuffers.",
    "RDP Port 3389 Open to Public": "Remote Desktop is reachable over the internet; high risk of ransomware infiltration (BlueKeep, brute-force).",
    "No Storage Soft Delete": "Accidental deletion or malicious ransomware cannot be recovered, leading to irreversible data loss.",
    "Disk Encryption Disabled": "Virtual machine OS and data disks lack BitLocker/AES encryption, exposing raw file systems to offline attacks.",
    "No Automated Backups": "Lack of snapshot redundancy exposes databases to permanent data loss during outages or host corruption.",
    "No Activity Alerts": "Security-relevant operations occur unmonitored; security teams are blinded during active breach attempts.",
    "Insecure Transfer Permitted": "Data transferred over non-TLS channels can be intercepted by intermediary network proxies.",
    "Unrestricted Inbound Access": "Broad wildcard CIDR (0.0.0.0/0) allows any external host to establish direct network connectivity.",
    "Anonymous Read Allowed": "Container policy allows unrestricted anonymous access to storage containers and data objects.",
}


class AuditReportPDF(FPDF):
    def __init__(self, filename: str, scan_id: int):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.filename = clean_text(filename)
        self.scan_id = scan_id

    def header(self):
        # Top corporate header bar
        self.set_font("helvetica", "B", 13)
        self.set_text_color(15, 23, 42)  # Slate-900
        self.cell(0, 7, clean_text("CloudGuard - Cloud Infrastructure Security Audit Report"), new_x="LMARGIN", new_y="NEXT")

        self.set_font("helvetica", "", 8)
        self.set_text_color(100, 116, 139)  # Slate-500
        self.cell(0, 4, clean_text("AUTOMATED CIS BENCHMARK MISCONFIGURATION & THREAT ASSESSMENT"), new_x="LMARGIN", new_y="NEXT")

        # Subtle separator line
        self.set_draw_color(226, 232, 240)  # Slate-200
        self.set_line_width(0.4)
        self.line(10, 22, 200, 22)
        self.ln(5)

    def footer(self):
        self.set_y(-14)
        self.set_font("helvetica", "", 8)
        self.set_text_color(148, 163, 184)  # Slate-400
        # Left: timestamp, Center: page, Right: confidentiality
        self.cell(0, 10, clean_text(f"Report ID: #{self.scan_id} | Confidential Security Assessment | Page {self.page_no()} of {{nb}}"), border=0, align="C")


def generate_scan_pdf(scan: dict, findings: list, operator_email: str = "SecOps Analyst") -> bytes:
    """
    Generates a clean, professional, readable executive PDF report.
    Suitable for academic defense, compliance submission, and engineering remediation.
    """
    pdf = AuditReportPDF(scan["filename"], scan["scan_id"])
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # 1. Document Title & Assessment Metadata
    pdf.set_font("helvetica", "B", 16)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, clean_text(f"Security Assessment: {scan['filename']}"), new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(71, 85, 105)
    scan_date = clean_text(str(scan.get("scanned_at", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))))
    pdf.cell(0, 5, clean_text(f"Audited on: {scan_date[:19]} UTC | Operator: {operator_email}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # 2. Executive Summary Box (Two-column layout)
    risk_score = clean_text(scan.get("risk_score", "Clean"))
    total_findings = scan.get("total_findings", 0)

    # Box background
    pdf.set_fill_color(248, 250, 252)  # Slate-50
    pdf.set_draw_color(203, 213, 225)  # Slate-300
    pdf.rect(10, pdf.get_y(), 190, 28, style="DF")

    start_y = pdf.get_y() + 3

    # Left: Overall Status
    pdf.set_xy(14, start_y)
    pdf.set_font("helvetica", "B", 9)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(85, 4, clean_text("ASSESSMENT STATUS & POSTURE"), new_x="LMARGIN", new_y="NEXT")

    pdf.set_x(14)
    pdf.set_font("helvetica", "B", 14)
    if risk_score == "Critical":
        pdf.set_text_color(225, 29, 72)  # Rose-600
    elif risk_score == "High":
        pdf.set_text_color(217, 119, 6)   # Amber-600
    elif risk_score in ["Medium", "Low"]:
        pdf.set_text_color(2, 132, 199)   # Sky-600
    else:
        pdf.set_text_color(16, 185, 129)  # Emerald-500
    pdf.cell(85, 7, clean_text(f"{risk_score.upper()} POSTURE"), new_x="LMARGIN", new_y="NEXT")

    pdf.set_x(14)
    pdf.set_font("helvetica", "", 8.5)
    pdf.set_text_color(71, 85, 105)
    if total_findings == 0:
        pdf.cell(85, 4, clean_text("Zero security misconfigurations detected. Compliant."), new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(85, 4, clean_text(f"{total_findings} security misconfiguration(s) require remediation."), new_x="LMARGIN", new_y="NEXT")

    # Right: Severity Breakdown Badges
    pdf.set_xy(110, start_y)
    pdf.set_font("helvetica", "B", 9)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(85, 4, clean_text("SEVERITY COUNTS"), new_x="LMARGIN", new_y="NEXT")

    pdf.set_xy(110, start_y + 6)
    pdf.set_font("helvetica", "B", 9)

    # Draw 4 count boxes
    metrics = [
        ("Critical", scan.get("critical_count", 0), (225, 29, 72)),
        ("High", scan.get("high_count", 0), (217, 119, 6)),
        ("Medium", scan.get("medium_count", 0), (2, 132, 199)),
        ("Low", scan.get("low_count", 0), (100, 116, 139)),
    ]
    cur_x = 110
    for label, count, color in metrics:
        pdf.set_xy(cur_x, start_y + 6)
        pdf.set_fill_color(255, 255, 255)
        pdf.set_draw_color(color[0], color[1], color[2])
        pdf.rect(cur_x, start_y + 6, 19, 12, style="DF")

        pdf.set_xy(cur_x, start_y + 7)
        pdf.set_text_color(color[0], color[1], color[2])
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(19, 5, str(count), align="C")

        pdf.set_xy(cur_x, start_y + 12)
        pdf.set_font("helvetica", "B", 6.5)
        pdf.cell(19, 4, label.upper(), align="C")
        cur_x += 21

    pdf.set_y(start_y + 28)
    pdf.ln(4)

    # 3. Findings / Faults Section
    if findings:
        pdf.set_font("helvetica", "B", 11)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 6, clean_text(f"Identified Faults & Security Misconfigurations ({len(findings)})"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 8.5)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 4, clean_text("The following security controls failed during manifest evaluation. Immediate remediation recommended:"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        for idx, f in enumerate(findings, 1):
            rule_name = clean_text(f.get("rule_name", "Unknown Rule"))
            severity = clean_text(f.get("severity", "Medium"))
            category = clean_text(f.get("category_name", "General Security"))
            detail = clean_text(f.get("detail", "Resource misconfigured."))
            fix_guidance = clean_text(f.get("fix_guidance", "Correct configuration parameter."))
            threat = clean_text(THREAT_IMPACT_MAP.get(f.get("rule_name"), "Increases attack surface and violates baseline security compliance."))

            # Ensure finding box doesn't break awkwardly across pages
            if pdf.get_y() > 240:
                pdf.add_page()

            # Finding card outline
            card_start_y = pdf.get_y()
            pdf.set_fill_color(255, 255, 255)
            pdf.set_draw_color(203, 213, 225)

            # Severity-coded left bar
            if severity == "Critical":
                bar_color = (225, 29, 72)
            elif severity == "High":
                bar_color = (217, 119, 6)
            elif severity == "Medium":
                bar_color = (2, 132, 199)
            else:
                bar_color = (100, 116, 139)

            # Title line: [#1] Critical - Rule Name (Category)
            pdf.set_font("helvetica", "B", 10)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 6, clean_text(f"#{idx}. [{severity.upper()}] {rule_name}"), new_x="LMARGIN", new_y="NEXT")

            pdf.set_font("helvetica", "", 8)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(0, 4, clean_text(f"Control Domain: {category}"), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)

            # Block 1: The Fault / What is Wrong
            pdf.set_font("helvetica", "B", 8)
            pdf.set_text_color(185, 28, 28)  # Red
            pdf.cell(0, 4, clean_text("FAULT IDENTIFIED / WHAT IS WRONG:"), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", "", 8)
            pdf.set_text_color(30, 41, 59)
            pdf.multi_cell(180, 4, detail, new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)

            # Block 2: Potential Threat / What Can Go Wrong
            pdf.set_font("helvetica", "B", 8)
            pdf.set_text_color(194, 65, 12)  # Orange
            pdf.cell(0, 4, clean_text("SECURITY THREAT / WHAT CAN GO WRONG:"), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", "", 8)
            pdf.set_text_color(51, 65, 85)
            pdf.multi_cell(180, 4, threat, new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)

            # Block 3: Remediation / How to Fix
            pdf.set_font("helvetica", "B", 8)
            pdf.set_text_color(4, 120, 87)   # Green
            pdf.cell(0, 4, clean_text("REMEDIATION & FIX GUIDANCE:"), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", "", 8)
            pdf.set_text_color(30, 41, 59)
            pdf.multi_cell(180, 4, fix_guidance, new_x="LMARGIN", new_y="NEXT")

            # Separator line between findings
            pdf.ln(2)
            pdf.set_draw_color(226, 232, 240)
            pdf.set_line_width(0.2)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(3)

    else:
        # CLEAN ASSESSMENT SECTION
        pdf.set_fill_color(240, 253, 244)  # Green-50
        pdf.set_draw_color(187, 247, 208)  # Green-200
        pdf.rect(10, pdf.get_y(), 190, 45, style="DF")

        pdf.set_xy(15, pdf.get_y() + 4)
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(21, 128, 61)  # Green-700
        pdf.cell(0, 6, clean_text("COMPLIANCE VERIFICATION - ZERO VULNERABILITIES DETECTED"), new_x="LMARGIN", new_y="NEXT")

        pdf.set_x(15)
        pdf.set_font("helvetica", "", 8.5)
        pdf.set_text_color(22, 101, 52)
        pdf.multi_cell(180, 4.5, clean_text(
            "This manifest was evaluated against the 15 CIS Microsoft Azure Foundations benchmark rules. "
            "All tested configurations conform to production security baselines with no open internet endpoints, "
            "no unencrypted storage resources, and strict transport encryption enforced."
        ))

        pdf.ln(2)
        pdf.set_x(15)
        pdf.set_font("helvetica", "B", 8)
        pdf.cell(0, 4, clean_text("Validated Security Domains:"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 8)
        pdf.set_x(15)
        pdf.cell(0, 4, clean_text(" [x] Storage Security   [x] Database Firewall   [x] TLS 1.2+ Strict   [x] AES-256 Rest Encryption   [x] Ingress Protection"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(10)

    # 4. Standard Sign-off Block
    if pdf.get_y() > 250:
        pdf.add_page()
    pdf.ln(4)
    pdf.set_draw_color(226, 232, 240)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)
    pdf.set_font("helvetica", "I", 7.5)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 4, clean_text("Report automatically compiled by CloudGuard SecOps Platform. Evaluated against CIS Azure v1.8 Benchmark controls."), new_x="LMARGIN", new_y="NEXT")

    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()
