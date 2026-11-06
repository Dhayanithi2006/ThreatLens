"""
ThreatLens Governance & Controls - Professional PDF Report Generator
Generates publication-quality, paginated PDF documents for Governance Reports
and Cross-Module Incident Investigation Dossiers using ReportLab.
"""

import io
from typing import Any, Dict, List
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas for dynamic total page count."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            super().showPage()
        super().save()

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Footer
        footer_text = f"ThreatLens GraphOps Security Platform  |  CONFIDENTIAL  |  Page {self._pageNumber} of {page_count}"
        self.drawRightString(letter[0] - 36, 20, footer_text)

        # Header rule on pages after page 1
        if self._pageNumber > 1:
            self.drawString(36, letter[1] - 25, "ThreatLens Security Dossier & Governance Report")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(36, letter[1] - 28, letter[0] - 36, letter[1] - 28)

        self.restoreState()


def _get_styles():
    base = getSampleStyleSheet()
    styles = {
        "DocTitle": ParagraphStyle(
            "DocTitle",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
        ),
        "DocSubtitle": ParagraphStyle(
            "DocSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#475569"),
        ),
        "SectionHeader": ParagraphStyle(
            "SectionHeader",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=10,
            spaceAfter=4,
        ),
        "Body": ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor("#1e293b"),
        ),
        "BodyBold": ParagraphStyle(
            "BodyBold",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor("#0f172a"),
        ),
        "Mono": ParagraphStyle(
            "Mono",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#0f172a"),
        ),
        "TableHeader": ParagraphStyle(
            "TableHeader",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white,
        ),
        "Disclaimer": ParagraphStyle(
            "Disclaimer",
            parent=base["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#78350f"),
        ),
    }
    return styles


def generate_governance_pdf(report: Dict[str, Any]) -> bytes:
    """Generates a professional PDF for a standard GovernanceReport."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    styles = _get_styles()
    story = []

    # Title & Metadata
    title = report.get("title", "ThreatLens Security Governance Report")
    report_id = report.get("report_id", "RPT-000")
    fw_scope = report.get("framework_scope", "ALL")
    gen_at = report.get("generated_at", "")[:19].replace("T", " ") + " UTC"
    gen_by = report.get("generated_by", "analyst-session")

    story.append(Paragraph(f"<b>ThreatLens Security Governance Assessment</b>", styles["DocTitle"]))
    story.append(Paragraph(f"Report ID: <b>{report_id}</b> | Framework: <b>{fw_scope}</b> | Scope: <b>{report.get('scope', 'ENTERPRISE')}</b>", styles["DocSubtitle"]))
    story.append(Paragraph(f"Generated: {gen_at} | Evaluator: {gen_by}", styles["DocSubtitle"]))
    story.append(Spacer(1, 10))

    # Summary Metrics
    summary = report.get("summary", {})
    metrics_data = [
        [
            Paragraph("Total Controls", styles["BodyBold"]),
            Paragraph("Compliant (PASS)", styles["BodyBold"]),
            Paragraph("Violations (FAIL)", styles["BodyBold"]),
            Paragraph("Needs Review", styles["BodyBold"]),
            Paragraph("Compliance %", styles["BodyBold"]),
        ],
        [
            Paragraph(str(summary.get("total_controls_assessed", 0)), styles["Body"]),
            Paragraph(f"<font color='#10b981'><b>{summary.get('passed_count', 0)}</b></font>", styles["Body"]),
            Paragraph(f"<font color='#ef4444'><b>{summary.get('failed_count', 0)}</b></font>", styles["Body"]),
            Paragraph(str(summary.get("needs_review_count", 0)), styles["Body"]),
            Paragraph(f"<font color='#0284c7'><b>{summary.get('overall_compliance_pct', 0.0)}%</b></font>", styles["Body"]),
        ],
    ]
    t_metrics = Table(metrics_data, colWidths=[108, 108, 108, 108, 108])
    t_metrics.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t_metrics)
    story.append(Spacer(1, 14))

    # Evaluations Table
    story.append(Paragraph("Policy Evaluations & Standards Alignment", styles["SectionHeader"]))
    evals = report.get("evaluations", [])

    eval_rows = [[
        Paragraph("Policy / Control", styles["TableHeader"]),
        Paragraph("Status", styles["TableHeader"]),
        Paragraph("Rule & Findings", styles["TableHeader"]),
        Paragraph("Remediation Action", styles["TableHeader"]),
    ]]

    for ev in evals:
        pol_id = ev.get("policy_id", "")
        ctrl_id = ev.get("control_id") or "N/A"
        status = ev.get("status", "")
        reason = ev.get("reasoning", "")
        rem = ev.get("recommended_remediation") or "None"

        col = "#10b981" if status == "PASS" else ("#ef4444" if status == "FAIL" else "#f59e0b")
        status_html = f"<font color='{col}'><b>{status}</b></font>"

        eval_rows.append([
            Paragraph(f"<b>{pol_id}</b><br/><font color='#64748b'>{ctrl_id}</font>", styles["Body"]),
            Paragraph(status_html, styles["Body"]),
            Paragraph(reason, styles["Body"]),
            Paragraph(rem, styles["Body"]),
        ])

    t_eval = Table(eval_rows, colWidths=[100, 60, 240, 140])
    t_eval.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_eval)
    story.append(Spacer(1, 14))

    # Disclaimer Box
    disclaimer = report.get("disclaimer", "")
    t_disc = Table([[Paragraph(f"<b>Normative Governance Notice:</b> {disclaimer}", styles["Disclaimer"])]], colWidths=[540])
    t_disc.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fffbeb")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#f59e0b")),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(t_disc)

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()


def generate_investigation_pdf(report: Dict[str, Any]) -> bytes:
    """Generates an executive, evidence-backed PDF for a cross-module InvestigationReport."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    styles = _get_styles()
    story = []

    # Title & Incident Banner
    report_id = report.get("report_id", "INV-000")
    case_id = report.get("case_id", "CASE-000")
    severity = report.get("severity", "HIGH")
    gen_at = report.get("generated_at", "")[:19].replace("T", " ") + " UTC"
    gen_by = report.get("generated_by", "analyst-session")

    story.append(Paragraph(f"<b>ThreatLens Incident Investigation &amp; Forensic Dossier</b>", styles["DocTitle"]))
    story.append(Paragraph(f"Report ID: <b>{report_id}</b> | Case ID: <b>{case_id}</b> | Severity: <b>{severity}</b>", styles["DocSubtitle"]))
    story.append(Paragraph(f"Generated: {gen_at} | Lead Analyst: {gen_by}", styles["DocSubtitle"]))
    story.append(Spacer(1, 10))

    # 1. Executive Incident Summary
    story.append(Paragraph("1. Incident Overview & Threat Classification", styles["SectionHeader"]))
    case_summary = report.get("case_summary", {})
    summary_data = [
        [
            Paragraph("<b>Subject:</b>", styles["BodyBold"]),
            Paragraph(str(case_summary.get("subject", "N/A")), styles["Body"]),
            Paragraph("<b>Recipient / Target:</b>", styles["BodyBold"]),
            Paragraph(str(case_summary.get("recipient", "N/A")), styles["Body"]),
        ],
        [
            Paragraph("<b>Primary Threat:</b>", styles["BodyBold"]),
            Paragraph(str(case_summary.get("primary_threat", "N/A")), styles["Body"]),
            Paragraph("<b>Threat Score:</b>", styles["BodyBold"]),
            Paragraph(f"<b>{case_summary.get('threat_score', 0)} / 100</b>", styles["Body"]),
        ],
        [
            Paragraph("<b>Investigation Status:</b>", styles["BodyBold"]),
            Paragraph(str(case_summary.get("status", "OPEN")), styles["Body"]),
            Paragraph("<b>Original Event Time:</b>", styles["BodyBold"]),
            Paragraph(str(case_summary.get("timestamp", "N/A"))[:19].replace("T", " "), styles["Body"]),
        ],
    ]
    t_summary = Table(summary_data, colWidths=[100, 170, 110, 160])
    t_summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 10))

    # 2. Knowledge Graph & Lateral Attack Paths
    story.append(Paragraph("2. Lateral Attack Paths & Chokepoint Analysis", styles["SectionHeader"]))
    paths = report.get("attack_paths", [])
    chokepoints = report.get("chokepoints", [])
    blast_radius = report.get("blast_radius", {})

    path_text = (
        f"Graph exploration evaluated lateral traversal up to 3 hops. "
        f"Total reachable entities: <b>{blast_radius.get('total_reachable_nodes', 0)}</b>. "
        f"Critical Crown Jewels at risk: <b>{len(blast_radius.get('critical_assets_at_risk', []))}</b>. "
        f"Identified attack paths: <b>{len(paths)}</b>. Candidate chokepoints: <b>{len(chokepoints)}</b>."
    )
    story.append(Paragraph(path_text, styles["Body"]))
    story.append(Spacer(1, 6))

    if paths:
        path_rows = [[
            Paragraph("Path ID", styles["TableHeader"]),
            Paragraph("Entry Node", styles["TableHeader"]),
            Paragraph("Target Crown Jewel", styles["TableHeader"]),
            Paragraph("Hops", styles["TableHeader"]),
            Paragraph("Path Traversal Sequence", styles["TableHeader"]),
        ]]
        for p in paths[:4]:
            pid = p.get("path_id", "p-01")
            hops = str(p.get("length", len(p.get("nodes", [])) - 1 if "nodes" in p else 1))
            seq = " → ".join(str(n.get("id", n)) if isinstance(n, dict) else str(n) for n in p.get("nodes", [])[:4])
            path_rows.append([
                Paragraph(pid, styles["BodyBold"]),
                Paragraph(str(p.get("start_node", "workstation")), styles["Body"]),
                Paragraph(str(p.get("end_node", "Crown Jewel")), styles["Body"]),
                Paragraph(hops, styles["Body"]),
                Paragraph(seq, styles["Mono"]),
            ])
        t_paths = Table(path_rows, colWidths=[60, 100, 110, 40, 230])
        t_paths.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_paths)
    story.append(Spacer(1, 10))

    # 3. Containment Simulation & What-If Impact
    sim = report.get("simulation_results", {})
    if sim:
        story.append(Paragraph("3. Containment Simulation (What-If Assessment)", styles["SectionHeader"]))
        sim_data = [
            [
                Paragraph("<b>Proposed Action:</b>", styles["BodyBold"]),
                Paragraph("Isolate Root Endpoint", styles["Body"]),
                Paragraph("<b>Containment Efficiency:</b>", styles["BodyBold"]),
                Paragraph(f"<font color='#10b981'><b>{sim.get('containment_efficiency_pct', 80.0)}%</b></font>", styles["Body"]),
            ],
            [
                Paragraph("<b>Eliminated Nodes:</b>", styles["BodyBold"]),
                Paragraph(str(sim.get("eliminated_nodes_count", 0)), styles["Body"]),
                Paragraph("<b>Remaining Crown Jewels:</b>", styles["BodyBold"]),
                Paragraph(str(sim.get("remaining_critical_assets_count", 0)), styles["Body"]),
            ],
        ]
        t_sim = Table(sim_data, colWidths=[110, 160, 130, 140])
        t_sim.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_sim)
        story.append(Spacer(1, 10))

    # 4. Chain of Custody Evidence Ledger
    story.append(Paragraph("4. Chain-of-Custody Cryptographic Evidence Ledger", styles["SectionHeader"]))
    ev_items = report.get("evidence_ledger_items", [])
    ev_rows = [[
        Paragraph("Evidence ID", styles["TableHeader"]),
        Paragraph("Type", styles["TableHeader"]),
        Paragraph("Source Subsystem", styles["TableHeader"]),
        Paragraph("Verifiable SHA-256 Digest", styles["TableHeader"]),
        Paragraph("Status", styles["TableHeader"]),
    ]]
    for item in ev_items[:6]:
        eid = item.get("evidence_id", "")
        etype = item.get("evidence_type", "")
        esrc = item.get("source", "SOC")
        ehash = item.get("sha256_hash", "")[:32] + "..."
        estat = item.get("verification_status", "VERIFIED")
        ev_rows.append([
            Paragraph(f"<b>{eid}</b>", styles["Body"]),
            Paragraph(etype, styles["Body"]),
            Paragraph(esrc, styles["Body"]),
            Paragraph(ehash, styles["Mono"]),
            Paragraph(f"<font color='#10b981'>{estat}</font>", styles["BodyBold"]),
        ])
    t_ev = Table(ev_rows, colWidths=[100, 90, 80, 210, 60])
    t_ev.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_ev)
    story.append(Spacer(1, 10))

    # 5. Governance Alignment & Policy Evaluations
    story.append(Paragraph("5. Governance Alignment & Standards Compliance", styles["SectionHeader"]))
    comps = report.get("compliance_assessments", [])
    comp_rows = [[
        Paragraph("Policy / Control", styles["TableHeader"]),
        Paragraph("Status", styles["TableHeader"]),
        Paragraph("Finding Rationale", styles["TableHeader"]),
        Paragraph("Remediation", styles["TableHeader"]),
    ]]
    for c in comps[:5]:
        pid = c.get("policy_id", "")
        cid = c.get("control_id") or "N/A"
        cstat = c.get("status", "")
        col = "#10b981" if cstat == "PASS" else ("#ef4444" if cstat == "FAIL" else "#f59e0b")
        comp_rows.append([
            Paragraph(f"<b>{pid}</b><br/><font color='#64748b'>{cid}</font>", styles["Body"]),
            Paragraph(f"<font color='{col}'><b>{cstat}</b></font>", styles["Body"]),
            Paragraph(c.get("reasoning", ""), styles["Body"]),
            Paragraph(c.get("recommended_remediation") or "None", styles["Body"]),
        ])
    t_comp = Table(comp_rows, colWidths=[90, 60, 250, 140])
    t_comp.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_comp)
    story.append(Spacer(1, 10))

    # 6. Actionable Recommendations
    story.append(Paragraph("6. Prescribed Remediation Plan", styles["SectionHeader"]))
    recs = report.get("recommendations", [])
    for idx, r in enumerate(recs, 1):
        story.append(Paragraph(f"<b>{idx}.</b> {r}", styles["Body"]))
    story.append(Spacer(1, 10))

    # Disclaimer Box
    disclaimer = report.get("disclaimer", "")
    t_disc = Table([[Paragraph(f"<b>Normative Governance &amp; Forensics Notice:</b> {disclaimer}", styles["Disclaimer"])]], colWidths=[540])
    t_disc.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fffbeb")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#f59e0b")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t_disc)

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()
