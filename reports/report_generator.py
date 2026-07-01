"""
A-ACAF Executive Report Generator
-------------------------------------------------------------------------------
Produces a board-ready PDF assurance report from audit results: executive
summary, per-agent scorecards, prioritized findings, and framework coverage.
-------------------------------------------------------------------------------
"""

import os
import sys
from datetime import datetime, timezone

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, PageBreak, HRFlowable)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---- palette ---------------------------------------------------------------
NAVY = colors.HexColor("#0f2540")
SLATE = colors.HexColor("#334155")
MUTE = colors.HexColor("#64748b")
LINE = colors.HexColor("#e2e8f0")
CRIT = colors.HexColor("#b91c1c")
HIGH = colors.HexColor("#c2410c")
MED = colors.HexColor("#a16207")
GOOD = colors.HexColor("#15803d")
BG_ALT = colors.HexColor("#f8fafc")

SEV_COLOR = {"CRITICAL": CRIT, "HIGH": HIGH, "MEDIUM": MED, "LOW": MUTE}


def _styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle("Cover", parent=s["Title"], fontSize=26, textColor=NAVY,
                         leading=30, spaceAfter=6))
    s.add(ParagraphStyle("CoverSub", parent=s["Normal"], fontSize=12, textColor=MUTE,
                         leading=16))
    s.add(ParagraphStyle("H2", parent=s["Heading2"], fontSize=14, textColor=NAVY,
                         spaceBefore=14, spaceAfter=6))
    s.add(ParagraphStyle("Body", parent=s["Normal"], fontSize=9.5, textColor=SLATE,
                         leading=14))
    s.add(ParagraphStyle("Small", parent=s["Normal"], fontSize=8, textColor=MUTE,
                         leading=11))
    s.add(ParagraphStyle("CellT", parent=s["Normal"], fontSize=8.5, textColor=SLATE,
                         leading=11))
    s.add(ParagraphStyle("CellB", parent=s["Normal"], fontSize=8.5, textColor=SLATE,
                         leading=11, fontName="Helvetica-Bold"))
    s.add(ParagraphStyle("CellW", parent=s["Normal"], fontSize=8.5,
                         textColor=colors.white, leading=11, fontName="Helvetica-Bold"))
    return s


def _score_color(score: int):
    if score >= 90: return GOOD
    if score >= 60: return MED
    return CRIT


def generate_report(results: list, out_path: str,
                    org_name: str = "Acme Corp", scope: str = "Production AI Agent Fleet"):
    S = _styles()
    doc = SimpleDocTemplate(out_path, pagesize=letter,
                            topMargin=0.7 * inch, bottomMargin=0.7 * inch,
                            leftMargin=0.75 * inch, rightMargin=0.75 * inch)
    story = []

    # ---- COVER --------------------------------------------------------------
    story.append(Spacer(1, 60))
    story.append(Paragraph("AI Agent Assurance Report", S["Cover"]))
    story.append(Paragraph("Control Assurance across NIST AI RMF, ISO/IEC 42001, "
                           "and OWASP LLM Top 10", S["CoverSub"]))
    story.append(Spacer(1, 18))
    story.append(HRFlowable(width="100%", color=LINE, thickness=1))
    story.append(Spacer(1, 14))

    fleet_avg = round(sum(r.assurance_score for r in results) / len(results)) if results else 0
    total_crit = sum(r.summary["critical"] for r in results)
    total_high = sum(r.summary["high"] for r in results)

    meta = [
        ["Organization", org_name],
        ["Assessment scope", scope],
        ["Agents assessed", str(len(results))],
        ["Report date", datetime.now(timezone.utc).strftime("%B %d, %Y")],
        ["Framework basis", "NIST AI RMF 1.0 | ISO/IEC 42001:2023 | OWASP LLM Top 10"],
    ]
    t = Table(meta, colWidths=[1.7 * inch, 4.6 * inch])
    t.setStyle(TableStyle([
        ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 9.5),
        ("FONT", (1, 0), (1, -1), "Helvetica", 9.5),
        ("TEXTCOLOR", (0, 0), (0, -1), NAVY),
        ("TEXTCOLOR", (1, 0), (1, -1), SLATE),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
    ]))
    story.append(t)
    story.append(Spacer(1, 24))

    # headline scorecard
    head = [["Fleet assurance score", "Critical findings", "High findings"],
            [f"{fleet_avg}/100", str(total_crit), str(total_high)]]
    ht = Table(head, colWidths=[2.5 * inch, 1.9 * inch, 1.9 * inch])
    ht.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, 0), "Helvetica", 9),
        ("FONT", (0, 1), (-1, 1), "Helvetica-Bold", 22),
        ("TEXTCOLOR", (0, 0), (-1, 0), MUTE),
        ("TEXTCOLOR", (0, 1), (0, 1), _score_color(fleet_avg)),
        ("TEXTCOLOR", (1, 1), (1, 1), CRIT if total_crit else GOOD),
        ("TEXTCOLOR", (2, 1), (2, 1), HIGH if total_high else GOOD),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("BACKGROUND", (0, 0), (-1, -1), BG_ALT),
    ]))
    story.append(ht)
    story.append(Spacer(1, 22))
    story.append(Paragraph(
        "This assessment evaluates deployed AI agents against a consolidated control "
        "set spanning three governance frameworks. Scoring is severity-weighted: a "
        "single critical failure (e.g. destructive access to regulated data, or absent "
        "action logging) materially lowers an agent's assurance score. Agents scoring "
        "below 90 carry gaps that should be remediated before broader deployment.",
        S["Body"]))
    story.append(PageBreak())

    # ---- EXECUTIVE SUMMARY TABLE -------------------------------------------
    story.append(Paragraph("Executive summary — fleet scorecard", S["H2"]))
    rows = [["Agent", "Environment", "Score", "Grade", "Crit", "High", "Med"]]
    for r in results:
        rows.append([
            Paragraph(r.agent_name, S["CellB"]),
            Paragraph(r.environment, S["CellT"]),
            str(r.assurance_score),
            Paragraph(r.grade.split(" - ")[0], S["CellT"]),
            str(r.summary["critical"]),
            str(r.summary["high"]),
            str(r.summary["medium"]),
        ])
    st = Table(rows, colWidths=[1.8*inch, 1.0*inch, 0.6*inch, 0.6*inch, 0.55*inch, 0.55*inch, 0.55*inch])
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8.5),
        ("FONT", (2, 1), (-1, -1), "Helvetica", 9),
        ("ALIGN", (2, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    for i, r in enumerate(results, start=1):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), BG_ALT))
        style.append(("TEXTCOLOR", (2, i), (2, i), _score_color(r.assurance_score)))
        style.append(("FONT", (2, i), (2, i), "Helvetica-Bold", 9))
    st.setStyle(TableStyle(style))
    story.append(st)
    story.append(Spacer(1, 16))

    # ---- PER-AGENT FINDINGS -------------------------------------------------
    for r in results:
        story.append(PageBreak())
        story.append(Paragraph(f"{r.agent_name}", S["H2"]))
        story.append(Paragraph(
            f"Environment: {r.environment}  &nbsp;|&nbsp;  Assurance score: "
            f"<b>{r.assurance_score}/100</b>  &nbsp;|&nbsp;  {r.grade}", S["Body"]))
        story.append(Spacer(1, 8))

        fails = r.failed()
        if not fails:
            story.append(Paragraph("No control failures. All 13 controls satisfied.", S["Body"]))
            continue

        story.append(Paragraph(f"{len(fails)} finding(s), highest severity first:", S["Small"]))
        story.append(Spacer(1, 4))

        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for f in sorted(fails, key=lambda x: order.get(x.severity, 9)):
            sev_c = SEV_COLOR.get(f.severity, MUTE)
            hdr = Table(
                [[Paragraph(f.severity, S["CellW"]),
                  Paragraph(f"{f.control_id} — {f.title}", S["CellB"])]],
                colWidths=[0.8*inch, 5.7*inch])
            hdr.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), sev_c),
                ("BACKGROUND", (1, 0), (1, 0), BG_ALT),
                ("ALIGN", (0, 0), (0, 0), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (1, 0), (1, 0), 8),
            ]))
            story.append(hdr)

            detail = [
                [Paragraph("Evidence", S["Small"]), Paragraph(f.evidence, S["CellT"])],
                [Paragraph("Business risk", S["Small"]), Paragraph(f.business_risk, S["CellT"])],
                [Paragraph("Remediation", S["Small"]), Paragraph(f.remediation, S["CellT"])],
                [Paragraph("Mapped controls", S["Small"]),
                 Paragraph(" &bull; ".join(
                     [f"NIST AI RMF: {', '.join(f.nist_ai_rmf)}",
                      f"ISO 42001: {', '.join(f.iso_42001)}",
                      f"OWASP: {', '.join(f.owasp_llm)}"]), S["Small"])],
            ]
            dt = Table(detail, colWidths=[1.1*inch, 5.4*inch])
            dt.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (0, -1), 4),
            ]))
            story.append(dt)
            story.append(Spacer(1, 10))

    # ---- footer -------------------------------------------------------------
    def _footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTE)
        canvas.drawString(0.75*inch, 0.45*inch,
                          "A-ACAF — AI Agent Control Assurance Framework  |  Synthetic assessment data")
        canvas.drawRightString(letter[0]-0.75*inch, 0.45*inch, f"Page {d.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return out_path


if __name__ == "__main__":
    from mock_data.fleet import FLEET_BEFORE
    from engine.auditor import audit_fleet
    results = audit_fleet(FLEET_BEFORE)
    out = generate_report(results, "/home/claude/agent-assurance/reports/sample_report.pdf",
                          org_name="Northwind Health (synthetic)")
    print("wrote", out)
