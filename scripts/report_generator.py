"""
GhostNet PDF Report Generator
Generates a professional threat intelligence PDF report for a single session.
Requires: reportlab
"""
import io
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

# Add paths
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'honeypot', 'analysis')))
from session_db import SessionDB

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm, cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "analysis.db"))
db = SessionDB(DB_PATH)

# ── Color palette (matching the dark cyber dashboard) ──
NAVY       = colors.HexColor("#0a0e1a")
NAVY_MID   = colors.HexColor("#111827")
CYAN       = colors.HexColor("#06b6d4")
CYAN_LIGHT = colors.HexColor("#67e8f9")
EMERALD    = colors.HexColor("#10b981")
WHITE      = colors.HexColor("#f0f9ff")
GRAY_LIGHT = colors.HexColor("#e2e8f0")
GRAY_MID   = colors.HexColor("#64748b")
GRAY_DARK  = colors.HexColor("#1e293b")

RISK_COLORS = {
    "critical": colors.HexColor("#ef4444"),
    "high":     colors.HexColor("#f97316"),
    "medium":   colors.HexColor("#eab308"),
    "low":      colors.HexColor("#22c55e"),
    "unknown":  colors.HexColor("#6b7280"),
}

KILL_CHAIN_COLORS = {
    "reconnaissance":       colors.HexColor("#8b5cf6"),
    "weaponization":        colors.HexColor("#ec4899"),
    "delivery":             colors.HexColor("#f97316"),
    "exploitation":         colors.HexColor("#ef4444"),
    "installation":         colors.HexColor("#dc2626"),
    "command & control":    colors.HexColor("#06b6d4"),
    "command and control":  colors.HexColor("#06b6d4"),
    "actions on objectives":colors.HexColor("#10b981"),
    "unknown":              colors.HexColor("#6b7280"),
}


def _make_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    styles = {}

    styles["title"] = ParagraphStyle(
        "title",
        fontName="Helvetica-Bold",
        fontSize=22,
        textColor=WHITE,
        alignment=TA_LEFT,
        spaceAfter=4,
        leading=26,
    )
    styles["subtitle"] = ParagraphStyle(
        "subtitle",
        fontName="Helvetica",
        fontSize=10,
        textColor=CYAN_LIGHT,
        alignment=TA_LEFT,
        spaceAfter=2,
    )
    styles["section_header"] = ParagraphStyle(
        "section_header",
        fontName="Helvetica-Bold",
        fontSize=11,
        textColor=CYAN,
        spaceBefore=14,
        spaceAfter=6,
        leading=14,
    )
    styles["body"] = ParagraphStyle(
        "body",
        fontName="Helvetica",
        fontSize=9,
        textColor=GRAY_DARK,
        spaceAfter=4,
        leading=14,
    )
    styles["body_white"] = ParagraphStyle(
        "body_white",
        fontName="Helvetica",
        fontSize=9,
        textColor=WHITE,
        spaceAfter=4,
        leading=14,
    )
    styles["mono"] = ParagraphStyle(
        "mono",
        fontName="Courier",
        fontSize=8,
        textColor=GRAY_DARK,
        spaceAfter=2,
        leading=12,
    )
    styles["mono_white"] = ParagraphStyle(
        "mono_white",
        fontName="Courier",
        fontSize=8,
        textColor=CYAN_LIGHT,
        spaceAfter=2,
        leading=12,
    )
    styles["label"] = ParagraphStyle(
        "label",
        fontName="Helvetica-Bold",
        fontSize=8,
        textColor=GRAY_MID,
        spaceAfter=1,
        leading=10,
    )
    styles["value"] = ParagraphStyle(
        "value",
        fontName="Helvetica",
        fontSize=9,
        textColor=GRAY_DARK,
        spaceAfter=2,
        leading=12,
    )
    return styles


def _confidence_bar(confidence: float) -> str:
    """Return a unicode bar representation of confidence."""
    pct = int(confidence * 10)
    filled = "█" * pct
    empty = "░" * (10 - pct)
    return f"{filled}{empty}  {int(confidence * 100)}%"


def generate_pdf_report(session_id: str) -> Optional[bytes]:
    """Generate a PDF report for the given session. Returns PDF bytes or None if not found."""
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError(
            "reportlab is not installed. Run: pip install reportlab"
        )

    # Fetch data
    session = db.get_session_detail(session_id)
    if not session:
        return None

    analysis = db.get_analysis(session_id)
    timeline = db.get_session_timeline(session_id)

    # Defaults if not analyzed
    risk_level = (session.get("risk_level") or "unknown").lower()
    summary = session.get("analysis_summary") or "No analysis has been run for this session."
    mitre_mapping: List[str] = analysis.get("mitre_mapping", []) if analysis else []
    iocs: List[str] = analysis.get("iocs", []) if analysis else []
    behavioral_tags: List[str] = analysis.get("behavioral_tags", []) if analysis else []
    recommendations: List[str] = analysis.get("recommendations", []) if analysis else []
    kill_chain_phase: str = (analysis.get("kill_chain_phase") or "Unknown") if analysis else "Unknown"
    confidence: float = analysis.get("confidence", 0.0) if analysis else 0.0
    intent: str = analysis.get("intent", "") if analysis else ""

    risk_color = RISK_COLORS.get(risk_level, RISK_COLORS["unknown"])
    kcp_color = KILL_CHAIN_COLORS.get(kill_chain_phase.lower(), KILL_CHAIN_COLORS["unknown"])

    # Build PDF in memory
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=f"GhostNet Threat Report — {session_id}",
        author="GhostNet Analysis Console",
    )

    S = _make_styles()
    W = doc.width
    elements = []

    # ── Header block ──────────────────────────────────────────────
    header_data = [[
        Paragraph("GHOSTNET", S["title"]),
        Paragraph(
            f'<font color="#64748b" size="8">THREAT INTELLIGENCE REPORT</font>',
            S["subtitle"],
        ),
    ]]
    header_table = Table(header_data, colWidths=[W * 0.6, W * 0.4])
    header_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("LEFTPADDING",   (0, 0), (-1, -1), 16),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 16),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 6 * mm))

    # ── Meta strip ────────────────────────────────────────────────
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    meta_data = [
        [
            Paragraph(f"<b>Session ID</b><br/><font face='Courier' size='8'>{session_id}</font>", S["body"]),
            Paragraph(f"<b>Source IP</b><br/>{session.get('ip_address', '—')}", S["body"]),
            Paragraph(f"<b>Protocol</b><br/>{session.get('protocol', '—')}", S["body"]),
            Paragraph(f"<b>Start Time</b><br/>{session.get('start_time', '—')}", S["body"]),
            Paragraph(f"<b>Generated</b><br/>{generated_at}", S["body"]),
        ]
    ]
    meta_table = Table(meta_data, colWidths=[W * 0.26, W * 0.18, W * 0.12, W * 0.22, W * 0.22])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), GRAY_LIGHT),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LINEAFTER",     (0, 0), (-2, -1), 0.5, GRAY_MID),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 4 * mm))

    # ── Risk / Confidence / Kill Chain summary bar ─────────────────
    risk_label = risk_level.upper()
    kcp_label = kill_chain_phase.title()
    conf_bar = _confidence_bar(confidence)

    summary_data = [[
        Paragraph(f'<font color="{risk_color.hexval()}" size="16"><b>{risk_label}</b></font><br/><font size="7" color="#64748b">RISK LEVEL</font>', S["body"]),
        Paragraph(f'<font color="{kcp_color.hexval()}" size="11"><b>{kcp_label}</b></font><br/><font size="7" color="#64748b">KILL CHAIN PHASE</font>', S["body"]),
        Paragraph(f'<font face="Courier" size="8" color="#06b6d4">{conf_bar}</font><br/><font size="7" color="#64748b">CONFIDENCE</font>', S["body"]),
    ]]
    summary_table = Table(summary_data, colWidths=[W * 0.22, W * 0.42, W * 0.36])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), NAVY_MID),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LINEAFTER",     (0, 0), (-2, -1), 0.5, colors.HexColor("#1e3a5f")),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 5 * mm))

    # ── Executive Summary ─────────────────────────────────────────
    elements.append(Paragraph("EXECUTIVE SUMMARY", S["section_header"]))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=CYAN, spaceAfter=4))
    if intent:
        elements.append(Paragraph(f"<b>Intent:</b> {intent}", S["body"]))
    elements.append(Paragraph(summary, S["body"]))
    elements.append(Spacer(1, 3 * mm))

    # ── Behavioral Tags ───────────────────────────────────────────
    if behavioral_tags:
        elements.append(Paragraph("BEHAVIORAL TAGS", S["section_header"]))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=CYAN, spaceAfter=4))
        tag_cells = [[Paragraph(f'<font color="#06b6d4"><b> {t.upper()} </b></font>', S["mono"]) for t in behavioral_tags]]
        tag_table = Table(tag_cells, colWidths=[W / max(len(behavioral_tags), 1)] * len(behavioral_tags))
        tag_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#0c1a30")),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("LINEAFTER",     (0, 0), (-2, -1), 0.5, colors.HexColor("#1e3a5f")),
        ]))
        elements.append(tag_table)
        elements.append(Spacer(1, 3 * mm))

    # ── MITRE ATT&CK Mapping ──────────────────────────────────────
    elements.append(Paragraph("MITRE ATT&CK MAPPING", S["section_header"]))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=CYAN, spaceAfter=4))
    if mitre_mapping:
        mitre_rows = [
            [Paragraph(f'<font face="Courier" color="#06b6d4"><b>{tech}</b></font>', S["body"]),
             Paragraph(f'<a href="https://attack.mitre.org/techniques/{tech.split(".")[0]}/">View on MITRE ATT&amp;CK →</a>', S["body"])]
            for tech in mitre_mapping
        ]
        mitre_header = [
            [Paragraph('<b>Technique ID</b>', S["label"]),
             Paragraph('<b>Reference</b>', S["label"])]
        ]
        mitre_table = Table(mitre_header + mitre_rows, colWidths=[W * 0.3, W * 0.7])
        mitre_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR",     (0, 0), (-1, 0), CYAN),
            ("BACKGROUND",    (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.HexColor("#e2e8f0")]),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("GRID",          (0, 0), (-1, -1), 0.3, GRAY_MID),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(mitre_table)
    else:
        elements.append(Paragraph("No specific MITRE ATT&CK techniques identified.", S["body"]))
    elements.append(Spacer(1, 3 * mm))

    # ── Indicators of Compromise ──────────────────────────────────
    if iocs:
        elements.append(Paragraph("INDICATORS OF COMPROMISE", S["section_header"]))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=CYAN, spaceAfter=4))
        ioc_rows = [[Paragraph(f'<font face="Courier" size="8">{ioc}</font>', S["body"])] for ioc in iocs]
        ioc_header = [[Paragraph('<b>IOC</b>', S["label"])]]
        ioc_table = Table(ioc_header + ioc_rows, colWidths=[W])
        ioc_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR",     (0, 0), (-1, 0), CYAN),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.HexColor("#e2e8f0")]),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("GRID",          (0, 0), (-1, -1), 0.3, GRAY_MID),
        ]))
        elements.append(ioc_table)
        elements.append(Spacer(1, 3 * mm))

    # ── Attack Timeline ───────────────────────────────────────────
    elements.append(Paragraph("ATTACK TIMELINE", S["section_header"]))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=CYAN, spaceAfter=4))
    if timeline:
        tl_header = [[
            Paragraph('<b>Timestamp</b>', S["label"]),
            Paragraph('<b>Type</b>', S["label"]),
            Paragraph('<b>Data</b>', S["label"]),
        ]]
        tl_rows = [
            [
                Paragraph(f'<font face="Courier" size="7">{str(e.get("timestamp",""))}</font>', S["body"]),
                Paragraph(f'<font color="#06b6d4"><b>{e.get("event_type","")}</b></font>', S["body"]),
                Paragraph(
                    f'<font face="Courier" size="8">{(str(e.get("raw_data","")) or "")[:120]}</font>',
                    S["body"]
                ),
            ]
            for e in timeline[:100]
        ]
        tl_table = Table(tl_header + tl_rows, colWidths=[W * 0.28, W * 0.13, W * 0.59])
        tl_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR",     (0, 0), (-1, 0), CYAN),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.HexColor("#e2e8f0")]),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("GRID",          (0, 0), (-1, -1), 0.3, GRAY_MID),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(tl_table)
        if len(timeline) > 100:
            elements.append(Paragraph(f"… {len(timeline) - 100} more events not shown.", S["body"]))
    else:
        elements.append(Paragraph("No events recorded for this session.", S["body"]))
    elements.append(Spacer(1, 3 * mm))

    # ── Recommendations ───────────────────────────────────────────
    if recommendations:
        elements.append(Paragraph("DEFENSIVE RECOMMENDATIONS", S["section_header"]))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=EMERALD, spaceAfter=4))
        for i, rec in enumerate(recommendations, 1):
            elements.append(Paragraph(f"<b>{i}.</b> {rec}", S["body"]))
        elements.append(Spacer(1, 3 * mm))

    # ── Footer note ───────────────────────────────────────────────
    elements.append(Spacer(1, 4 * mm))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=GRAY_MID))
    elements.append(Spacer(1, 2 * mm))
    elements.append(Paragraph(
        f"<font size='7' color='#64748b'>Generated by GhostNet Analysis Console · {generated_at} · "
        f"For authorized security research use only.</font>",
        S["body"],
    ))

    def _page_template(canvas, doc):
        canvas.saveState()
        # Top accent line
        canvas.setStrokeColor(CYAN)
        canvas.setLineWidth(2)
        canvas.line(20 * mm, A4[1] - 10 * mm, A4[0] - 20 * mm, A4[1] - 10 * mm)
        # Page number bottom right
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(GRAY_MID)
        canvas.drawRightString(A4[0] - 20 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc.build(elements, onFirstPage=_page_template, onLaterPages=_page_template)
    return buffer.getvalue()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python report_generator.py <session_id>")
        sys.exit(1)
    sid = sys.argv[1]
    pdf_bytes = generate_pdf_report(sid)
    if pdf_bytes:
        out = f"report_{sid}.pdf"
        with open(out, "wb") as f:
            f.write(pdf_bytes)
        print(f"Report saved: {out}")
    else:
        print("Session not found.")
