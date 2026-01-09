# reports/pdf_report.py
from __future__ import annotations

import os
from typing import Dict, List

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from core.models import AnalysisResult, Severity


FONT_MAIN = "ArialCyr"
FONT_BOLD = "ArialCyr-Bold"
FONT_ITALIC = "ArialCyr-Italic"

def _register_fonts() -> None:
    win_fonts = r"C:\Windows\Fonts"
    regular = os.path.join(win_fonts, "arial.ttf")
    bold = os.path.join(win_fonts, "arialbd.ttf")
    italic = os.path.join(win_fonts, "ariali.ttf")

    try:
        pdfmetrics.registerFont(TTFont(FONT_MAIN, regular))
        pdfmetrics.registerFont(TTFont(FONT_BOLD, bold))
        pdfmetrics.registerFont(TTFont(FONT_ITALIC, italic))
    except Exception as e:
        print(f"[PDF] Ошибка регистрации Arial: {e}")
        pdfmetrics.registerFont(TTFont("Helvetica", regular))



SEVERITY_ORDER: List[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

SEVERITY_TITLES: Dict[Severity, str] = {
    Severity.CRITICAL: "Critical Issues",
    Severity.HIGH: "High Issues",
    Severity.MEDIUM: "Medium Issues",
    Severity.LOW: "Low Issues",
    Severity.INFO: "Info / Low Impact",
}

SEVERITY_COLOR: Dict[Severity, colors.Color] = {
    Severity.CRITICAL: colors.Color(0.85, 0.0, 0.0),
    Severity.HIGH: colors.Color(0.85, 0.35, 0.0),
    Severity.MEDIUM: colors.Color(0.85, 0.65, 0.0),
    Severity.LOW: colors.Color(0.0, 0.55, 0.0),
    Severity.INFO: colors.Color(0.2, 0.2, 0.2),
}



def _ensure_dir_for_file(path: str) -> None:
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)


def _wrap_text(c, text, max_width, font, size):
    c.setFont(font, size)
    words = text.split()
    lines = []
    cur = ""

    for w in words:
        candidate = (cur + " " + w).strip()
        if c.stringWidth(candidate, font, size) <= max_width:
            cur = candidate
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines



def generate_pdf_report(
    analysis: AnalysisResult,
    output_path: str,
    title: str = "Android Static Analysis Report",
) -> None:
    _register_fonts()
    _ensure_dir_for_file(output_path)

    c = canvas.Canvas(output_path, pagesize=A4)
    width, height = A4

    mx = 20 * mm
    my = 20 * mm
    y = height - my
    content_w = width - 2 * mx

    def new_page():
        nonlocal y
        c.showPage()
        y = height - my

    def line(text, font=FONT_MAIN, size=10, dy=12, color=colors.black):
        nonlocal y
        if y < my + dy:
            new_page()
        c.setFont(font, size)
        c.setFillColor(color)
        c.drawString(mx, y, text)
        y -= dy

    # Header
    line(title, FONT_BOLD, 18, 26)
    line(f"APK: {analysis.apk_path}", size=10, dy=14)
    line(f"Package: {analysis.package_name}", size=10)
    line(f"App name: {analysis.app_name}", size=10)
    line(f"Version: {analysis.version_name}", size=10)

    score = analysis.risk_score()
    grade = analysis.risk_grade()
    line(f"Risk score: {score} (grade {grade})", FONT_BOLD, 11, 16)

    stats = analysis.severity_stats()
    line(
        "Findings: " +
        ", ".join(f"{s.name}: {stats.get(s, 0)}" for s in SEVERITY_ORDER),
        size=10,
        dy=14,
    )

    y -= 10
    c.line(mx, y, mx + content_w, y)
    y -= 20

    grouped = {sev: [] for sev in SEVERITY_ORDER}
    for f in analysis.findings:
        grouped[f.severity].append(f)

    for sev in SEVERITY_ORDER:
        items = grouped[sev]
        if not items:
            continue

        if y < my + 40:
            new_page()

        c.setFillColor(SEVERITY_COLOR[sev])
        c.rect(mx, y - 4, content_w, 16, fill=True, stroke=False)
        c.setFont(FONT_BOLD, 11)
        c.setFillColor(colors.white)
        c.drawString(mx + 4, y, f"{SEVERITY_TITLES[sev]} ({len(items)})")
        y -= 26

        for fnd in items:
            if y < my + 80:
                new_page()

            box_top = y
            text_lines = []

            text_lines.append((FONT_BOLD, 10, f"{fnd.analyzer}::{fnd.type}"))

            text_lines.append((FONT_MAIN, 9, f"Title: {fnd.title}"))
            if fnd.location:
                text_lines.append((FONT_MAIN, 9, f"Location: {fnd.location}"))

            desc = fnd.description.replace("\n", " ")
            for ln in _wrap_text(c, f"Desc: {desc}", content_w - 8, FONT_MAIN, 9):
                text_lines.append((FONT_MAIN, 9, ln))

            if fnd.metadata:
                meta = f"Metadata: {fnd.metadata}"
                for ln in _wrap_text(c, meta, content_w - 8, FONT_ITALIC, 8):
                    text_lines.append((FONT_ITALIC, 8, ln))

            inner_y = box_top - 6
            total_h = 0

            for font, size, text in text_lines:
                c.setFont(font, size)
                c.setFillColor(colors.black)
                c.drawString(mx + 4, inner_y, text)
                inner_y -= size + 3
                total_h += size + 3

            total_h += 6
            c.setStrokeColor(colors.grey)
            c.rect(mx, box_top - total_h, content_w, total_h, stroke=True)

            y = box_top - total_h - 10

    c.showPage()
    c.save()
