from __future__ import annotations

from pathlib import Path

import pandas as pd
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .data_utils import display_df, report_df, safe_int


def summary(df: pd.DataFrame) -> dict[str, int | str]:
    if df is None or df.empty:
        return {
            "total_detection_rows": 0,
            "total_detection_count": 0,
            "total_unique_file": 0,
            "vt_found": 0,
            "vt_not_found": 0,
            "vt_error": 0,
            "malicious_sum": 0,
            "suspicious_sum": 0,
            "top_file": "-",
        }
    total_count = int(df.get("NumberOfDetections", pd.Series(dtype=int)).apply(safe_int).sum())
    vt_found = int((df.get("VTFound", pd.Series(dtype=str)).astype(str) == "Yes").sum())
    vt_not_found = int((df.get("VTFound", pd.Series(dtype=str)).astype(str).isin(["No", "Not Found"])).sum())
    vt_error = int((df.get("VTFound", pd.Series(dtype=str)).astype(str) == "Error").sum())
    malicious_sum = int(df.get("VTMalicious", pd.Series(dtype=int)).apply(safe_int).sum())
    suspicious_sum = int(df.get("VTSuspicious", pd.Series(dtype=int)).apply(safe_int).sum())
    top_file = "-"
    if "FileName" in df.columns and not df.empty:
        top = df.sort_values("NumberOfDetections", ascending=False).iloc[0]
        top_file = str(top.get("FileName", "-"))
    return {
        "total_detection_rows": int(len(df)),
        "total_detection_count": total_count,
        "total_unique_file": int(df.get("FileName", pd.Series(dtype=str)).nunique()),
        "vt_found": vt_found,
        "vt_not_found": vt_not_found,
        "vt_error": vt_error,
        "malicious_sum": malicious_sum,
        "suspicious_sum": suspicious_sum,
        "top_file": top_file,
    }


def generate_report_html(df: pd.DataFrame, output_path: Path, days: int) -> None:
    template_dir = Path(__file__).resolve().parents[2] / "templates"
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=select_autoescape())
    template = env.get_template("report.html.j2")
    rows = report_df(df).head(100).to_dict(orient="records")
    html = template.render(summary=summary(df), rows=rows, days=days)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")


def generate_report_md(df: pd.DataFrame, output_path: Path, days: int) -> None:
    s = summary(df)
    rows = report_df(df).head(30)
    lines = [
        "# CrowdStrike Detection Report",
        "",
        f"Period: Last {days} days",
        "",
        "## Summary",
        "",
        f"- Total detection rows: {s['total_detection_rows']}",
        f"- Total detection count: {s['total_detection_count']}",
        f"- Unique detected object: {s['total_unique_file']}",
        f"- VT found: {s['vt_found']}",
        f"- VT not found: {s['vt_not_found']}",
        f"- VT error: {s['vt_error']}",
        f"- VT malicious total: {s['malicious_sum']}",
        f"- VT suspicious total: {s['suspicious_sum']}",
        f"- Top detected object: {s['top_file']}",
        "",
        "## Detection Table",
        "",
        "SHA256 is intentionally hidden from this report.",
        "",
    ]
    if rows.empty:
        lines.append("No detection data was returned.")
    else:
        lines.append(rows.to_markdown(index=False))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
