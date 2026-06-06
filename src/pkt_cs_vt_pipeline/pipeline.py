from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pandas as pd

from .config import Settings
from .data_utils import build_crowdstrike_sha_csv, merge_vt, normalize_detection_df
from .ngsiem import CrowdStrikeNGSIEMClient, save_rows_to_csv
from .queries import detection_query, hash_query
from .vt import enrich_hashes
from .reporting import generate_report_html, generate_report_md


@dataclass
class PipelineResult:
    raw_detection_csv: Path
    crowdstrike_sha_csv: Path
    vt_enrichment_csv: Path
    final_enriched_csv: Path
    report_html: Path
    report_md: Path
    dashboard_df: pd.DataFrame
    vt_df: pd.DataFrame
    logs: list[str]


def run_pipeline(
    settings: Settings,
    days: int,
    limit: int,
    max_hashes: int,
    skip_vt: bool = False,
    use_local_csv: bool = False,
    local_csv_path: str | None = None,
    timeout_seconds: int = 180,
    poll_seconds: int = 5,
    log: Callable[[str], None] | None = None,
) -> PipelineResult:
    logs: list[str] = []

    def emit(message: str) -> None:
        logs.append(message)
        if log:
            log(message)

    output_dir = settings.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    raw_detection_csv = output_dir / "crowdstrike_detection_raw.csv"
    crowdstrike_sha_csv = output_dir / "crowdstrike_sha.csv"
    vt_enrichment_csv = output_dir / "vt_hash_enrichment.csv"
    final_enriched_csv = output_dir / "final_detection_enriched.csv"
    report_html = output_dir / "report.html"
    report_md = output_dir / "report.md"

    if use_local_csv:
        if not local_csv_path:
            raise RuntimeError("Local CSV path is empty.")
        emit(f"Reading local CSV: {local_csv_path}")
        raw_df = pd.read_csv(local_csv_path, encoding="utf-8-sig")
        raw_df.to_csv(raw_detection_csv, index=False, encoding="utf-8-sig")
    else:
        if not settings.falcon_configured:
            raise RuntimeError("CrowdStrike API is not configured. Fill CS_CLIENT_ID, CS_CLIENT_SECRET, and CS_REPOSITORY in .env.")
        emit(f"Running CrowdStrike NGSIEM query for last {days} days...")
        client = CrowdStrikeNGSIEMClient(settings, timeout_seconds=timeout_seconds, poll_seconds=poll_seconds)
        # Main dashboard is based on detection query. Hash query output is created from this dataframe to avoid double query.
        rows = client.run_query(detection_query(days=days, limit=limit), start=f"{days}d")
        raw_df = save_rows_to_csv(rows, raw_detection_csv)
        emit(f"Saved raw detection CSV: {raw_detection_csv}")

    detections_df = normalize_detection_df(raw_df)
    emit(f"CrowdStrike detections loaded: {len(detections_df)}")

    sha_df = build_crowdstrike_sha_csv(detections_df, crowdstrike_sha_csv)
    emit(f"Saved CrowdStrike SHA CSV: {crowdstrike_sha_csv}")
    emit(f"Unique valid SHA256 selected for VT enrichment: {sha_df['SHA256String'].nunique() if not sha_df.empty else 0}")

    vt_df = pd.DataFrame()
    if skip_vt:
        emit("Skipping VirusTotal lookup by user option.")
    elif sha_df.empty:
        emit("Skipping VirusTotal lookup because no valid SHA256 was found.")
    else:
        emit("Running VirusTotal enrichment...")
        vt_df = enrich_hashes(
            source_csv=crowdstrike_sha_csv,
            output_csv=vt_enrichment_csv,
            api_key=settings.vt_api_key,
            delay_seconds=settings.vt_request_delay_seconds,
            max_hashes=max_hashes,
            progress=emit,
        )
        emit(f"Saved VT enrichment CSV: {vt_enrichment_csv}")

    # Make sure output exists even when VT is skipped.
    if vt_df.empty:
        vt_df.to_csv(vt_enrichment_csv, index=False, encoding="utf-8-sig")

    final_df = merge_vt(detections_df, vt_df, vt_skipped=skip_vt)
    # final CSV keeps SHA256 for audit/reconciliation. Dashboard/report hide it.
    final_df.to_csv(final_enriched_csv, index=False, encoding="utf-8-sig")
    emit(f"Saved final enriched CSV: {final_enriched_csv}")

    generate_report_html(final_df, report_html, days)
    generate_report_md(final_df, report_md, days)
    emit(f"Generated report HTML: {report_html}")
    emit(f"Generated report Markdown: {report_md}")
    emit("Done.")

    return PipelineResult(
        raw_detection_csv=raw_detection_csv,
        crowdstrike_sha_csv=crowdstrike_sha_csv,
        vt_enrichment_csv=vt_enrichment_csv,
        final_enriched_csv=final_enriched_csv,
        report_html=report_html,
        report_md=report_md,
        dashboard_df=final_df,
        vt_df=vt_df,
        logs=logs,
    )
