from __future__ import annotations

import csv
import re
import time
from pathlib import Path
from typing import Callable

import pandas as pd
import requests

SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def is_valid_sha256(value: object) -> bool:
    return bool(value is not None and SHA256_RE.match(str(value).strip()))


def get_vt_report(sha256: str, api_key: str) -> dict[str, str]:
    url = f"https://www.virustotal.com/api/v3/files/{sha256.strip()}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    response = requests.get(url, headers=headers, timeout=30)

    if response.status_code == 404:
        return {
            "SHA256String": sha256,
            "VTFound": "No",
            "VTMalicious": "0",
            "VTSuspicious": "0",
            "VTUndetected": "0",
            "VTObjectType": "Unknown",
            "VTThreatLabel": "Unknown",
        }

    if response.status_code == 429:
        raise RuntimeError("VirusTotal API rate limit reached. Wait a few minutes or continue later.")

    response.raise_for_status()

    attributes = response.json().get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    threat = attributes.get("popular_threat_classification", {})

    return {
        "SHA256String": sha256,
        "VTFound": "Yes",
        "VTMalicious": str(stats.get("malicious", 0)),
        "VTSuspicious": str(stats.get("suspicious", 0)),
        "VTUndetected": str(stats.get("undetected", 0)),
        "VTObjectType": str(attributes.get("type_description", "Unknown") or "Unknown"),
        "VTThreatLabel": str(threat.get("suggested_threat_label", "Unknown") or "Unknown"),
    }


def enrich_hashes(
    source_csv: Path,
    output_csv: Path,
    api_key: str,
    delay_seconds: int = 20,
    max_hashes: int = 25,
    progress: Callable[[str], None] | None = None,
) -> pd.DataFrame:
    """Read crowdstrike_sha.csv, deduplicate SHA256, lookup VirusTotal, save vt_hash_enrichment.csv."""
    if not api_key:
        raise RuntimeError("VT_API_KEY is not configured.")
    if not source_csv.exists():
        raise FileNotFoundError(f"Source CSV not found: {source_csv}")

    rows: list[dict[str, str]] = []
    seen_hashes: set[str] = set()

    with source_csv.open(newline="", encoding="utf-8-sig") as f_in:
        reader = csv.DictReader(f_in)
        for row in reader:
            sha256 = str(row.get("SHA256String", "")).strip()
            if not is_valid_sha256(sha256):
                continue
            if sha256 in seen_hashes:
                continue
            seen_hashes.add(sha256)
            if len(seen_hashes) > max_hashes:
                break

            if progress:
                progress(f"Checking VirusTotal {len(seen_hashes)}/{max_hashes}: {sha256[:12]}...")

            try:
                vt_result = get_vt_report(sha256, api_key)
            except Exception as exc:  # keep pipeline running even if VT fails
                vt_result = {
                    "SHA256String": sha256,
                    "VTFound": "Error",
                    "VTMalicious": "0",
                    "VTSuspicious": "0",
                    "VTUndetected": "0",
                    "VTObjectType": "Error",
                    "VTThreatLabel": str(exc)[:120],
                }
            rows.append(vt_result)
            time.sleep(delay_seconds)

    fieldnames = [
        "SHA256String",
        "VTFound",
        "VTMalicious",
        "VTSuspicious",
        "VTUndetected",
        "VTObjectType",
        "VTThreatLabel",
    ]
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return pd.DataFrame(rows, columns=fieldnames)
