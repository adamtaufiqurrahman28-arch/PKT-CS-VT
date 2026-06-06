from __future__ import annotations

import json
import re
from typing import Any

import pandas as pd

from .vt import is_valid_sha256

DISPLAY_COLUMNS = [
    "ReadableTime",
    "FileName",
    "ObjectType",
    "SeverityName",
    "NumberOfDetections",
    "VTFound",
    "VTMalicious",
    "VTSuspicious",
    "VTObjectType",
    "VTThreatLabel",
    "ComputerName",
    "DetectName",
    "Tactic",
    "Technique",
    "ProductType",
    "Version",
]

REPORT_COLUMNS = [
    "FileName",
    "ObjectType",
    "SeverityName",
    "NumberOfDetections",
    "VTFound",
    "VTMalicious",
    "VTSuspicious",
    "VTObjectType",
    "VTThreatLabel",
    "ComputerName",
    "DetectName",
    "Tactic",
    "Technique",
]


def first_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and pd.isna(value):
        return ""
    text = str(value)
    if not text or text == "nan":
        return ""
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return ", ".join(str(x) for x in parsed[:10])
        if isinstance(parsed, dict):
            return ", ".join(f"{k}: {v}" for k, v in list(parsed.items())[:10])
    except Exception:
        pass
    return text


def infer_object_type(row: pd.Series) -> str:
    vt_label = str(row.get("VTThreatLabel", ""))
    vt_obj = str(row.get("VTObjectType", ""))
    detect = str(row.get("DetectName", ""))
    filename = str(row.get("FileName", ""))
    malicious = safe_int(row.get("VTMalicious", 0))

    corpus = " ".join([vt_label, vt_obj, detect, filename])
    if re.search(r"trojan", corpus, re.I):
        return "Trojan"
    if re.search(r"worm", corpus, re.I):
        return "Worm"
    if re.search(r"ransom", corpus, re.I):
        return "Ransomware"
    if re.search(r"phish|credential|url", corpus, re.I) or re.search(r"^https?://", filename, re.I):
        return "Phishing Link"
    if malicious > 10:
        return "Malware"
    if re.search(r"script|powershell|batch|javascript|vbs|macro|command", corpus, re.I) or re.search(r"\.(ps1|vbs|js|jse|hta|bat|cmd)$", filename, re.I):
        return "Suspicious Script"
    if re.search(r"executable|win32|pe", vt_obj, re.I) or re.search(r"\.(exe|scr|msi)$", filename, re.I):
        return "Executable"
    if re.search(r"\.dll$|rundll32\.exe", filename, re.I):
        return "DLL / LOLBIN"
    existing = str(row.get("ObjectType", ""))
    if existing and existing.lower() not in {"nan", "none"}:
        return existing
    return "Suspicious Object"


def safe_int(value: Any) -> int:
    try:
        return int(float(str(value)))
    except Exception:
        return 0


def normalize_detection_df(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame(columns=["SHA256String"] + DISPLAY_COLUMNS)

    out = df.copy()
    # Make sure expected columns exist.
    for col in ["SHA256String", "FileName", "ObjectType", "SeverityName", "NumberOfDetections"]:
        if col not in out.columns:
            out[col] = ""

    # Normalize collected fields from JSON-ish strings.
    for col in ["ReadableTime", "ComputerName", "DetectName", "Tactic", "Technique", "ProductType", "Version"]:
        if col not in out.columns:
            out[col] = ""
        out[col] = out[col].apply(first_value)

    out["SHA256String"] = out["SHA256String"].astype(str).str.strip()
    out["NumberOfDetections"] = out["NumberOfDetections"].apply(safe_int)
    out["FileName"] = out["FileName"].replace({"nan": "Unknown", "": "Unknown"})
    out["ObjectType"] = out.apply(infer_object_type, axis=1)
    return out


def build_crowdstrike_sha_csv(detections_df: pd.DataFrame, output_path) -> pd.DataFrame:
    df = normalize_detection_df(detections_df)
    cols = [
        "ReadableTime",
        "FileName",
        "SHA256String",
        "SeverityName",
        "DetectName",
        "Tactic",
        "Technique",
        "ObjectType",
        "NumberOfDetections",
        "ComputerName",
        "ProductType",
        "Version",
    ]
    for col in cols:
        if col not in df.columns:
            df[col] = ""
    out = df[cols].copy()
    # Keep only rows with SHA256 for the VT input CSV, matching your manual process.
    out = out[out["SHA256String"].apply(is_valid_sha256)]
    out.to_csv(output_path, index=False, encoding="utf-8-sig")
    return out


def merge_vt(detections_df: pd.DataFrame, vt_df: pd.DataFrame | None, vt_skipped: bool = False) -> pd.DataFrame:
    detections = normalize_detection_df(detections_df)
    if detections.empty:
        return detections

    if vt_df is not None and not vt_df.empty:
        vt = vt_df.drop_duplicates(subset=["SHA256String"]).copy()
        merged = detections.merge(vt, how="left", on="SHA256String")
    else:
        merged = detections.copy()
        for col in ["VTFound", "VTMalicious", "VTSuspicious", "VTUndetected", "VTObjectType", "VTThreatLabel"]:
            merged[col] = ""

    valid_hash_mask = merged["SHA256String"].apply(is_valid_sha256)
    if vt_skipped:
        merged["VTFound"] = "Not Checked"
    else:
        merged.loc[~valid_hash_mask, "VTFound"] = "No Hash"
        merged.loc[valid_hash_mask & merged["VTFound"].fillna("").eq(""), "VTFound"] = "Not Found"

    for col in ["VTMalicious", "VTSuspicious", "VTUndetected"]:
        merged[col] = merged[col].fillna("0").replace("", "0")
    merged["VTObjectType"] = merged["VTObjectType"].fillna("Unknown").replace("", "Unknown")
    merged["VTThreatLabel"] = merged["VTThreatLabel"].fillna("Unknown").replace("", "Unknown")
    merged["ObjectType"] = merged.apply(infer_object_type, axis=1)
    return merged


def display_df(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame(columns=DISPLAY_COLUMNS)
    for col in DISPLAY_COLUMNS:
        if col not in df.columns:
            df[col] = ""
    return df[DISPLAY_COLUMNS].copy()


def report_df(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame(columns=REPORT_COLUMNS)
    for col in REPORT_COLUMNS:
        if col not in df.columns:
            df[col] = ""
    return df[REPORT_COLUMNS].copy()
