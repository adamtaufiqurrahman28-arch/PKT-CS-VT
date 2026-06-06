from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from pkt_cs_vt_pipeline.config import load_settings
from pkt_cs_vt_pipeline.data_utils import display_df, safe_int
from pkt_cs_vt_pipeline.pipeline import run_pipeline
from pkt_cs_vt_pipeline.queries import FINAL_QUERY_REFERENCE, detection_query, hash_query
from pkt_cs_vt_pipeline.reporting import summary

st.set_page_config(page_title="CrowdStrike Detection Lookup", layout="wide")

settings = load_settings()

st.title("CrowdStrike Detection Lookup")
st.caption("One-click NGSIEM detection query → VirusTotal enrichment → dashboard/report. SHA256 is used internally and hidden from dashboard/report.")

with st.sidebar:
    st.header("Run options")
    days = st.radio("Detection range", options=[7, 14, 100], index=0, format_func=lambda x: f"Last {x} days")
    limit = st.number_input("Max detection rows from NGSIEM", min_value=10, max_value=1000, value=100, step=10)
    max_hashes = st.number_input("Max unique SHA256 to enrich", min_value=0, max_value=500, value=25, step=5)
    skip_vt = st.checkbox("Skip VirusTotal lookup", value=False)
    timeout_seconds = st.number_input("NGSIEM timeout seconds", min_value=30, max_value=900, value=180, step=30)
    poll_seconds = st.number_input("NGSIEM poll seconds", min_value=2, max_value=60, value=5, step=1)

    st.divider()
    st.subheader("Test mode")
    use_local_csv = st.checkbox("Use local CSV instead of NGSIEM", value=False)
    local_csv_path = st.text_input("Local CSV path", value="sample_crowdstrike_sha.csv")

    st.divider()
    run = st.button("Run Full Pipeline", type="primary", use_container_width=True)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Repository", settings.cs_repository or "not set")
c2.metric("Falcon API", "configured" if settings.falcon_configured else "missing")
c3.metric("VirusTotal", "configured" if settings.vt_configured else "missing")
c4.metric("Output", str(settings.output_dir.name))

with st.expander("Show CQL used by this app"):
    st.write("Query 1 / detection extraction:")
    st.code(detection_query(days=days, limit=limit), language="text")
    st.write("Reference Query 2 / CrowdStrike lookup enrichment version:")
    st.code(FINAL_QUERY_REFERENCE.replace("__DAYS__", str(days)), language="text")

if run:
    status = st.status("Starting pipeline...", expanded=True)
    log_lines: list[str] = []

    def ui_log(message: str) -> None:
        log_lines.append(message)
        status.write(message)

    try:
        result = run_pipeline(
            settings=settings,
            days=int(days),
            limit=int(limit),
            max_hashes=int(max_hashes),
            skip_vt=skip_vt,
            use_local_csv=use_local_csv,
            local_csv_path=local_csv_path,
            timeout_seconds=int(timeout_seconds),
            poll_seconds=int(poll_seconds),
            log=ui_log,
        )
        status.update(label="Pipeline completed", state="complete", expanded=False)
        st.session_state["last_result"] = result
    except Exception as exc:
        status.update(label="Pipeline failed", state="error", expanded=True)
        st.error(f"Process failed: {exc}")
        st.stop()

result = st.session_state.get("last_result")

if result is None:
    st.info("Klik **Run Full Pipeline** untuk menjalankan proses otomatis.")
    st.stop()

final_df = result.dashboard_df.copy()
df_display = display_df(final_df)
s = summary(final_df)

st.subheader("Detection Summary")
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Detection rows", s["total_detection_rows"])
col2.metric("Detection count", s["total_detection_count"])
col3.metric("Unique object", s["total_unique_file"])
col4.metric("VT found", s["vt_found"])
col5.metric("VT malicious", s["malicious_sum"])

if final_df.empty:
    st.warning("No detection returned from CrowdStrike/local CSV. This means the NGSIEM query returned 0 row or parsing did not find table rows.")
else:
    left, right = st.columns(2)
    with left:
        st.write("Object type distribution")
        obj_counts = final_df["ObjectType"].fillna("Unknown").value_counts().reset_index()
        obj_counts.columns = ["ObjectType", "Count"]
        st.bar_chart(obj_counts.set_index("ObjectType"))
    with right:
        st.write("Severity distribution")
        sev_counts = final_df["SeverityName"].fillna("Unknown").value_counts().reset_index()
        sev_counts.columns = ["SeverityName", "Count"]
        st.bar_chart(sev_counts.set_index("SeverityName"))

    st.subheader("Detection Details")
    st.caption("SHA256 is hidden here. Internal CSV still keeps it for matching and audit.")
    st.dataframe(df_display, use_container_width=True, hide_index=True)

    st.subheader("Top detected object")
    top_obj = df_display.copy()
    top_obj["NumberOfDetections"] = top_obj["NumberOfDetections"].apply(safe_int)
    top_obj = top_obj.groupby(["FileName", "ObjectType"], as_index=False)["NumberOfDetections"].sum()
    top_obj = top_obj.sort_values("NumberOfDetections", ascending=False).head(20)
    st.dataframe(top_obj, use_container_width=True, hide_index=True)

st.subheader("Generated files")
files = [
    ("CrowdStrike detection raw CSV", result.raw_detection_csv),
    ("CrowdStrike SHA CSV", result.crowdstrike_sha_csv),
    ("VirusTotal enrichment CSV", result.vt_enrichment_csv),
    ("Final enriched CSV", result.final_enriched_csv),
    ("Report HTML", result.report_html),
    ("Report Markdown", result.report_md),
]
for label, path in files:
    if Path(path).exists():
        with open(path, "rb") as f:
            st.download_button(label=f"Download {label}", data=f.read(), file_name=Path(path).name)

with st.expander("Logs"):
    for line in result.logs:
        st.write(line)
