from __future__ import annotations

from pkt_cs_vt_pipeline.config import load_settings
from pkt_cs_vt_pipeline.pipeline import run_pipeline


if __name__ == "__main__":
    settings = load_settings()
    result = run_pipeline(
        settings=settings,
        days=7,
        limit=100,
        max_hashes=25,
        skip_vt=False,
    )
    print("Done")
    print(f"Final CSV: {result.final_enriched_csv}")
    print(f"Report HTML: {result.report_html}")
