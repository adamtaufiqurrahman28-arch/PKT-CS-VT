from __future__ import annotations

from .config import load_settings
from .pipeline import run_pipeline

settings = load_settings()
result = run_pipeline(settings=settings, days=7, limit=100, max_hashes=25)
print("Done")
print(result.final_enriched_csv)
