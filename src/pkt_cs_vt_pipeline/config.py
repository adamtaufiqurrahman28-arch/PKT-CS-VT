from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv


CLOUD_BASE_URLS = {
    "us1": "https://api.crowdstrike.com",
    "us2": "https://api.us-2.crowdstrike.com",
    "eu1": "https://api.eu-1.crowdstrike.com",
    "usgov1": "https://api.laggar.gcw.crowdstrike.com",
}


@dataclass(frozen=True)
class Settings:
    cs_base_url: str
    cs_client_id: str
    cs_client_secret: str
    cs_repository: str
    vt_api_key: str
    vt_request_delay_seconds: int
    output_dir: Path

    @property
    def falcon_configured(self) -> bool:
        return bool(self.cs_client_id and self.cs_client_secret and self.cs_repository)

    @property
    def vt_configured(self) -> bool:
        return bool(self.vt_api_key)


def normalize_base_url(value: str) -> str:
    value = (value or "us2").strip()
    if value in CLOUD_BASE_URLS:
        return CLOUD_BASE_URLS[value]
    return value.rstrip("/")


def load_settings() -> Settings:
    load_dotenv()
    output_dir = Path(os.getenv("OUTPUT_DIR", "output")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    return Settings(
        cs_base_url=normalize_base_url(os.getenv("CS_BASE_URL", "us2")),
        cs_client_id=os.getenv("CS_CLIENT_ID", "").strip(),
        cs_client_secret=os.getenv("CS_CLIENT_SECRET", "").strip(),
        cs_repository=os.getenv("CS_REPOSITORY", "search-all").strip(),
        vt_api_key=os.getenv("VT_API_KEY", "").strip(),
        vt_request_delay_seconds=int(os.getenv("VT_REQUEST_DELAY_SECONDS", "20")),
        output_dir=output_dir,
    )
