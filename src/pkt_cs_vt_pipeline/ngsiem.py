from __future__ import annotations

import csv
import json
import time
from pathlib import Path
from typing import Any, Iterable

import pandas as pd
import requests

from .config import Settings


class NGSIEMError(RuntimeError):
    pass


class CrowdStrikeNGSIEMClient:
    def __init__(self, settings: Settings, timeout_seconds: int = 180, poll_seconds: int = 5):
        self.settings = settings
        self.timeout_seconds = timeout_seconds
        self.poll_seconds = poll_seconds
        self.session = requests.Session()
        self._token: str | None = None

    def authenticate(self) -> None:
        url = f"{self.settings.cs_base_url}/oauth2/token"
        data = {
            "client_id": self.settings.cs_client_id,
            "client_secret": self.settings.cs_client_secret,
        }
        response = self.session.post(url, data=data, timeout=30)
        if response.status_code >= 400:
            raise NGSIEMError(f"Falcon OAuth failed: {response.status_code} {response.text[:500]}")
        payload = response.json()
        self._token = payload.get("access_token")
        if not self._token:
            raise NGSIEMError("Falcon OAuth response did not contain access_token")
        self.session.headers.update({"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"})

    def start_search(self, query: str, start: str = "7d") -> str:
        if not self._token:
            self.authenticate()
        url = f"{self.settings.cs_base_url}/humio/api/v1/repositories/{self.settings.cs_repository}/queryjobs"
        body = {"isLive": False, "start": start, "queryString": query}
        response = self.session.post(url, json=body, timeout=60)
        if response.status_code >= 400:
            raise NGSIEMError(f"Start NGSIEM query failed: {response.status_code} {response.text[:1000]}")
        payload = response.json()
        search_id = extract_search_id(payload)
        if not search_id:
            raise NGSIEMError(f"Could not find query job id in response: {json.dumps(payload)[:1000]}")
        return search_id

    def get_status(self, search_id: str) -> dict[str, Any]:
        if not self._token:
            self.authenticate()
        url = f"{self.settings.cs_base_url}/humio/api/v1/repositories/{self.settings.cs_repository}/queryjobs/{search_id}"
        response = self.session.get(url, timeout=60)
        if response.status_code >= 400:
            raise NGSIEMError(f"Get NGSIEM query status failed: {response.status_code} {response.text[:1000]}")
        return response.json()

    def run_query(self, query: str, start: str = "7d") -> list[dict[str, Any]]:
        search_id = self.start_search(query=query, start=start)
        deadline = time.time() + self.timeout_seconds
        last_payload: dict[str, Any] = {}

        while time.time() < deadline:
            payload = self.get_status(search_id)
            last_payload = payload
            events = extract_events(payload)
            if events:
                return normalize_events(events)

            if is_query_done(payload):
                return normalize_events(extract_events(payload))

            time.sleep(self.poll_seconds)

        # Return anything we could extract before timing out; otherwise error.
        events = extract_events(last_payload)
        if events:
            return normalize_events(events)
        raise NGSIEMError("NGSIEM query timeout. Try increasing NGSIEM timeout seconds.")


def extract_search_id(payload: dict[str, Any]) -> str | None:
    candidates = [
        payload.get("id"),
        payload.get("search_id"),
        payload.get("queryJobId"),
        payload.get("jobId"),
    ]
    body = payload.get("body") if isinstance(payload.get("body"), dict) else {}
    candidates += [body.get("id"), body.get("search_id"), body.get("queryJobId"), body.get("jobId")]
    resources = payload.get("resources") or body.get("resources") or []
    if isinstance(resources, list) and resources:
        first = resources[0]
        if isinstance(first, dict):
            candidates += [first.get("id"), first.get("search_id"), first.get("queryJobId"), first.get("jobId")]
        elif isinstance(first, str):
            candidates.append(first)
    for candidate in candidates:
        if candidate:
            return str(candidate)
    return None


def extract_events(payload: Any) -> list[Any]:
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []

    keys = ["events", "results", "data", "rows"]
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return value

    body = payload.get("body")
    if isinstance(body, dict):
        for key in keys:
            value = body.get(key)
            if isinstance(value, list):
                return value

        resources = body.get("resources")
        if isinstance(resources, list):
            for item in resources:
                found = extract_events(item)
                if found:
                    return found

    resources = payload.get("resources")
    if isinstance(resources, list):
        for item in resources:
            found = extract_events(item)
            if found:
                return found

    return []


def is_query_done(payload: dict[str, Any]) -> bool:
    text = json.dumps(payload).lower()
    done_markers = ["done", "finished", "completed", "success", "closed"]
    running_markers = ["running", "started", "pending"]
    if any(marker in text for marker in done_markers) and not any(marker in text for marker in running_markers):
        return True
    meta = payload.get("metaData") or payload.get("metadata") or {}
    if isinstance(meta, dict):
        return bool(meta.get("isDone") or meta.get("done") or meta.get("closed"))
    return False


def normalize_events(events: Iterable[Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for event in events:
        if isinstance(event, dict):
            row = flatten_event(event)
            normalized.append(row)
        elif isinstance(event, list):
            # Fallback for table rows without headers.
            normalized.append({f"col_{idx}": value for idx, value in enumerate(event)})
        else:
            normalized.append({"value": event})
    return normalized


def flatten_event(event: dict[str, Any]) -> dict[str, Any]:
    # NGSIEM can return fields in different shapes depending on endpoint / table mode.
    if "fields" in event and isinstance(event["fields"], dict):
        base = dict(event["fields"])
    else:
        base = dict(event)

    # Some responses include an event string with nested key/value fields.
    if "event" in base and isinstance(base["event"], dict):
        nested = base.pop("event")
        base.update(nested)

    # Convert lists/dicts to compact JSON strings so CSV and Streamlit table stay stable.
    clean: dict[str, Any] = {}
    for key, value in base.items():
        if isinstance(value, (list, dict)):
            clean[key] = json.dumps(value, ensure_ascii=False)
        else:
            clean[key] = value
    return clean


def save_rows_to_csv(rows: list[dict[str, Any]], path: Path) -> pd.DataFrame:
    if not rows:
        df = pd.DataFrame()
        df.to_csv(path, index=False, encoding="utf-8-sig")
        return df

    df = pd.DataFrame(rows)
    df.to_csv(path, index=False, encoding="utf-8-sig")
    return df
