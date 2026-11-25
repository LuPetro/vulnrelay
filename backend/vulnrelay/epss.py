"""On-demand EPSS lookups against the FIRST API."""

import json
import re
from datetime import date

import httpx
from sqlalchemy import text
from sqlalchemy.engine import Engine

URL = "https://api.first.org/data/v1/epss"


def lookup(engine: Engine, cve_id: str, *, client: httpx.Client | None = None) -> dict | None:
    cve_id = cve_id.upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        raise ValueError("Invalid CVE identifier")
    owned = client is None
    client = client or httpx.Client(timeout=30, follow_redirects=False)
    try:
        response = client.get(URL, params={"cve": cve_id})
        response.raise_for_status()
        payload = response.json()
        if payload["status"] != "OK" or not isinstance(payload["data"], list):
            raise ValueError("Invalid EPSS response")
        rows = payload["data"]
        if not rows:
            return None
        if len(rows) != 1 or rows[0]["cve"] != cve_id:
            raise ValueError("Unexpected EPSS response")
        row = rows[0]
        score, percentile = float(row["epss"]), float(row["percentile"])
        if not 0 <= score <= 1 or not 0 <= percentile <= 1:
            raise ValueError("Invalid EPSS score")
        measured_on = date.fromisoformat(row["date"]).isoformat()
        item = {
            "id": cve_id,
            "score": score,
            "percentile": percentile,
            "measured_on": measured_on,
            "raw": json.dumps(row, sort_keys=True),
        }
        with engine.begin() as connection:
            connection.execute(
                text("""INSERT INTO epss_scores (cve_id, score, percentile, measured_on, raw)
                VALUES (:id, :score, :percentile, :measured_on, :raw)
                ON CONFLICT(cve_id) DO UPDATE SET score=excluded.score, percentile=excluded.percentile,
                measured_on=excluded.measured_on, raw=excluded.raw
                WHERE excluded.measured_on >= epss_scores.measured_on"""),
                item,
            )
            stored = (
                connection.execute(
                    text(
                        "SELECT cve_id AS id, score, percentile, measured_on, raw FROM epss_scores WHERE cve_id=:id"
                    ),
                    {"id": cve_id},
                )
                .mappings()
                .one()
            )
        return dict(stored)
    finally:
        if owned:
            client.close()
