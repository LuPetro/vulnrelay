"""Daily FIRST EPSS CSV enrichment, avoiding use of the lookup API for bulk refresh."""

import csv
import gzip
import io
import json
import re
from datetime import UTC, date, datetime

import httpx
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
MAX_COMPRESSED = 30 * 1024 * 1024
MAX_EXPANDED = 100 * 1024 * 1024


def refresh(engine: Engine, *, client: httpx.Client | None = None) -> int:
    with engine.connect() as connection:
        wanted = {row.id for row in connection.execute(text("SELECT id FROM vulnerabilities UNION SELECT cve_id AS id FROM kev_entries"))}
    if not wanted:
        return 0
    owned = client is None
    client = client or httpx.Client(timeout=45, follow_redirects=False)
    try:
        content = bytearray()
        url = httpx.URL(URL)
        for redirect in range(3):
            with client.stream("GET", url) as response:
                if response.is_redirect and redirect < 2:
                    target = response.url.join(response.headers.get("location", ""))
                    if target.scheme != "https" or target.host != "epss.empiricalsecurity.com" or target.port not in (None, 443) or target.username:
                        raise ValueError("Unsafe EPSS redirect")
                    url = target
                    continue
                response.raise_for_status()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > MAX_COMPRESSED:
                        raise ValueError("EPSS download exceeds size limit")
                break
        with gzip.GzipFile(fileobj=io.BytesIO(content)) as archive:
            expanded = archive.read(MAX_EXPANDED + 1)
        if len(expanded) > MAX_EXPANDED:
            raise ValueError("EPSS expansion exceeds size limit")
        document = expanded.decode("utf-8-sig")
        metadata, _, data = document.partition("\n")
        timestamp = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", metadata)
        if not timestamp:
            raise ValueError("EPSS measurement date is missing")
        measured = date.fromisoformat(timestamp[1]).isoformat()
        reader = csv.DictReader(io.StringIO(data))
        if not {"cve", "epss", "percentile"}.issubset(reader.fieldnames or []):
            raise ValueError("Invalid EPSS CSV header")
        rows, seen = [], set()
        for row in reader:
            if row["cve"] not in wanted:
                continue
            if row["cve"] in seen:
                raise ValueError("Duplicate EPSS row")
            seen.add(row["cve"])
            score, percentile = float(row["epss"]), float(row["percentile"])
            if not 0 <= score <= 1 or not 0 <= percentile <= 1:
                raise ValueError("Invalid EPSS metric")
            rows.append({"id": row["cve"], "score": score, "percentile": percentile,
                         "measured": measured, "raw": json.dumps({**row, "date": measured})})
        with engine.begin() as connection:
            previous = connection.execute(text("SELECT checkpoint FROM source_state WHERE source='epss'")).scalar_one_or_none()
            if previous and measured < previous:
                raise ValueError("EPSS dataset is older than stored checkpoint")
            if rows:
                connection.execute(text('''INSERT INTO epss_scores (cve_id,score,percentile,measured_on,raw)
                    VALUES (:id,:score,:percentile,:measured,:raw) ON CONFLICT(cve_id) DO UPDATE SET
                    score=excluded.score, percentile=excluded.percentile, measured_on=excluded.measured_on,
                    raw=excluded.raw WHERE excluded.measured_on>=epss_scores.measured_on'''), rows)
            connection.execute(text('''INSERT INTO source_state (source,checkpoint,last_success_at,last_error)
                VALUES ('epss',:checkpoint,:success,NULL) ON CONFLICT(source) DO UPDATE SET
                checkpoint=excluded.checkpoint,last_success_at=excluded.last_success_at,last_error=NULL'''),
                {"checkpoint": measured, "success": datetime.now(UTC).isoformat()})
        return len(rows)
    except (httpx.HTTPError, ValueError, TypeError, KeyError, OSError, EOFError):
        try:
            with engine.begin() as connection:
                connection.execute(text("""INSERT INTO source_state (source,last_error) VALUES ('epss','EPSS refresh failed')
                    ON CONFLICT(source) DO UPDATE SET last_error=excluded.last_error"""))
        except SQLAlchemyError:
            pass
        raise
    finally:
        if owned:
            client.close()
