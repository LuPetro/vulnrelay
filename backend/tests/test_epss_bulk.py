import gzip

import httpx
import pytest
from sqlalchemy import text

from vulnrelay.epss_bulk import refresh


def test_daily_csv_enriches_local_records_and_rejects_corruption(configured_engine):
    with configured_engine.begin() as connection:
        connection.execute(text("INSERT INTO vulnerabilities (id,modified,nvd_raw) VALUES ('CVE-2026-1234','2026-11-12','{}')"))
    data = gzip.compress(b'#model_version:v2025.03.14,score_date:2026-11-12T00:00:00Z\ncve,epss,percentile\nCVE-2026-1234,0.75,0.99\nCVE-2026-9999,0.1,0.5\n')
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, content=data))) as client:
        assert refresh(configured_engine, client=client) == 1
    with configured_engine.connect() as connection:
        assert connection.execute(text("SELECT score FROM epss_scores")).scalar_one() == 0.75
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, content=data[:-10]))) as client, pytest.raises(EOFError):
        refresh(configured_engine, client=client)
    with configured_engine.connect() as connection:
        state = connection.execute(text("SELECT checkpoint,last_error FROM source_state WHERE source='epss'")).one()
        assert state.checkpoint == "2026-11-12"
        assert state.last_error == "EPSS refresh failed"


def test_csv_follows_only_https_same_host_redirects(configured_engine):
    with configured_engine.begin() as connection:
        connection.execute(text("INSERT INTO vulnerabilities (id,modified,nvd_raw) VALUES ('CVE-2026-1234','2026-11-12','{}')"))
    data = gzip.compress(b'#score_date:2026-11-12\ncve,epss,percentile\nCVE-2026-1234,0.1,0.2\n')
    def handler(request):
        if request.url.path.endswith('current.csv.gz'):
            return httpx.Response(302, headers={"location": "epss_scores-2026-11-12.csv.gz"})
        return httpx.Response(200, content=data)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert refresh(configured_engine, client=client) == 1
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(302, headers={"location": "http://127.0.0.1/secret"}))) as client, pytest.raises(ValueError):
        refresh(configured_engine, client=client)
