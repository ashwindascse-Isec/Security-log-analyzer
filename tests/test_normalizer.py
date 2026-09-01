from logrelay_engine.schema.normalizer import LogNormalizer


def test_normalize_single_line():
    normalizer = LogNormalizer()
    raw_log = '192.168.1.50 - - [10/Oct/2020:13:55:36 +0530] "GET /admin HTTP/1.1" 401 532 "-" "python-requests/2.28"'

    event = normalizer.normalize_line(raw_log)

    assert event is not None
    assert event.ip_address == "192.168.1.50"
    assert event.type_code == "HTTP_401"
    assert event.path == "/admin"

    # Verify BCNF lookup deduplication
    assert len(normalizer.users) == 1
    assert len(normalizer.ip_registry) == 1
    assert len(normalizer.event_types) == 1
    assert normalizer.users["anon_192_168_1_50"].access_level == "BOT"


def test_deduplication_across_multiple_lines():
    normalizer = LogNormalizer()
    log1 = '192.168.1.50 - - [10/Oct/2020:13:55:36 +0530] "GET /home HTTP/1.1" 200 102 "-" "Mozilla/5.0"'
    log2 = '192.168.1.50 - - [10/Oct/2020:13:56:01 +0530] "POST /login HTTP/1.1" 200 450 "-" "Mozilla/5.0"'

    normalizer.normalize_line(log1)
    normalizer.normalize_line(log2)

    # IP Registry and EventType should not duplicate identical entries
    assert len(normalizer.events) == 2
    assert len(normalizer.ip_registry) == 1
    assert len(normalizer.event_types) == 1