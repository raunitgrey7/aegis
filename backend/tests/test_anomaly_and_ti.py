from datetime import UTC, datetime, timedelta

from aegis.detection.anomaly import (
    DnsEntropyBaseline,
    FirstSeenBaseline,
    LoginHourBaseline,
    VolumeBaseline,
)
from aegis.schemas.events import EventType, SecurityEvent, SourceType
from aegis.threat_intel.matcher import ThreatIntelMatcher
from aegis.threat_intel.store import IOC, IOCType, ThreatIntelStore


def auth(ts, user="alice", **kw):
    return SecurityEvent(timestamp=ts, source=SourceType.WINDOWS, event_type=EventType.AUTHENTICATION,
                         action="login_success", user=user, **kw)


def test_login_hour_flags_off_hours():
    b = LoginHourBaseline(min_history=12)
    base = datetime(2026, 8, 1, 9, 0, tzinfo=UTC)
    # 20 logins at 09:00
    for d in range(20):
        assert b.observe(auth(base + timedelta(days=d))) is None
    # a 03:00 login should now be flagged
    det = b.observe(auth(base.replace(hour=3) + timedelta(days=25)))
    assert det is not None and det.rule_id == "ANOM-LOGIN-HOUR"


def test_first_seen_location():
    b = FirstSeenBaseline(min_history=5)
    base = datetime(2026, 8, 1, 9, 0, tzinfo=UTC)
    for d in range(6):
        b.observe(auth(base + timedelta(days=d), geo_country="IN", src_ip="10.0.0.5"))
    det = b.observe(auth(base + timedelta(days=7), geo_country="RU", src_ip="45.9.9.9"))
    assert det is not None and det.rule_id == "ANOM-LOGIN-LOCATION"


def test_volume_baseline_flags_spike():
    b = VolumeBaseline(min_history=20, z_threshold=3.5)
    base = datetime(2026, 8, 1, 9, 0, tzinfo=UTC)
    for i in range(30):
        b.observe(SecurityEvent(timestamp=base + timedelta(minutes=i), source="network",
                                event_type=EventType.NETWORK_CONNECTION, action="connect",
                                host="WS-1", dst_ip="8.8.8.8", bytes_out=50_000))
    det = b.observe(SecurityEvent(timestamp=base + timedelta(hours=2), source="network",
                                  event_type=EventType.NETWORK_CONNECTION, action="connect",
                                  host="WS-1", dst_ip="8.8.8.8", bytes_out=500_000_000))
    assert det is not None and det.rule_id == "ANOM-EGRESS-VOLUME"


def test_volume_baseline_ignores_sanctioned():
    b = VolumeBaseline(min_history=20, z_threshold=3.5)
    base = datetime(2026, 8, 1, 9, 0, tzinfo=UTC)
    for i in range(30):
        b.observe(SecurityEvent(timestamp=base + timedelta(minutes=i), source="network",
                                event_type=EventType.NETWORK_CONNECTION, action="connect",
                                host="WS-1", dst_ip="8.8.8.8", bytes_out=50_000))
    det = b.observe(SecurityEvent(timestamp=base + timedelta(hours=2), source="network",
                                  event_type=EventType.NETWORK_CONNECTION, action="connect",
                                  host="WS-1", dst_ip="13.107.136.9", bytes_out=500_000_000,
                                  domain="onedrive.live.com"))
    assert det is None  # sanctioned cloud is allowlisted


def test_dns_entropy():
    b = DnsEntropyBaseline()
    e = SecurityEvent(source="dns", event_type=EventType.DNS_QUERY, action="query",
                      host="WS-1", domain="a8f3k2j9x7q1w5e0r4t6y8u2i0o3p5.tunnel.example.com")
    det = b.observe(e)
    assert det is not None and det.rule_id == "ANOM-DNS-ENTROPY"


def test_threat_intel_matcher():
    store = ThreatIntelStore()
    store.add(IOC("45.155.205.233", IOCType.IP, "Cobalt Strike C2", "test", 0.95, "critical"))
    m = ThreatIntelMatcher(store)
    e = SecurityEvent(source="network", event_type=EventType.NETWORK_CONNECTION, action="connect",
                      host="WS-1", dst_ip="45.155.205.233", dst_port=443)
    dets = m.process(e)
    assert len(dets) == 1
    assert dets[0].kind.value == "threat_intel"
    assert "Cobalt Strike" in dets[0].title


def test_threat_intel_cidr_and_domain():
    store = ThreatIntelStore()
    store.add(IOC("179.43.175.0/24", IOCType.CIDR, "BPH", "test", 0.7, "high"))
    store.add(IOC("evil.example.com", IOCType.DOMAIN, "phish", "test", 0.8, "high"))
    assert store.lookup_ip("179.43.175.44") is not None
    assert store.lookup_ip("8.8.8.8") is None
    assert store.lookup_domain("sub.evil.example.com") is not None  # parent-domain walk


def test_shipped_ti_store_loads():
    from aegis.config import get_settings

    store = ThreatIntelStore.from_directory(get_settings().threat_intel_dir)
    s = store.stats()
    assert s["ips"] >= 5
    assert s["cidrs"] >= 1  # spamhaus loaded
