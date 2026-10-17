"""Unit and integration tests for passive security evidence collectors and manager."""

from typing import Any, Dict, List, Optional
from app.schemas.evidence import EvidenceCollectionStatus, EvidenceItemCreate
from app.services.collector import BaseCollector, CollectorManager
from app.services.passive_analyzer import PassiveUrlAnalyzer


class FaultyTestCollector(BaseCollector):
    """Collector that intentionally raises an exception to verify error containment."""

    @property
    def name(self) -> str:
        return "faulty_test_collector"

    def collect(self, url: str, context: Optional[Dict[str, Any]] = None) -> List[EvidenceItemCreate]:
        raise RuntimeError("Simulated internal collector failure")


def test_passive_analyzer_https_standard_domain() -> None:
    """Verify passive analysis of a standard HTTPS domain URL."""
    analyzer = PassiveUrlAnalyzer()
    url = "https://sub.portal.example.com/dashboard/home"
    evidence = analyzer.collect(url)

    signals = {e.signal_name: e for e in evidence}

    # 1. url_scheme
    assert "url_scheme" in signals
    scheme_item = signals["url_scheme"]
    assert scheme_item.collection_status == EvidenceCollectionStatus.OBSERVED
    assert scheme_item.observed_value == "https"
    assert scheme_item.structured_data["is_tls_encrypted"] is True

    # 2. hostname_type
    assert "hostname_type" in signals
    host_item = signals["hostname_type"]
    assert host_item.collection_status == EvidenceCollectionStatus.OBSERVED
    assert host_item.observed_value == "domain_name"
    assert host_item.structured_data["is_ip_literal"] is False

    # 3. tld_identifier
    assert "tld_identifier" in signals
    tld_item = signals["tld_identifier"]
    assert tld_item.collection_status == EvidenceCollectionStatus.OBSERVED
    assert tld_item.observed_value == "com"

    # 4. subdomain_depth
    assert "subdomain_depth" in signals
    depth_item = signals["subdomain_depth"]
    assert depth_item.collection_status == EvidenceCollectionStatus.OBSERVED
    # sub.portal.example.com has 4 parts -> 4 - 2 = 2
    assert depth_item.observed_value == "2"

    # 5. explicit_port: absent because none was specified
    assert "explicit_port" in signals
    port_item = signals["explicit_port"]
    assert port_item.collection_status == EvidenceCollectionStatus.ABSENT
    assert port_item.observed_value is None

    # 6. sensitive_lexical_tokens: absent
    assert "sensitive_lexical_tokens" in signals
    assert signals["sensitive_lexical_tokens"].collection_status == EvidenceCollectionStatus.ABSENT


def test_passive_analyzer_http_ipv4_with_explicit_port_and_tokens() -> None:
    """Verify passive analysis of an unencrypted HTTP URL with IP literal, port, and sensitive tokens."""
    analyzer = PassiveUrlAnalyzer()
    url = "http://192.168.1.50:8443/admin/login?token=abc"
    evidence = analyzer.collect(url)

    signals = {e.signal_name: e for e in evidence}

    # Scheme
    assert signals["url_scheme"].observed_value == "http"
    assert signals["url_scheme"].structured_data["is_tls_encrypted"] is False

    # Hostname: IP literal
    assert signals["hostname_type"].observed_value == "ipv4_literal"
    assert signals["hostname_type"].structured_data["is_ip_literal"] is True
    assert signals["hostname_type"].structured_data["is_private"] is True

    # TLD absent for IP literal
    assert signals["tld_identifier"].collection_status == EvidenceCollectionStatus.ABSENT

    # Explicit port
    assert signals["explicit_port"].collection_status == EvidenceCollectionStatus.OBSERVED
    assert signals["explicit_port"].observed_value == "8443"
    assert signals["explicit_port"].structured_data["is_standard_web_port"] is False

    # Sensitive lexical tokens observed
    token_item = signals["sensitive_lexical_tokens"]
    assert token_item.collection_status == EvidenceCollectionStatus.OBSERVED
    assert "admin" in token_item.observed_value
    assert "login" in token_item.observed_value
    assert "token" in token_item.observed_value
    # Explanatory notes should be factual, not an assertion of malice
    assert "malicious intent" in token_item.explanatory_notes.lower()


def test_collector_manager_error_isolation() -> None:
    """Verify that a failing collector does not halt execution and is recorded as ERROR evidence."""
    manager = CollectorManager()
    manager.register(PassiveUrlAnalyzer())
    manager.register(FaultyTestCollector())

    assert len(manager.registered_collectors) == 2

    # Run all collectors on a test URL
    results = manager.run_all("https://example.com/test")

    # Should contain items from PassiveUrlAnalyzer plus error record from FaultyTestCollector
    error_items = [r for r in results if r.collection_status == EvidenceCollectionStatus.ERROR]
    assert len(error_items) == 1
    err = error_items[0]
    assert err.signal_name == "faulty_test_collector_execution_status"
    assert err.evidence_source == "faulty_test_collector"
    assert "Simulated internal collector failure" in err.structured_data["error_message"]

    # Verify normal evidence was also collected
    observed_items = [r for r in results if r.collection_status == EvidenceCollectionStatus.OBSERVED]
    assert len(observed_items) > 0
