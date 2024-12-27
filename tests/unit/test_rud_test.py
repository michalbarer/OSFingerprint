from scapy.packet import Raw

from src.response_tests.rud_test import IntegrityReturnedUDPDataTest


def test_analyze_no_payload():
    response_data = {}
    test = IntegrityReturnedUDPDataTest(response_data)
    result = test.analyze()
    assert result == "I"


def test_analyze_matching_payload():
    response_data = {
        "udp_payload": Raw(b"\x43" * 10)
    }
    test = IntegrityReturnedUDPDataTest(response_data)
    result = test.analyze()
    assert result == "G"


def test_analyze_truncated_payload():
    response_data = {
        "udp_payload": Raw(b"")
    }
    test = IntegrityReturnedUDPDataTest(response_data)
    result = test.analyze()
    assert result == "G"


def test_analyze_non_matching_payload():
    response_data = {
        "udp_payload": Raw(b"\x43\x44\x45")
    }
    test = IntegrityReturnedUDPDataTest(response_data)
    result = test.analyze()
    assert result == "I"
