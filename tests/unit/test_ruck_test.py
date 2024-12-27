from src.response_tests.ruck_test import IntegrityReturnedUDPChecksumTest


def test_analyze_no_checksums():
    response_data = {}
    test = IntegrityReturnedUDPChecksumTest(response_data)
    result = test.analyze()
    assert result is None


def test_analyze_matching_checksums():
    response_data = {
        "udp_checksum": 1234,
        "returned_udp_checksum": 1234
    }
    test = IntegrityReturnedUDPChecksumTest(response_data)
    result = test.analyze()
    assert result == "G"


def test_analyze_non_matching_checksums():
    response_data = {
        "udp_checksum": 1234,
        "returned_udp_checksum": 5678
    }
    test = IntegrityReturnedUDPChecksumTest(response_data)
    result = test.analyze()
    assert result == 1234
