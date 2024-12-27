from src.response_tests.ripck_test import IntegrityReturnedIPChecksumTest


def test_analyze_no_checksums():
    response_data = {}
    test = IntegrityReturnedIPChecksumTest(response_data)
    result = test.analyze()
    assert result is None


def test_analyze_zero_checksum():
    response_data = {
        "ip_checksum": 1234,
        "returned_ip_checksum": 0
    }
    test = IntegrityReturnedIPChecksumTest(response_data)
    result = test.analyze()
    assert result == "Z"


def test_analyze_matching_checksums():
    response_data = {
        "ip_checksum": 1234,
        "returned_ip_checksum": 1234
    }
    test = IntegrityReturnedIPChecksumTest(response_data)
    result = test.analyze()
    assert result == "G"


def test_analyze_non_matching_checksums():
    response_data = {
        "ip_checksum": 1234,
        "returned_ip_checksum": 5678
    }
    test = IntegrityReturnedIPChecksumTest(response_data)
    result = test.analyze()
    assert result == "I"
