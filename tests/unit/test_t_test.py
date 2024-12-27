from src.response_tests.t_test import IPInitialTTLTest


def test_analyze_no_icmp_response():
    response_data = {
        "sent_ttl": 64
    }
    test = IPInitialTTLTest(response_data)
    result = test.analyze()
    assert result is None


def test_analyze_no_ttl_in_icmp_response():
    response_data = {
        "icmp_u1_response": {},
        "sent_ttl": 64
    }
    test = IPInitialTTLTest(response_data)
    result = test.analyze()
    assert result is None


def test_analyze_negative_hop_distance():
    response_data = {
        "icmp_u1_response": {"ttl": 70},
        "sent_ttl": 64
    }
    test = IPInitialTTLTest(response_data)
    result = test.analyze()
    assert result is None


def test_analyze_valid_ttl():
    response_data = {
        "icmp_u1_response": {"ttl": 50},
        "sent_ttl": 64
    }
    test = IPInitialTTLTest(response_data)
    result = test.analyze()
    assert result == 64


def test_analyze_valid_ttl_with_hop_distance():
    response_data = {
        "icmp_u1_response": {"ttl": 30},
        "sent_ttl": 64
    }
    test = IPInitialTTLTest(response_data)
    result = test.analyze()
    assert result == 64
