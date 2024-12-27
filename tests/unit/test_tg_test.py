from src.response_tests.tg_test import IPInitialTTLGuessTest


def test_analyze_no_icmp_response():
    response_data = {}
    test = IPInitialTTLGuessTest(response_data)
    result = test.analyze()
    assert result is None


def test_analyze_observed_ttl_32():
    response_data = {
        "icmp_u1_response": {"ttl": 20}
    }
    test = IPInitialTTLGuessTest(response_data)
    result = test.analyze()
    assert result == 32


def test_analyze_observed_ttl_64():
    response_data = {
        "icmp_u1_response": {"ttl": 50}
    }
    test = IPInitialTTLGuessTest(response_data)
    result = test.analyze()
    assert result == 64


def test_analyze_observed_ttl_128():
    response_data = {
        "icmp_u1_response": {"ttl": 100}
    }
    test = IPInitialTTLGuessTest(response_data)
    result = test.analyze()
    assert result == 128


def test_analyze_observed_ttl_255():
    response_data = {
        "icmp_u1_response": {"ttl": 200}
    }
    test = IPInitialTTLGuessTest(response_data)
    result = test.analyze()
    assert result == 255


def test_analyze_observed_ttl_above_255():
    response_data = {
        "icmp_u1_response": {"ttl": 300}
    }
    test = IPInitialTTLGuessTest(response_data)
    result = test.analyze()
    assert result == 255
