from src.response_tests.gcd_test import TCPISNGCDTest


def test_analyze_insufficient_isns():
    response_data = {
        "isns": [1000]
    }
    test = TCPISNGCDTest(response_data)
    result = test.analyze()
    assert result is None


def test_analyze_no_differences():
    response_data = {
        "isns": [1000, 1000]
    }
    test = TCPISNGCDTest(response_data)
    result = test.analyze()
    assert result == 0


def test_analyze_gcd():
    response_data = {
        "isns": [1000, 2000, 3000]
    }
    test = TCPISNGCDTest(response_data)
    result = test.analyze()
    assert result == 1000


def test_analyze_gcd_with_wraparound():
    response_data = {
        "isns": [2000, 1000]
    }
    test = TCPISNGCDTest(response_data)
    result = test.analyze()
    assert result == 1000


def test_analyze_gcd_mixed_differences():
    response_data = {
        "isns": [1000, 3000, 7000, 11000]
    }
    test = TCPISNGCDTest(response_data)
    result = test.analyze()
    assert result == 2000
