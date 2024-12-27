from src.response_tests.isr_test import TCPISNRateTest


def test_tcp_isn_rate_test():
    response_data = {
        "isns": [100, 200, 300, 400, 500],
        "timestamps": [1, 2, 3, 4, 5]
    }
    test = TCPISNRateTest(response_data)
    assert test.analyze() == 53


def test_tcp_isn_rate_test_insufficient_data():
    response_data = {
        "isns": [100, 200]
    }
    test = TCPISNRateTest(response_data)
    assert test.analyze() == 0


def test_tcp_isn_rate_test_zero_time_diff():
    response_data = {
        "isns": [100, 200, 300],
        "timestamps": [1, 1, 1]
    }
    test = TCPISNRateTest(response_data)
    assert test.analyze() == 0


def test_tcp_isn_rate_test_negative_time_diff():
    response_data = {
        "isns": [100, 200, 300],
        "timestamps": [3, 2, 1]
    }
    test = TCPISNRateTest(response_data)
    assert test.analyze() == 0


def test_tcp_isn_rate_test_wraparound():
    response_data = {
        "isns": [200, 100],
        "timestamps": [1, 2]
    }
    test = TCPISNRateTest(response_data)
    assert test.analyze() == 256
