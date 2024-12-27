from src.response_tests.ts_test import TCPTimestampOptionTest


def test_analyze_insufficient_data():
    response_data = {
        "timestamp_vals": [1000],
        "timestamps": [1]
    }
    test = TCPTimestampOptionTest(response_data)
    result = test.analyze()
    assert result == "U"


def test_analyze_zero_timestamp():
    response_data = {
        "timestamp_vals": [1000, 0, 2000],
        "timestamps": [1, 2, 3]
    }
    test = TCPTimestampOptionTest(response_data)
    result = test.analyze()
    assert result == 0


def test_analyze_frequency_2hz():
    response_data = {
        "timestamp_vals": [1000, 1002, 1004],
        "timestamps": [1, 2, 3]
    }
    test = TCPTimestampOptionTest(response_data)
    result = test.analyze()
    assert result == 1


def test_analyze_frequency_100hz():
    response_data = {
        "timestamp_vals": [1000, 1100, 1200],
        "timestamps": [1, 2, 3]
    }
    test = TCPTimestampOptionTest(response_data)
    result = test.analyze()
    assert result == 7


def test_analyze_frequency_200hz():
    response_data = {
        "timestamp_vals": [1000, 1200, 1400],
        "timestamps": [1, 2, 3]
    }
    test = TCPTimestampOptionTest(response_data)
    result = test.analyze()
    assert result == 8


def test_analyze_logarithmic_rate():
    response_data = {
        "timestamp_vals": [1000, 2000, 4000],
        "timestamps": [1, 2, 3]
    }
    test = TCPTimestampOptionTest(response_data)
    result = test.analyze()
    assert result == 11
