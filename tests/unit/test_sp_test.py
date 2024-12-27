from src.response_tests.sp_test import TCPISNSequencePredictabilityTest


def test_analyze_insufficient_isns():
    response_data = {
        "isns": [1000, 2000, 3000],
        "timestamps": [1, 2, 3]
    }
    test = TCPISNSequencePredictabilityTest(response_data, gcd_value=10)
    result = test.analyze()
    assert result is None


def test_analyze_mismatched_timestamps():
    response_data = {
        "isns": [1000, 2000, 3000, 4000],
        "timestamps": [1, 2, 3]
    }
    test = TCPISNSequencePredictabilityTest(response_data, gcd_value=10)
    result = test.analyze()
    assert result is None


def test_analyze_zero_time_difference():
    response_data = {
        "isns": [1000, 2000, 3000, 4000],
        "timestamps": [1, 1, 2, 3]
    }
    test = TCPISNSequencePredictabilityTest(response_data, gcd_value=10)
    result = test.analyze()
    assert result is not None


def test_analyze_standard_deviation_error():
    response_data = {
        "isns": [1000, 2000, 3000, 4000],
        "timestamps": [1, 2, 3, 4]
    }
    test = TCPISNSequencePredictabilityTest(response_data, gcd_value=10)
    result = test.analyze()
    assert result is not None


def test_analyze_low_standard_deviation():
    response_data = {
        "isns": [1000, 2001, 3002, 4003],
        "timestamps": [1, 2, 3, 4]
    }
    test = TCPISNSequencePredictabilityTest(response_data, gcd_value=1)
    result = test.analyze()
    assert result == 0


def test_analyze_high_standard_deviation():
    response_data = {
        "isns": [1000, 3000, 6000, 10000],
        "timestamps": [1, 2, 3, 4]
    }
    test = TCPISNSequencePredictabilityTest(response_data, gcd_value=1)
    result = test.analyze()
    assert result > 0
