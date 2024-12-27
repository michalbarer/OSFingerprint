from src.response_tests.ripl_test import ReturnedProbeIPTotalLengthTest


def test_analyze_no_length():
    response_data = {}
    test = ReturnedProbeIPTotalLengthTest(response_data)
    result = test.analyze()
    assert result is None


def test_analyze_length_328():
    response_data = {
        "returned_ip_total_length": 0x148
    }
    test = ReturnedProbeIPTotalLengthTest(response_data)
    result = test.analyze()
    assert result == "G"


def test_analyze_other_length():
    response_data = {
        "returned_ip_total_length": 500
    }
    test = ReturnedProbeIPTotalLengthTest(response_data)
    result = test.analyze()
    assert result == 500
