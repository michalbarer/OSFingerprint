from src.response_tests.s_test import TCPSequenceNumberTest


def test_analyze_no_sequence_or_ack_number():
    response_data = {}
    test = TCPSequenceNumberTest(response_data)
    result = test.analyze()
    assert result is None


def test_analyze_no_ack_number():
    response_data = {
        "response_sequence_number": 1234
    }
    test = TCPSequenceNumberTest(response_data)
    result = test.analyze()
    assert result is None


def test_analyze_no_sequence_number():
    response_data = {
        "probe_ack_number": 1234
    }
    test = TCPSequenceNumberTest(response_data)
    result = test.analyze()
    assert result is None


def test_analyze_zero_sequence_number():
    response_data = {
        "response_sequence_number": 0,
        "probe_ack_number": 1234
    }
    test = TCPSequenceNumberTest(response_data)
    result = test.analyze()
    assert result == "Z"


def test_analyze_matching_sequence_and_ack_number():
    response_data = {
        "response_sequence_number": 1234,
        "probe_ack_number": 1234
    }
    test = TCPSequenceNumberTest(response_data)
    result = test.analyze()
    assert result == "A"


def test_analyze_sequence_number_one_more_than_ack_number():
    response_data = {
        "response_sequence_number": 1235,
        "probe_ack_number": 1234
    }
    test = TCPSequenceNumberTest(response_data)
    result = test.analyze()
    assert result == "A+"


def test_analyze_other_sequence_number():
    response_data = {
        "response_sequence_number": 5678,
        "probe_ack_number": 1234
    }
    test = TCPSequenceNumberTest(response_data)
    result = test.analyze()
    assert result == "O"
