from src.response_tests.a_test import TCPAcknowledgmentNumberTest

def test_analyze_ack_number_zero():
    response_data = {
        "response_ack_number": 0,
        "probe_sequence_number": 100
    }
    test = TCPAcknowledgmentNumberTest(response_data)
    result = test.analyze()
    assert result == "Z"

def test_analyze_ack_number_equal():
    response_data = {
        "response_ack_number": 100,
        "probe_sequence_number": 100
    }
    test = TCPAcknowledgmentNumberTest(response_data)
    result = test.analyze()
    assert result == "S"

def test_analyze_ack_number_plus_one():
    response_data = {
        "response_ack_number": 101,
        "probe_sequence_number": 100
    }
    test = TCPAcknowledgmentNumberTest(response_data)
    result = test.analyze()
    assert result == "S+"

def test_analyze_ack_number_other():
    response_data = {
        "response_ack_number": 200,
        "probe_sequence_number": 100
    }
    test = TCPAcknowledgmentNumberTest(response_data)
    result = test.analyze()
    assert result == "O"

def test_analyze_insufficient_data():
    response_data = {
        "response_ack_number": None,
        "probe_sequence_number": 100
    }
    test = TCPAcknowledgmentNumberTest(response_data)
    result = test.analyze()
    assert result is None