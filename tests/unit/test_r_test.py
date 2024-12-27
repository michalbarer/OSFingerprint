from src.response_tests.r_test import ResponsivenessTest

def test_analyze_response_received():
    response_data = {
        "response_received": True
    }
    test = ResponsivenessTest(response_data)
    result = test.analyze()
    assert result == "Y"

def test_analyze_no_response_received():
    response_data = {
        "response_received": False
    }
    test = ResponsivenessTest(response_data)
    result = test.analyze()
    assert result == "N"

def test_analyze_response_received_missing_key():
    response_data = {}
    test = ResponsivenessTest(response_data)
    result = test.analyze()
    assert result == "N"
