from src.response_tests.cc_test import ExplicitCongestionNotificationTest

def test_analyze_flags_both():
    response_data = {
        "flags": ["E", "C"]
    }
    test = ExplicitCongestionNotificationTest(response_data)
    result = test.analyze()
    assert result == "S"

def test_analyze_flags_e():
    response_data = {
        "flags": ["E"]
    }
    test = ExplicitCongestionNotificationTest(response_data)
    result = test.analyze()
    assert result == "Y"

def test_analyze_flags_c():
    response_data = {
        "flags": ["C"]
    }
    test = ExplicitCongestionNotificationTest(response_data)
    result = test.analyze()
    assert result == "O"

def test_analyze_flags_n():
    response_data = {
        "flags": ["N"]
    }
    test = ExplicitCongestionNotificationTest(response_data)
    result = test.analyze()
    assert result == "N"

def test_analyze_flags_none():
    response_data = {
        "flags": []
    }
    test = ExplicitCongestionNotificationTest(response_data)
    result = test.analyze()
    assert result is None
