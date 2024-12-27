from src.response_tests.q_test import TCPMiscellaneousQuirksTest


def test_analyze_no_quirks():
    response_data = {
        "reserved_field": 0,
        "urgent_pointer": 0,
        "urg_flag_set": False
    }
    test = TCPMiscellaneousQuirksTest(response_data)
    result = test.analyze()
    assert result == ""


def test_analyze_reserved_field_quirk():
    response_data = {
        "reserved_field": 1,
        "urgent_pointer": 0,
        "urg_flag_set": False
    }
    test = TCPMiscellaneousQuirksTest(response_data)
    result = test.analyze()
    assert result == "R"


def test_analyze_urgent_pointer_quirk():
    response_data = {
        "reserved_field": 0,
        "urgent_pointer": 1,
        "urg_flag_set": False
    }
    test = TCPMiscellaneousQuirksTest(response_data)
    result = test.analyze()
    assert result == "U"


def test_analyze_both_quirks():
    response_data = {
        "reserved_field": 1,
        "urgent_pointer": 1,
        "urg_flag_set": False
    }
    test = TCPMiscellaneousQuirksTest(response_data)
    result = test.analyze()
    assert result == "RU"


def test_analyze_urgent_pointer_with_urg_flag():
    response_data = {
        "reserved_field": 0,
        "urgent_pointer": 1,
        "urg_flag_set": True
    }
    test = TCPMiscellaneousQuirksTest(response_data)
    result = test.analyze()
    assert result == ""
