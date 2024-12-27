from src.response_tests.o_tests import O1Test, O2Test, O3Test, O4Test, O5Test, O6Test


def test_analyze_no_options():
    response_data = {
        "tcp_options_1": []
    }
    test = O1Test(response_data)
    result = test.analyze()
    assert result == ""


def test_analyze_eol_option():
    response_data = {
        "tcp_options_2": [("EOL",)]
    }
    test = O2Test(response_data)
    result = test.analyze()
    assert result == "L"


def test_analyze_nop_option():
    response_data = {
        "tcp_options_3": [("NOP",)]
    }
    test = O3Test(response_data)
    result = test.analyze()
    assert result == "N"


def test_analyze_mss_option():
    response_data = {
        "tcp_options_4": [("MSS", 1460)]
    }
    test = O4Test(response_data)
    result = test.analyze()
    assert result == "M5B4"


def test_analyze_wscale_option():
    response_data = {
        "tcp_options_5": [("WScale", 7)]
    }
    test = O5Test(response_data)
    result = test.analyze()
    assert result == "W7"


def test_analyze_timestamp_option():
    response_data = {
        "tcp_options_6": [("Timestamp", (123456, 0))]
    }
    test = O6Test(response_data)
    result = test.analyze()
    assert result == "T10"


def test_analyze_sackok_option():
    response_data = {
        "tcp_options_1": [("SAckOK",)]
    }
    test = O1Test(response_data)
    result = test.analyze()
    assert result == "S"


def test_analyze_multiple_options():
    response_data = {
        "tcp_options_1": [("EOL",), ("NOP",), ("MSS", 1460), ("WScale", 7), ("Timestamp", (123456, 0)), ("SAckOK",)]
    }
    test = O1Test(response_data)
    result = test.analyze()
    assert result == "LNM5B4W7T10S"
