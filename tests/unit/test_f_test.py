from src.response_tests.f_test import TCPFlagsTest

def test_tcp_flags_are_sorted():
    response_data = {
        "flags": "EAF"
    }
    test = TCPFlagsTest(response_data)
    result = test.analyze()
    assert result == "EAF"

def test_no_tcp_flags():
    response_data = {
        "flags": ""
    }
    test = TCPFlagsTest(response_data)
    result = test.analyze()
    assert result == ""

def test_tcp_flags_are_not_sorted():
    response_data = {
        "flags": "PUF"
    }
    test = TCPFlagsTest(response_data)
    result = test.analyze()
    assert result == "UPF"
