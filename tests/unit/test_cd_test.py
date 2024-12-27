from src.response_tests.cd_test import ICMPResponseCodeTest

def test_analyze_codes_zero():
    response_data = {
        "icmp_responses": [
            {"response_code": 0, "probe_code": 0},
            {"response_code": 0, "probe_code": 0}
        ]
    }
    test = ICMPResponseCodeTest(response_data)
    result = test.analyze()
    assert result == "Z"

def test_analyze_codes_same():
    response_data = {
        "icmp_responses": [
            {"response_code": 3, "probe_code": 3},
            {"response_code": 4, "probe_code": 4}
        ]
    }
    test = ICMPResponseCodeTest(response_data)
    result = test.analyze()
    assert result == "S"

def test_analyze_codes_same_non_zero():
    res_code = 3
    response_data = {
        "icmp_responses": [
            {"response_code": res_code, "probe_code": 3},
            {"response_code": res_code, "probe_code": 4}
        ]
    }
    test = ICMPResponseCodeTest(response_data)
    result = test.analyze()
    assert result == str(res_code)

def test_analyze_codes_different():
    response_data = {
        "icmp_responses": [
            {"response_code": 3, "probe_code": 4},
            {"response_code": 4, "probe_code": 4}
        ]
    }
    test = ICMPResponseCodeTest(response_data)
    result = test.analyze()
    assert result == "O"

def test_analyze_insufficient_responses():
    response_data = {
        "icmp_responses": [
            {"response_code": 3, "probe_code": 3}
        ]
    }
    test = ICMPResponseCodeTest(response_data)
    result = test.analyze()
    assert result is None

def test_analyze_no_responses():
    response_data = {
        "icmp_responses": []
    }
    test = ICMPResponseCodeTest(response_data)
    result = test.analyze()
    assert result is None
