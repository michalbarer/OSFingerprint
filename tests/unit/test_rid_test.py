from src.response_tests.rid_test import ReturnedProbeIPIDValueTest

def test_analyze_no_ip_id():
    response_data = {}
    test = ReturnedProbeIPIDValueTest(response_data)
    result = test.analyze()
    assert result is None

def test_analyze_ip_id_1042():
    response_data = {
        "returned_ip_id": 1042
    }
    test = ReturnedProbeIPIDValueTest(response_data)
    result = test.analyze()
    assert result == "G"

def test_analyze_ip_id_4210():
    response_data = {
        "returned_ip_id": 4210
    }
    test = ReturnedProbeIPIDValueTest(response_data)
    result = test.analyze()
    assert result == 0x4210

def test_analyze_other_ip_id():
    response_data = {
        "returned_ip_id": 1234
    }
    test = ReturnedProbeIPIDValueTest(response_data)
    result = test.analyze()
    assert result == 1234
