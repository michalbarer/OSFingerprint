from src.response_tests.un_test import UnusedPortUnreachableFieldTest


def test_analyze_no_unused_field():
    response_data = {}
    test = UnusedPortUnreachableFieldTest(response_data)
    result = test.analyze()
    assert result is None


def test_analyze_empty_unused_field():
    response_data = {
        "unused_field": b''
    }
    test = UnusedPortUnreachableFieldTest(response_data)
    result = test.analyze()
    assert result == 0


def test_analyze_nonzero_unused_field():
    response_data = {
        "unused_field": b'\x01\x02\x03\x04'
    }
    test = UnusedPortUnreachableFieldTest(response_data)
    result = test.analyze()
    assert result == 67305985


def test_analyze_another_nonzero_unused_field():
    response_data = {
        "unused_field": b'\xFF\xFE\xFD\xFC'
    }
    test = UnusedPortUnreachableFieldTest(response_data)
    result = test.analyze()
    assert result == 4244504319
