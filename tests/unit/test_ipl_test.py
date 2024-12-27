from src.response_tests.ipl_test import IPTotalLengthTest


def test_ipl_test():
    test = IPTotalLengthTest(response_data={"ip_total_length": 20})
    assert test.analyze() == 20


def test_ipl_test_no_data():
    test = IPTotalLengthTest(response_data={})
    assert test.analyze() is None
