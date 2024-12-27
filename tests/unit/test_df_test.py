from src.response_tests.df_test import IPDontFragmentTest

def test_df_flag_set():
    response_data = {
        "df_flag_set": True
    }
    test = IPDontFragmentTest(response_data)
    result = test.analyze()
    assert result == "Y"

def test_df_flag_not_set():
    response_data = {
        "df_flag_set": False
    }
    test = IPDontFragmentTest(response_data)
    result = test.analyze()
    assert result == "N"
