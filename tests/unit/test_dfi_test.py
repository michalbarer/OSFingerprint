from src.response_tests.dfi_test import ICMPDontFragmentTest


def test_df_bit_is_false():
    response_data = {
        "icmp_responses": [
            {
                "df": False,
                "probe_df": False
            },
            {
                "df": False,
                "probe_df": False
            }
        ]
    }
    test = ICMPDontFragmentTest(response_data)
    result = test.analyze()
    assert result == "N"


def test_df_bit_is_same_as_probe():
    response_data = {
        "icmp_responses": [
            {
                "df": True,
                "probe_df": True
            },
            {
                "df": False,
                "probe_df": False
            }
        ]
    }
    test = ICMPDontFragmentTest(response_data)
    result = test.analyze()
    assert result == "S"


def test_df_bit_is_true():
    response_data = {
        "icmp_responses": [
            {
                "df": True,
                "probe_df": False
            },
            {
                "df": True,
                "probe_df": False
            }
        ]
    }
    test = ICMPDontFragmentTest(response_data)
    result = test.analyze()
    assert result == "Y"


def test_df_bit_is_other():
    response_data = {
        "icmp_responses": [
            {
                "df": False,
                "probe_df": True
            },
            {
                "df": True,
                "probe_df": False
            }
        ]
    }
    test = ICMPDontFragmentTest(response_data)
    result = test.analyze()
    assert result == "O"


def test_df_flag_insufficient_responses():
    response_data = {
        "icmp_responses": [
            {
                "df": True
            }
        ]
    }
    test = ICMPDontFragmentTest(response_data)
    result = test.analyze()
    assert result is None


def test_df_flag_no_responses():
    response_data = {
        "icmp_responses": []
    }
    test = ICMPDontFragmentTest(response_data)
    result = test.analyze()
    assert result is None
