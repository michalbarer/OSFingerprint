from response_tests.base_response_test import ResponseTest


class IPDontFragmentTest(ResponseTest):
    """
    Tests whether the IP Don't Fragment (DF) bit is set in the response.
    """
    def analyze(self):
        is_df_flag_set = self.response_data.get("df_flag_set")
        return "Y" if is_df_flag_set else "N"
