from response_tests.base_response_test import ResponseTest


class IPDontFragmentTest(ResponseTest):
    """
    Tests whether the IP Don't Fragment (DF) bit is set in the response.
    """

    def analyze(self):
        flags = self.response_data.get("flags")

        if not flags:
            print("No flag data available, unable to determine ECN support.")
            return None

        if "DF" in flags:
            print("IP DF bit is set (Y).")
            return "Y"
        else:
            print("IP DF bit is not set (N).")
            return "N"
