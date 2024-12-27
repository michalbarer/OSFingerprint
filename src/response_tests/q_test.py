from src.response_tests.base_response_test import ResponseTest


class TCPMiscellaneousQuirksTest(ResponseTest):
    """
    TCP Miscellaneous Quirks (Q) Test.
    This test checks for two specific quirks in the TCP stack:
    - A nonzero reserved field in the TCP header.
    - A nonzero urgent pointer value when the URG flag is not set.
    """

    def analyze(self):
        """
        Analyzes the response data for TCP quirks and generates the Q string.
        """
        reserved_field = self.response_data.get("reserved_field", 0)
        urgent_pointer = self.response_data.get("urgent_pointer", 0)
        urg_flag_set = self.response_data.get("urg_flag_set", False)

        quirks = []

        if reserved_field != 0:
            quirks.append("R")

        if urgent_pointer != 0 and not urg_flag_set:
            quirks.append("U")

        quirks_string = "".join(sorted(quirks))

        if not quirks_string:
            quirks_string = ""

        print(f"TCP Miscellaneous Quirks (Q) Result: {quirks_string}")
        return quirks_string
