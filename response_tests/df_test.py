from response_tests.base_response_test import ResponseTest


class IPDontFragmentTest(ResponseTest):
    """
    Tests whether the IP Don't Fragment (DF) bit is set in the response.
    """

    def analyze(self):
        if not self.response_data or "ip" not in self.response_data:
            print("No IP header data found in response.")
            return None

        ip_header = self.response_data.get("ip")
        flags = ip_header.get("flags", "")

        if "DF" in flags:
            print("IP DF bit is set (Y).")
            return "Y"
        else:
            print("IP DF bit is not set (N).")
            return "N"
