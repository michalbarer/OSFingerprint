from response_tests.base_response_test import ResponseTest


class ResponsivenessTest(ResponseTest):
    """
    This test records whether the target responded to a given probe.
    The result is 'Y' if a response is received and 'N' otherwise.
    """

    def analyze(self):
        """
        :return: 'Y' if the target responded, 'N' otherwise.
        """
        if self.response_data.get("response_received"):
            result = "Y"
        else:
            result = "N"

        return result
