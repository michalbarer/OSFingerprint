from src.response_tests.base_response_test import ResponseTest


class ExplicitCongestionNotificationTest(ResponseTest):
    """
    Explicit Congestion Notification (CC) Test.
    Determines the ECN support level by examining the CWR and ECE flags in the response to the ECN probe.
    """

    def analyze(self):
        """
        Analyzes the ECN probe response to determine CC value.
        """
        flags = self.response_data.get("flags")

        if not flags:
            return None

        if "E" in flags and "C" in flags:
            result = "S"
        elif "E" in flags:
            result = "Y"
        elif "C" in flags:
            result = "O"
        else:
            result = "N"

        return result
