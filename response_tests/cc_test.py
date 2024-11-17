from response_tests.base_response_test import ResponseTest


class ExplicitCongestionNotificationTest(ResponseTest):
    """
    Explicit Congestion Notification (CC) Test.
    Determines the ECN support level by examining the CWR and ECE flags in the response to the ECN probe.
    """

    def analyze(self):
        """
        Analyzes the ECN probe response to determine CC value.
        """
        # Retrieve the SYN/ACK flags from the response data
        flags = self.response_data.get("flags")

        # Ensure that flags data is available
        if not flags:
            print("No flag data available, unable to determine ECN support.")
            return None

        # Extract the CWR and ECE flag states
        cwr_set = "CWR" in flags
        ece_set = "ECE" in flags

        # Determine the CC value based on the flag states
        if ece_set and not cwr_set:
            result = "Y"  # Only ECE is set; ECN is supported
        elif not ece_set and not cwr_set:
            result = "N"  # Neither ECE nor CWR is set; ECN not supported
        elif ece_set and cwr_set:
            result = "S"  # Both ECE and CWR are set; echoing reserved bits
        else:
            result = "O"  # Any other combination of flags

        print(f"Explicit Congestion Notification (CC) Result: {result}")
        return result
