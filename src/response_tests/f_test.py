from src.response_tests.base_response_test import ResponseTest


class TCPFlagsTest(ResponseTest):
    """
    TCP Flags (F) Test.
    Examines the TCP flags in the response and represents them as a string,
    where each letter corresponds to a specific flag set in the TCP header.
    """

    def analyze(self):
        """
        Analyzes the TCP flags in the response and generates the F string.
        """
        flags = self.response_data.get("flags")

        if not flags:
            return ""

        # Ensure the flags are in the correct order
        ordered_flags = "EUAPRFS"
        sorted_flag_string = "".join(sorted(flags, key=ordered_flags.index))
        return sorted_flag_string
