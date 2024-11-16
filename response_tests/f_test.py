from response_tests.base_response_test import ResponseTest


class TCPFlagsTest(ResponseTest):
    """
    TCP Flags (F) Test.
    Examines the TCP flags in the response and represents them as a string,
    where each letter corresponds to a specific flag set in the TCP header.
    """

    # Mapping of flag names to their corresponding characters
    FLAG_MAPPING = {
        "ECE": "E",
        "URG": "U",
        "ACK": "A",
        "PSH": "P",
        "RST": "R",
        "SYN": "S",
        "FIN": "F"
    }

    def analyze(self):
        """
        Analyzes the TCP flags in the response and generates the F string.
        """
        # Retrieve the flags from the response data
        flags = self.response_data.get("flags")

        if not flags:
            print("No TCP flags available for analysis.")
            return ""

        # Translate the flags into their corresponding characters
        flag_string = "".join(self.FLAG_MAPPING.get(flag, "") for flag in flags)

        # Ensure the flags are in the correct order
        ordered_flags = "EUAPRFS"  # Order of flags from high to low bit
        sorted_flag_string = "".join(sorted(flag_string, key=ordered_flags.index))

        print(f"TCP Flags (F) Result: {sorted_flag_string}")
        return sorted_flag_string
