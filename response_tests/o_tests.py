from response_tests.base_response_test import ResponseTest


class TCPOptionsTest(ResponseTest):
    """
    TCP Options (O) Test.
    Records the TCP header options in a packet while preserving the original order
    and providing information about option values.
    """

    def analyze(self):
        """
        Analyzes the TCP options from the response data.
        """
        tcp_options = self.response_data.get("tcp_options", [])

        if not tcp_options:
            print("No TCP options data available for analysis.")
            return ""

        # Build the options string
        option_string = ""
        for option in tcp_options:
            if option[0] == "EOL":
                option_string += "L"
            elif option[0] == "NOP":
                option_string += "N"
            elif option[0] == "MSS":
                option_string += f"M{option[1]}"
            elif option[0] == "WScale":
                option_string += f"W{option[1]}"
            elif option[0] == "Timestamp":
                tsval = 1 if option[1][0] != 0 else 0
                tsecr = 1 if option[1][1] != 0 else 0
                option_string += f"T{tsval}{tsecr}"
            elif option[0] == "SAckOK":
                option_string += "S"

        print(f"TCP Options (O) String: {option_string}")
        return option_string

class O1Test(TCPOptionsTest):
    """TCP Options Test for Probe O1."""
    pass


class O2Test(TCPOptionsTest):
    """TCP Options Test for Probe O2."""
    pass


class O3Test(TCPOptionsTest):
    """TCP Options Test for Probe O3."""
    pass


class O4Test(TCPOptionsTest):
    """TCP Options Test for Probe O4."""
    pass


class O5Test(TCPOptionsTest):
    """TCP Options Test for Probe O5."""
    pass


class O6Test(TCPOptionsTest):
    """TCP Options Test for Probe O6."""
    pass
