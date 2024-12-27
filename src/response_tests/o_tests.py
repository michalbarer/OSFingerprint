from typing import Optional

from src.response_tests.base_response_test import ResponseTest


class TCPOptionsTest(ResponseTest):
    """
    TCP Options (O) Test.
    Records the TCP header options in a packet while preserving the original order
    and providing information about option values.
    """
    def __init__(self, response_data, index: Optional[int] = None):
        super().__init__(response_data)
        self.index = index

    def analyze(self):
        """
        Analyzes the TCP options from the response data.
        """
        key = "tcp_options"
        if self.index:
            key = f"tcp_options_{self.index}"
        tcp_options = self.response_data.get(key, [])

        if not tcp_options:
            return ""

        # Build the options string
        option_string = ""
        for option in tcp_options:
            if option[0] == "EOL":
                option_string += "L"
            elif option[0] == "NOP":
                option_string += "N"
            elif option[0] == "MSS":
                option_string += f"M{(option[1]):x}"
            elif option[0] == "WScale":
                option_string += f"W{option[1]}"
            elif option[0] == "Timestamp":
                tsval = 1 if option[1][0] != 0 else 0
                tsecr = 1 if option[1][1] != 0 else 0
                option_string += f"T{tsval}{tsecr}"
            elif option[0] == "SAckOK":
                option_string += "S"

        option_string = option_string.upper()
        return option_string

class O1Test(TCPOptionsTest):
    """TCP Options Test for Probe O1."""

    def __init__(self, response_data):
        super().__init__(response_data, 1)


class O2Test(TCPOptionsTest):
    """TCP Options Test for Probe O2."""

    def __init__(self, response_data):
        super().__init__(response_data, 2)


class O3Test(TCPOptionsTest):
    """TCP Options Test for Probe O3."""

    def __init__(self, response_data):
        super().__init__(response_data, 3)


class O4Test(TCPOptionsTest):
    """TCP Options Test for Probe O4."""

    def __init__(self, response_data):
        super().__init__(response_data, 4)


class O5Test(TCPOptionsTest):
    """TCP Options Test for Probe O5."""

    def __init__(self, response_data):
        super().__init__(response_data, 5)


class O6Test(TCPOptionsTest):
    """TCP Options Test for Probe O6."""

    def __init__(self, response_data):
        super().__init__(response_data, 6)
