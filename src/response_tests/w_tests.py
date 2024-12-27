from typing import Optional

from src.response_tests.base_response_test import ResponseTest


class TCPInitialWindowSizeTest(ResponseTest):
    """
    TCP Initial Window Size (W) Test.
    Records the 16-bit TCP window size of the received packet.
    """
    def __init__(self, response_data, index: Optional[int] = None):
        super().__init__(response_data)
        self.index = index

    def analyze(self):
        """
        Analyzes the TCP window size from the response data.
        """
        key = "tcp_window_size"
        if self.index:
            key = f"tcp_window_size_{self.index}"

        tcp_window_size = self.response_data.get(key)

        if tcp_window_size is None:
            print("No TCP window size data available for analysis.")
            return None

        print(f"TCP Initial Window Size (W): {tcp_window_size}")
        return tcp_window_size


class W1Test(TCPInitialWindowSizeTest):
    """TCP Window Size Test for Probe W1."""

    def __init__(self, response_data):
        super().__init__(response_data, 1)


class W2Test(TCPInitialWindowSizeTest):
    """TCP Window Size Test for Probe W2."""

    def __init__(self, response_data):
        super().__init__(response_data, 2)


class W3Test(TCPInitialWindowSizeTest):
    """TCP Window Size Test for Probe W3."""

    def __init__(self, response_data):
        super().__init__(response_data, 3)


class W4Test(TCPInitialWindowSizeTest):
    """TCP Window Size Test for Probe W4."""

    def __init__(self, response_data):
        super().__init__(response_data, 4)


class W5Test(TCPInitialWindowSizeTest):
    """TCP Window Size Test for Probe W5."""

    def __init__(self, response_data):
        super().__init__(response_data, 5)


class W6Test(TCPInitialWindowSizeTest):
    """TCP Window Size Test for Probe W6."""

    def __init__(self, response_data):
        super().__init__(response_data, 6)
