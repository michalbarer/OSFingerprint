from response_tests.base_response_test import ResponseTest


class TCPInitialWindowSizeTest(ResponseTest):
    """
    TCP Initial Window Size (W) Test.
    Records the 16-bit TCP window size of the received packet.
    """

    def analyze(self):
        """
        Analyzes the TCP window size from the response data.
        """
        tcp_window_size = self.response_data.get("tcp_window_size")

        if tcp_window_size is None:
            print("No TCP window size data available for analysis.")
            return None

        print(f"TCP Initial Window Size (W): {tcp_window_size}")
        return tcp_window_size


class W1Test(TCPInitialWindowSizeTest):
    """TCP Window Size Test for Probe W1."""
    pass


class W2Test(TCPInitialWindowSizeTest):
    """TCP Window Size Test for Probe W2."""
    pass


class W3Test(TCPInitialWindowSizeTest):
    """TCP Window Size Test for Probe W3."""
    pass


class W4Test(TCPInitialWindowSizeTest):
    """TCP Window Size Test for Probe W4."""
    pass


class W5Test(TCPInitialWindowSizeTest):
    """TCP Window Size Test for Probe W5."""
    pass


class W6Test(TCPInitialWindowSizeTest):
    """TCP Window Size Test for Probe W6."""
    pass
