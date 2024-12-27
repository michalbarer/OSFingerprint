import zlib

from src.response_tests.base_response_test import ResponseTest


class TCPRSTDataChecksumTest(ResponseTest):
    """
    TCP RST Data Checksum (RD) Test.
    Computes a CRC32 checksum for ASCII data in TCP reset packets.
    If no data is present, the RD value is set to zero.
    """

    def analyze(self):
        """
        Analyzes the TCP RST packet for data and computes its CRC32 checksum.
        """
        data = self.response_data.get("data", b"")

        if not data:
            print("TCP RST Data Checksum (RD): 0")
            return 0

        checksum = zlib.crc32(data) & 0xFFFFFFFF  # Ensure a 32-bit result
        print(f"TCP RST Data Checksum (RD): {checksum}")
        return checksum
