import zlib

from src.response_tests.rd_test import TCPRSTDataChecksumTest

def test_analyze_no_data():
    response_data = {
        "data": b""
    }
    test = TCPRSTDataChecksumTest(response_data)
    result = test.analyze()
    assert result == 0

def test_analyze_with_data():
    response_data = {
        "data": b"test data"
    }
    test = TCPRSTDataChecksumTest(response_data)
    result = test.analyze()
    expected_checksum = zlib.crc32(b"test data") & 0xFFFFFFFF
    assert result == expected_checksum

def test_analyze_with_different_data():
    response_data = {
        "data": b"another test data"
    }
    test = TCPRSTDataChecksumTest(response_data)
    result = test.analyze()
    expected_checksum = zlib.crc32(b"another test data") & 0xFFFFFFFF
    assert result == expected_checksum

def test_analyze_missing_data_key():
    response_data = {}
    test = TCPRSTDataChecksumTest(response_data)
    result = test.analyze()
    assert result == 0
