from src.response_tests.w_tests import TCPInitialWindowSizeTest, W1Test, W2Test, W3Test, W4Test, W5Test, W6Test


def test_analyze_no_tcp_window_size():
    response_data = {}
    test = TCPInitialWindowSizeTest(response_data)
    result = test.analyze()
    assert result is None


def test_analyze_tcp_window_size():
    response_data = {"tcp_window_size": 1024}
    test = TCPInitialWindowSizeTest(response_data)
    result = test.analyze()
    assert result == 1024


def test_analyze_tcp_window_size_w1():
    response_data = {"tcp_window_size_1": 2048}
    test = W1Test(response_data)
    result = test.analyze()
    assert result == 2048


def test_analyze_tcp_window_size_w2():
    response_data = {"tcp_window_size_2": 4096}
    test = W2Test(response_data)
    result = test.analyze()
    assert result == 4096


def test_analyze_tcp_window_size_w3():
    response_data = {"tcp_window_size_3": 8192}
    test = W3Test(response_data)
    result = test.analyze()
    assert result == 8192


def test_analyze_tcp_window_size_w4():
    response_data = {"tcp_window_size_4": 16384}
    test = W4Test(response_data)
    result = test.analyze()
    assert result == 16384


def test_analyze_tcp_window_size_w5():
    response_data = {"tcp_window_size_5": 32768}
    test = W5Test(response_data)
    result = test.analyze()
    assert result == 32768


def test_analyze_tcp_window_size_w6():
    response_data = {"tcp_window_size_6": 65536}
    test = W6Test(response_data)
    result = test.analyze()
    assert result == 65536
