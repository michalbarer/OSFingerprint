from probes.ecn import ExplicitCongestionNotificationProbe
from probes.icmp_echo import ICMPEchoProbe
from probes.tcp import TCPProbe
from probes.tcp_seq import TCPSequenceProbe
from probes.udp import UDPProbe
from response_tests.response_test_mapping import probe_to_test_mapping


def main():
    # Example usage
    target_ip = "ynet.co.il"
    open_port = 80
    closed_port = 81

    # Run each probe type
    probes = [
        # TCPSequenceProbe(target_ip, open_port),
        ICMPEchoProbe(target_ip),
        ExplicitCongestionNotificationProbe(target_ip, open_port),
        # TCPProbe(target_ip, open_port, closed_port),
        UDPProbe(target_ip, closed_port)
    ]

    for probe in probes:
        probe.send_probe()
        probe.analyze_response()
        print()
        resp_data = probe.get_response_data()
        response_tests = probe_to_test_mapping[probe.__class__.__name__]
        for test in response_tests:
            result = test(response_data=resp_data).analyze()
            print(result)


if __name__ == "__main__":
    main()