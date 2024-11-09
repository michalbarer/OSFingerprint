from probes.ecn import ExplicitCongestionNotificationProbe
from probes.icmp_echo import ICMPEchoProbe
from probes.tcp import TCPFlagProbe
from probes.tcp_seq import TCPSequenceProbe
from probes.upd import UDPProbe
from response_tests.gcd_test import TCPISNGCDTest


def main():
    # Example usage
    target_ip = "ynet.co.il"
    target_port = 80

    # Run each probe type
    probes = [
        TCPSequenceProbe(target_ip, target_port),
        # ICMPEchoProbe(target_ip),
        # ExplicitCongestionNotificationProbe(target_ip, target_port),
        # TCPFlagProbe(target_ip, target_port),
        # UDPProbe(target_ip, target_port)
    ]

    for probe in probes:
        probe.send_probe()
        probe.analyze_response()
        resp_data = probe.get_response_data()
        test = TCPISNGCDTest(response_data=resp_data)
        test.analyze()


if __name__ == "__main__":
    main()