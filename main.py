from nmap_db.parsed_nmap_os_db import os_db
from nmap_db.query_db import calculate_os_score
from probes import T1Probe, T2Probe, T3Probe
from probes.ecn import ExplicitCongestionNotificationProbe
from probes.icmp_echo import ICMPEchoProbe
from probes.tcp import T4Probe, T5Probe, T6Probe, T7Probe
from probes.tcp_seq import SEQProbe, OPSProbe, WINProbe
from probes.udp import UDPProbe
from response_tests import (
    TCPISNGCDTest,
    TCPISNSequencePredictabilityTest,
    TCPIIDTI,
    TCPIIDCI,
    ICMPIIDII,
    TCPAndICMPIPIDSequenceBooleanTest
)
from response_tests.response_test_mapping import probe_to_test_mapping


# from core.utils.fp_utils import resolve_host
# import validators


def run_seq_probe_and_tests(target_ip, open_port, closed_port):
    seq_probe = SEQProbe(target_ip, open_port)
    seq_probe.send_probe()
    seq_probe.analyze_response()
    seq_response_data = seq_probe.get_response_data()
    seq_probe_results = {}
    response_tests = probe_to_test_mapping[seq_probe.__class__.__name__]

    gcd_value = None
    ti_value = None
    ii_value = None
    icmp_response_data = None

    for test in response_tests:
        if test == TCPISNSequencePredictabilityTest:
            value = test(response_data=seq_response_data, gcd_value=gcd_value).analyze()
        elif test == TCPIIDCI:
            t_closed_ports = [T5Probe(target_ip, closed_port), T6Probe(target_ip, closed_port), T7Probe(target_ip, closed_port)]
            t_probe_results = {
                "closed_port_ipd_ids": []
            }
            for t_test in t_closed_ports:
                t_test.send_probe()
                ip_id = t_test.get_response_data()["ip_id"]
                if ip_id:
                    t_probe_results["closed_port_ipd_ids"].append(ip_id)

            value = test(response_data=t_probe_results).analyze()
        elif test == ICMPIIDII:
            icmp_probe = ICMPEchoProbe(target_ip)
            icmp_probe.send_probe()
            icmp_response_data = icmp_probe.get_response_data()
            value = test(response_data=icmp_response_data).analyze()
        elif test == TCPAndICMPIPIDSequenceBooleanTest and icmp_response_data:
            value = test(icmp_response_data=icmp_response_data,
                         tcp_response_data=seq_response_data,
                         ii_result=ii_value, ti_result=ti_value).analyze()
        else:
            value = test(response_data=seq_response_data).analyze()

        if test == TCPISNGCDTest:
            gcd_value = value
        elif test == TCPIIDTI:
            ti_value = value
        elif test == ICMPIIDII:
            ii_value = value

        seq_probe_results[test.__name__] = value

    return seq_probe_results


# def validate_host(host: str):  # todo - resolve url to ip address
#   """
#   Validates the host and returns the resolved IP address.
#   :param host: the host to validate
#   :return: the resolved IP address
#   """
#     if validators.domain(host):
#         host = resolve_host(host)
#     else:
#         socket.inet_aton(host)
#     return host


def main():
    target_ip = '45.33.32.156' # "scanme.nmap.org"
    open_port = 80
    closed_port = 1234

    # target_ip = "10.100.102.192"
    # open_port = 8075
    # closed_port = 1000

    all_results = {}

    # Run SEQ probe:
    seq_probe_results = run_seq_probe_and_tests(target_ip, open_port, closed_port)
    all_results[SEQProbe.__name__] = seq_probe_results

    # Run other probes:
    probes = [
        OPSProbe(target_ip, open_port),
        WINProbe(target_ip, open_port),
        T1Probe(target_ip, open_port),
        ICMPEchoProbe(target_ip),
        ExplicitCongestionNotificationProbe(target_ip, open_port),
        T2Probe(target_ip, open_port),
        T3Probe(target_ip, open_port),
        T4Probe(target_ip, open_port),
        T5Probe(target_ip, closed_port),
        T6Probe(target_ip, closed_port),
        T7Probe(target_ip, closed_port),
        UDPProbe(target_ip, closed_port)
    ]

    # all_results = {}

    for probe in probes:
        probe.send_probe()
        probe.analyze_response()
        print()
        resp_data = probe.get_response_data()
        response_tests = probe_to_test_mapping[probe.__class__.__name__]
        probe_results = {}
        for test in response_tests:
            result = test(response_data=resp_data).analyze()
            probe_results[test.__name__] = result
        print()
        all_results[probe.__class__.__name__] = probe_results

    import pprint
    pprint.pprint(all_results)

    # Calculate the scores for each OS
    os_scores = calculate_os_score(all_results, os_db)

    sorted_os_scores = sorted(os_scores.items(), key=lambda item: item[1], reverse=True)[:10]
    print()
    print("Top ten matching Operating Systems:")
    for os, score in sorted_os_scores:
        print(f"{os}: {score}")


if __name__ == "__main__":
    main()
