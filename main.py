from nmap_db.query_db import calculate_os_score
from probes import T1Probe, T2Probe, T3Probe
from probes.ecn import ExplicitCongestionNotificationProbe
from probes.icmp_echo import ICMPEchoProbe
from probes.tcp import T4Probe, T5Probe, T6Probe, T7Probe
from probes.tcp_seq import SEQProbe, OPSProbe, WINProbe
from probes.udp import UDPProbe
from response_tests.response_test_mapping import probe_to_test_mapping
from nmap_db.parsed_nmap_os_db import os_db


def main():
    target_ip = "scanme.nmap.org"
    open_port = 80
    closed_port = 1234

    # Run each probe type
    probes = [
        # SEQProbe(target_ip, open_port),
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

    all_results = {}

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

    # Find the OS with the highest score
    best_os = max(os_scores, key=os_scores.get)

    print(f"The best matching OS is: {best_os} with a score of {os_scores[best_os]}")


if __name__ == "__main__":
    main()

# todo: Fix SEQ tests - maybe run dependencies inside probe
# todo: Cast tests response and db to hex: DB in hex type (check if there are ints)
# todo: project document
