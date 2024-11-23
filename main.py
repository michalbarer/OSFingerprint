from nmap_db.query_db import calculate_os_score
from probes import T1Probe, T2Probe, T3Probe
from probes.ecn import ExplicitCongestionNotificationProbe
from probes.icmp_echo import ICMPEchoProbe
from probes.tcp import T4Probe, T5Probe, T6Probe, T7Probe
from probes.tcp_seq import SEQProbe, OPSProbe, WINProbe
from probes.udp import UDPProbe
from response_tests import TCPISNGCDTest, TCPISNSequencePredictabilityTest, TCPISNRateTest, TCPIIDTI, \
    TCPTimestampOptionTest
from response_tests.response_test_mapping import probe_to_test_mapping
from nmap_db.parsed_nmap_os_db import os_db


def main():
    # target_ip = "scanme.nmap.org"
    # open_port = 80
    # closed_port = 1234

    target_ip = "10.100.102.192"
    open_port = 8075
    closed_port = 1000

    all_results = {}
    # # Run seq probe:
    # seq_probe = SEQProbe(target_ip, open_port)
    # seq_probe.send_probe()
    # seq_probe.analyze_response()
    # print()
    # response_tests = probe_to_test_mapping[seq_probe.__class__.__name__]
    # seq_probe_results = {}
    # seq_response_data = seq_probe.get_response_data()
    # gcd_value = TCPISNGCDTest(response_data=seq_response_data).analyze()
    # seq_probe_results[TCPISNGCDTest.__name__] = gcd_value
    # sp_value = TCPISNSequencePredictabilityTest(response_data=seq_response_data, gcd_value=gcd_value).analyze()
    # seq_probe_results[TCPISNSequencePredictabilityTest.__name__] = sp_value
    # isr_value = TCPISNRateTest(response_data=seq_response_data).analyze()
    # seq_probe_results[TCPISNRateTest.__name__] = isr_value
    # ti_value =  TCPIIDTI(response_data=seq_response_data).analyze()
    # seq_probe_results[TCPIIDTI.__name__] = ti_value
    # ts_test = TCPTimestampOptionTest(response_data=seq_response_data).analyze()
    # seq_probe_results[TCPTimestampOptionTest.__name__] = ts_test
    # # TCPAndICMPIPIDSequenceBooleanTest
    # all_results[seq_probe.__class__.__name__] = seq_probe_results

    # Run each probe type
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

    # Find the OS with the highest score
    max_score = max(os_scores.values())
    best_os_list = [os for os, score in os_scores.items() if score == max_score]
    print(f"The best matching OS(es) with a score of {max_score}: {', '.join(best_os_list)}")


if __name__ == "__main__":
    main()

# todo: Fix SEQ tests - maybe run dependencies inside probe
# todo: Cast tests response and db to hex: DB in hex type (check if there are ints)
# todo: project document
