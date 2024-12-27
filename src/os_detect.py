from src.probes.ecn import ExplicitCongestionNotificationProbe
from src.probes.icmp_echo import ICMPEchoProbe
from src.probes.tcp import T4Probe, T5Probe, T6Probe, T7Probe, T2Probe, T3Probe
from src.probes.tcp_seq import SEQProbe, OPSProbe, WINProbe, T1Probe
from src.probes.udp import UDPProbe

from src.response_tests.gcd_test import TCPISNGCDTest
from src.response_tests.ip_id_test.ci_test import TCPIIDCI
from src.response_tests.ip_id_test.ii_test import ICMPIIDII
from src.response_tests.ip_id_test.ss_test import TCPAndICMPIPIDSequenceBooleanTest
from src.response_tests.ip_id_test.ti_test import TCPIIDTI
from src.response_tests.sp_test import TCPISNSequencePredictabilityTest
from src.response_tests.response_test_mapping import probe_to_test_mapping

from src.nmap_db.query_db import calculate_os_score
from src.nmap_db.parsed_nmap_os_db import OS_DB


def run_seq_probe_and_tests(target_ip, open_port, closed_port):
    seq_probe = SEQProbe(target_ip, open_port)
    seq_probe.send_probe()
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
                if ip_id is not None:
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

    return {seq_probe.__class__.__name__: seq_probe_results}


def run_all_probes_and_tests(target_ip, open_port, closed_port):
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

    all_results = {}

    for probe in probes:
        probe.send_probe()
        resp_data = probe.get_response_data()
        response_tests = probe_to_test_mapping[probe.__class__.__name__]
        probe_results = {}
        for test in response_tests:
            result = test(response_data=resp_data).analyze()
            probe_results[test.__name__] = result
        all_results[probe.__class__.__name__] = probe_results
    return all_results


def run_tests(target_ip: str, open_ports: list, closed_ports: list):
    open_port = open_ports[0]
    closed_port = closed_ports[0]
    all_results = {}

    all_results.update(run_seq_probe_and_tests(target_ip, open_port, closed_port))
    all_results.update(run_all_probes_and_tests(target_ip, open_port, closed_port))

    return all_results

def compare_results_to_db(results, top_results: int = 10):
    """
    Calculates the OS score for each OS in the database.
    """
    os_scores = calculate_os_score(results, OS_DB)
    return sorted(os_scores.items(), key=lambda item: item[1], reverse=True)[:top_results]

