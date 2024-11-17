from nmap_db.match_points import match_points
from nmap_db.db_names_mapping import test_names_mapping, probes_mapping
from probes import T1Probe, T2Probe, T3Probe
from probes.ecn import ExplicitCongestionNotificationProbe
from probes.icmp_echo import ICMPEchoProbe
from probes.tcp import T4Probe, T5Probe, T6Probe, T7Probe
from probes.tcp_seq import SEQProbe, OPSProbe, WINProbe
from probes.udp import UDPProbe
from response_tests.response_test_mapping import probe_to_test_mapping
from nmap_db.parsed_nmap_os_db import os_db


def compare_result(probe, test_name, test_result, db_result):
    """
    Compares the given test result with the db result and returns the score based on the matching points.
    """
    # Matching points for the test
    test_probe = match_points[probe]
    test_points = test_probe[test_name]

    # For string matching
    if isinstance(test_result, str):
        if test_result == db_result:
            return test_points
        return 0

    # For tuple range matching (numeric range or hex range)
    elif isinstance(test_result, tuple):
        start, end = test_result
        if isinstance(start, int) and isinstance(end, int):
            # Numeric range check
            if start <= db_result <= end:
                return test_points
        elif isinstance(start, str) and isinstance(end, str):
            # Hex range check
            if start <= db_result <= end:
                return test_points
        return 0

    # For list matching (check if the test result is in the list)
    elif isinstance(test_result, list):
        if db_result in test_result:
            return test_points
        return 0

    return 0


def calculate_os_score(probe_results, db):
    os_scores = {}

    for os_name, os_data in db.items():
        os_score = 0  # Initialize score for the current OS

        # Iterate through all tests in the probe results
        for probe, tests in probe_results.items():
            for test_name, test_result in tests.items():
                db_test_name = test_names_mapping[test_name]
                db_probe = probes_mapping[probe]
                if db_test_name in os_data['Tests'][db_probe]:
                    # Compare the test result with the OS test result and add points
                    os_score += compare_result(probe, db_test_name, test_result, os_data['Tests'][db_probe][db_test_name])

        # Store the final score for the OS
        os_scores[os_name] = os_score
        print(f"Score for {os_name}: {os_score}")

    return os_scores


def main():
    # Example usage
    target_ip = "ynet.co.il"
    open_port = 80
    closed_port = 1234

    # Run each probe type
    probes = [
        # SEQProbe(target_ip, open_port),
        # OPSProbe(target_ip, open_port),
        # WINProbe(target_ip, open_port),
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