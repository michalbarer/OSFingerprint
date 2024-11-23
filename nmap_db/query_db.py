from nmap_db.db_names_mapping import test_names_mapping, probes_mapping
from nmap_db.match_points import MATCH_POINTS


def compare_result(probe, test_name, test_result, db_result):
    """
    Compares the given test result with the db result and returns the score based on the matching points.
    """
    # Matching points for the test
    test_probe = MATCH_POINTS[probe]
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
