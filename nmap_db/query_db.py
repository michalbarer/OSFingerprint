from typing import Dict

from nmap_db.db_names_mapping import test_names_mapping, probes_mapping
from nmap_db.match_points import MATCH_POINTS
import re


def evaluate_single_range_db_value(test_result: str, db_value: str) -> bool:
    """
    Evaluates a condition string containing one range enclosed in square brackets.
    Example: 'M5B4NW[1-3]NNT11SLL'
    """
    # Regex to extract the range and its bounds
    match = re.search(r'\[(\w+)-(\w+)\]', db_value)
    if not match:
        return test_result == db_value  # If no range, do direct match

    # Extract range bounds
    start, end = match.groups()
    start = start.replace('M', '')  # Remove 'M' if present
    end = end.replace('M', '')
    start = int(start, 16) if start.isalnum() else int(start)  # Convert to int/hex
    end = int(end, 16) if end.isalnum() else int(end)

    # Extract the placeholder from the condition (e.g., 'NW[1-3]')
    range_placeholder = match.group(0)

    # Split test_result to align with condition
    range_index = db_value.index(range_placeholder)  # Find where the range appears
    before_range = db_value[:range_index]  # Part before the range
    after_range = db_value[range_index + len(range_placeholder):]  # Part after the range

    # Validate structure of test_result matches condition
    if not (test_result.startswith(before_range) and test_result.endswith(after_range)):
        return False

    # Extract the actual value from test_result corresponding to the range
    range_start_index = len(before_range)
    range_end_index = len(test_result) - len(after_range)
    try:
        range_value = int(test_result[range_start_index:range_end_index], 16)  # Convert to int/hex
    except ValueError:
        return False

    # Check if the value is within the range
    return start <= range_value <= end




def evaluate_condition(test_result, db_result) -> bool:
    """
    Evaluates a single condition against the test result.
    """
    if isinstance(db_result, tuple) and len(db_result) == 2:  # Range check
        start, end = db_result
        if isinstance(start, int) and isinstance(end, int) and isinstance(test_result, int):
            return start <= test_result <= end
        elif isinstance(start, str) and isinstance(end, str) and isinstance(test_result, str):
            return start <= test_result <= end

    elif isinstance(db_result, str):  # String-based condition
        try:
            if '[' in db_result and ']' in db_result:
                return evaluate_single_range_db_value(test_result, db_result)
            elif '-' in db_result and '[' not in db_result and ']' not in db_result:  # Range operator (e.g., '4E7-5B4')
                start, end = db_result.split('-')
                return int(start, 16) <= test_result <= int(end, 16)
            elif db_result.startswith('>'):  # Greater than
                try:
                    return test_result > int(db_result[1:])
                except ValueError:
                    return test_result > int(db_result[1:], 16)
            elif db_result.startswith('<'):  # Less than
                return test_result < int(db_result[1:])
            else:  # Direct string or hex match
                return test_result == db_result
        except TypeError:
            return False

    elif isinstance(db_result, int):  # Exact match with an integer
        return test_result == db_result

    return False


def compare_result(probe: str, test_name: str, test_result, db_result) -> int:
    """
    Compares a single test result with the database result and assigns points based on the match.
    Supports ranges, expressions, and mixed-type lists in the database.
    """
    if test_result is None or db_result is None:
        return 0

    test_points = MATCH_POINTS[probe][test_name]

    # Handle list of conditions
    if isinstance(db_result, list):
        for condition in db_result:
            if evaluate_condition(test_result, condition):
                return test_points

    # Handle single condition
    if evaluate_condition(test_result, db_result):
        return test_points

    return 0


# Original Compare Result function
# def compare_result(probe: str, test_name: str, test_result, db_result) -> int:
#     """
#     Compares the given test result with the db result and returns the score based on the matching points.
#     """
#
#     if test_result is None:
#         return 0
#
#     # Matching points for the test
#     test_probe = MATCH_POINTS[probe]
#     test_points = test_probe[test_name]
#
#     # For string or int matching
#     if test_result == db_result:
#         return test_points
#
#     # For tuple range matching (numeric range or hex range)
#     elif isinstance(db_result, tuple):
#         start, end = db_result
#         if isinstance(start, int) and isinstance(end, int) and isinstance(test_result, int):
#             # Numeric range check
#             if start <= test_result <= end:
#                 return test_points
#         elif isinstance(start, str) and isinstance(end, str) and isinstance(test_result, str):
#             # Hex range check
#             if start <= test_result <= end:
#                 return test_points
#
#     # For list matching (check if the test result is in the list)
#     elif isinstance(db_result, list):
#         if test_result in db_result:
#             return test_points
#
#     return 0


def calculate_os_score(probe_results, db) -> Dict[str, float]:
    os_scores = {}

    for os_name, os_data in db.items():
        os_score = 0  # Initialize score for the current OS
        max_score = 0  # Initialize max score for the current OS

        # Iterate through all tests in the probe results
        for probe, tests in probe_results.items():
            for test_name, test_result in tests.items():
                db_test_name = test_names_mapping[test_name]
                db_probe = probes_mapping[probe]
                if db_test_name in os_data['Tests'][db_probe]:
                    max_score += MATCH_POINTS[probe][db_test_name]
                    # Compare the test result with the OS test result and add points
                    os_score += compare_result(probe, db_test_name, test_result, os_data['Tests'][db_probe][db_test_name])

        # Store the final score for the OS
        os_scores[os_name] = round((os_score / max_score) * 100, 2)
        print(f"Score for {os_name}: {os_score}")

    return os_scores
