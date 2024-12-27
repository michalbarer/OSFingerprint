class NotHexadecimalError(Exception):
    pass

def hex_str_int(hex_string: str):
    """
    Parses a hexadecimal string and converts it to an int.

    Args:
        hex_string (str): The hexadecimal string (e.g., 'ff').

    Returns:
        int: The integer value of the hexadecimal string.
    """
    try:
        return int(hex_string, 16)
    except ValueError as e:
        raise NotHexadecimalError("Input must be a string representing a hexadecimal value")

