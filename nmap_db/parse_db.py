import re


def parse_nmap_os_db(file_path):
    """
    Efficiently parses the nmap-os-db file and organizes it into a dictionary,
    dividing test entries into nested dictionaries, handling nulls, integers,
    ranges (as tuples), lists, and removing % from each key-value pair individually.

    :param file_path: Path to the nmap-os-db file.
    :return: Dictionary containing the parsed data.
    """
    os_db = {}
    current_fingerprint = None  # Tracks the currently parsed fingerprint

    # Precompiled regex patterns for efficiency
    range_pattern = re.compile(r"^([0-9A-Fa-f]+)-([0-9A-Fa-f]+)$")  # Matches ranges like '6A-BE'
    key_value_pattern = re.compile(r"([^=]+)=([^%]*)")  # Matches key=value pairs like 'SP=6A-BE'

    def parse_value(value):
        """
        Parses a value into its appropriate type:
        - Null (None)
        - Integer
        - Range as tuple (start, end)
        - List combining ranges and individual values
        """
        if not value:
            return None  # Null value

        parts = value.split("|")  # Split into components by '|'
        parsed_parts = []
        for part in parts:
            part = part.strip()
            # Check if the part is a range
            if range_match := range_pattern.match(part):
                start, end = range_match.groups()
                if start.isdigit() and end.isdigit():
                    parsed_parts.append((int(start), int(end)))  # Numeric range
                else:
                    parsed_parts.append((start.upper(), end.upper()))  # Hex range
            # Check if the part is an integer
            elif part.isdigit():
                parsed_parts.append(int(part))
            # Otherwise, treat as string
            else:
                parsed_parts.append(part)

        # If there's only one item, return it directly; otherwise, return the list
        return parsed_parts[0] if len(parsed_parts) == 1 else parsed_parts

    def parse_probe(probe_string):
        """
        Parses a probe string into a dictionary, handling nulls, integers,
        ranges, and combined lists with ranges, and removes % for each value individually.
        """
        probe_data = {}
        for match in key_value_pattern.finditer(probe_string):
            key, value = match.groups()
            key = key.strip()
            key = key.replace("%", "").strip()  # Remove '%' for this value
            probe_data[key] = parse_value(value)
        return probe_data

    with open(file_path, 'r') as file:
        for line in (line.strip() for line in file):
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Detect the start of a new fingerprint entry
            if line.startswith("Fingerprint"):
                current_fingerprint = line[len("Fingerprint "):].strip()
                os_db[current_fingerprint] = {"Class": None, "CPE": [], "Tests": {}}
            elif current_fingerprint:
                # Handle Class entries
                if line.startswith("Class"):
                    os_db[current_fingerprint]["Class"] = line[len("Class "):].strip()
                # Handle CPE entries
                elif line.startswith("CPE"):
                    os_db[current_fingerprint]["CPE"].append(line[len("CPE "):].strip())
                # Handle test entries (e.g., SEQ, OPS, WIN, etc.)
                else:
                    test_key, test_value = line.split("(", 1)
                    test_key = test_key.strip()
                    test_value = test_value.rstrip(")").strip()
                    os_db[current_fingerprint]["Tests"][test_key] = parse_probe(test_value)

    return os_db


# Example usage:
if __name__ == "__main__":
    file_path = "nmap-os-db.txt"  # Replace with the actual file path
    os_data = parse_nmap_os_db(file_path)

    # Print the parsed dictionary
    import pprint

    pprint.pprint(os_data)
