import re

from src.utils.parsers import hex_str_int, NotHexadecimalError


def parse_nmap_os_db(file_path):
    """
    Efficiently parses the nmap-os-db file and organizes it into a dictionary,
    dividing test entries into nested dictionaries, handling nulls, integers,
    ranges (as tuples), lists, and removing % from each key-value pair individually.

    :param file_path: Path to the nmap-os-db file.
    :return: Dictionary containing the parsed data.
    """
    os_db = {}
    current_fingerprint = None

    range_pattern = re.compile(r"^([0-9A-Fa-f]+)-([0-9A-Fa-f]+)$")
    key_value_pattern = re.compile(r"([^=]+)=([^%]*)")

    def parse_value(value):
        """
        Parses a value into its appropriate type:
        - Null (None)
        - Integer
        - Range as tuple (start, end)
        - List combining ranges and individual values
        """
        if not value:
            return ""

        parts = value.split("|")
        parsed_parts = []
        for part in parts:
            part = part.strip()
            if range_match := range_pattern.match(part):
                start, end = range_match.groups()
                parsed_parts.append((hex_str_int(start), hex_str_int(end)))
            else:
                try:
                    parsed_parts.append(hex_str_int(part))
                except NotHexadecimalError:
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
            if not line or line.startswith("#"):
                continue

            if line.startswith("Fingerprint"):
                current_fingerprint = line[len("Fingerprint "):].strip()
                os_db[current_fingerprint] = {"Class": None, "CPE": [], "Tests": {}}
            elif current_fingerprint:
                if line.startswith("Class"):
                    os_db[current_fingerprint]["Class"] = line[len("Class "):].strip()
                elif line.startswith("CPE"):
                    os_db[current_fingerprint]["CPE"].append(line[len("CPE "):].strip())
                else:
                    test_key, test_value = line.split("(", 1)
                    test_key = test_key.strip()
                    test_value = test_value.rstrip(")").strip()
                    os_db[current_fingerprint]["Tests"][test_key] = parse_probe(test_value)

    return os_db


if __name__ == "__main__":
    file_path = "nmap-os-db.txt"
    os_data = parse_nmap_os_db(file_path)

    import pprint
    pprint.pprint(os_data)

    python_file_path = "parsed_nmap_os_db.py"
    with open(python_file_path, 'w') as py_file:
        py_file.write("OS_DB = ")
        py_file.write(str(os_data))
