import re

from src.nmap_db.db_names_mapping import test_names_mapping, probes_mapping
from src.utils.parsers import hex_str_int


def format_input(nmap_res: str) -> str:
    """
    :param nmap_res: The output of the following command: `sudo nmap -sS -T4 -O -d [host]`
    """
    # Remove 'OS:' from each row
    nmap_res = nmap_res.replace('OS:', '')

    index = nmap_res.find("SEQ")
    if index != -1:
        nmap_res = nmap_res[index:]
    lines = nmap_res.splitlines()

    # Remove lines before "SEQ"
    filtered_lines = []
    start_adding = False
    for line in lines:
        if "SEQ" in line:
            start_adding = True
        if start_adding:
            filtered_lines.append(line)

    # Join lines
    formatted_nmap_res = ''.join(filtered_lines).replace(')', ')\n')
    return formatted_nmap_res


def parse_and_convert(output, probes_mapping, test_names_mapping):
    """
    Parses the output string and converts it according to the mappings.
    Uses the value to get the key name from test_names_mapping and probes_mapping.
    Decodes hex values to decimal if present.
    """
    # Reverse the mappings for value-to-key lookup
    reverse_test_names_mapping = {v: k for k, v in test_names_mapping.items()}
    reverse_probes_mapping = {v: k for k, v in probes_mapping.items()}

    results = {}
    probe_pattern = re.compile(r"(\w+)\((.*?)\)")

    for probe_match in probe_pattern.finditer(output):
        probe_short_name, probe_data = probe_match.groups()
        # Get the full probe name
        probe_full_name = reverse_probes_mapping.get(probe_short_name, probe_short_name)
        tests = {}

        for test in probe_data.split('%'):
            if '=' in test:
                test_key, test_value = test.split('=', 1)
                if re.match(r"^[0-9A-Fa-f]+$", test_value):
                    test_value = hex_str_int(test_value)
                test_full_name = reverse_test_names_mapping.get(test_key, test_key)
                tests[test_full_name] = test_value
            else:
                test_full_name = reverse_test_names_mapping.get(test, test)
                tests[test_full_name] = None

        results[probe_full_name] = tests

    return results


def find_differences(dict1, dict2):
    """
    Recursively finds differences between two dictionaries.

    Args:
        dict1 (dict): First dictionary to compare.
        dict2 (dict): Second dictionary to compare.

    Returns:
        dict: A dictionary containing the differences.
    """
    differences = {}

    all_keys = set(dict1.keys()).union(dict2.keys())
    for key in all_keys:
        if key not in dict1:
            differences[key] = {"status": "missing_in_first", "value_in_second": dict2[key]}
        elif key not in dict2:
            differences[key] = {"status": "missing_in_second", "value_in_first": dict1[key]}
        else:
            value1, value2 = dict1[key], dict2[key]
            if isinstance(value1, dict) and isinstance(value2, dict):
                # Recursively find differences in nested dictionaries
                nested_diff = find_differences(value1, value2)
                if nested_diff:  # Only include non-empty differences
                    differences[key] = {"status": "nested_diff", "differences": nested_diff}
            elif value1 != value2:
                differences[key] = {"status": "value_mismatch", "value_in_first": value1, "value_in_second": value2}

    return differences


def main(desired_fp: str, nmap_result: str, osfp_result: dict):
    formatted_str = format_input(nmap_result)
    nmap_dict = parse_and_convert(formatted_str, probes_mapping, test_names_mapping)

    diff = find_differences(nmap_dict, osfp_result)
    return diff


if __name__ == "__main__":
    # desired_fingerprint = "Apple macOS 11 (Big Sur) - 13 (Ventura) or iOS 16 (Darwin 20.6.0 - 22.4.0)"
    desired_fp = "Linux 4.19 - 5.15"
    # This is the output of: sudo nmap -sS -T4 -O -d nmap.scanme.org
    input_str = """OS:SCAN(V=7.95%E=4%D=12/27%OT=22%CT=1%CU=44319%PV=N%DS=18%DC=I%G=N%TM=676EF
OS:68B%P=x86_64-apple-darwin21.6.0)SEQ(SP=FD%GCD=1%ISR=10D%TI=Z%II=I%TS=A)O
OS:PS(O1=M578ST11NW7%O2=M578ST11NW7%O3=M578NNT11NW7%O4=M578ST11NW7%O5=M578S
OS:T11NW7%O6=M578ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)E
OS:CN(R=Y%DF=Y%T=3D%W=FAF0%O=M578NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=3E%S=O%A=S+%F
OS:=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=3D%W=0%S=Z%A=S+%F=AR%O=%R
OS:D=0%Q=)T6(R=N)T7(R=N)U1(R=Y%DF=N%T=3E%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=3E%CD=S)"""

    # Ron's macOS
#     input_str = """OS:SCAN(V=7.95%E=4%D=12/27%OT=5000%CT=1%CU=44513%PV=Y%DS=1%DC=D%G=Y%M=80A99
# OS:7%TM=676EE737%P=x86_64-apple-darwin21.6.0)SEQ(SP=101%GCD=1%ISR=109%TI=Z%
# OS:CI=RD%II=RI%TS=21)OPS(O1=M5B4NW6NNT11SLL%O2=M5B4NW6NNT11SLL%O3=M5B4NW6NN
# OS:T11%O4=M5B4NW6NNT11SLL%O5=M5B4NW6NNT11SLL%O6=M5B4NNT11SLL)WIN(W1=FFFF%W2
# OS:=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFFF)ECN(R=Y%DF=Y%T=40%W=FFFF%O=M5B4NW6
# OS:SLL%CC=N%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%
# OS:DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=N%T=40%W=0%S=Z%A=S+%F=AR%
# OS:O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=N%T=40%
# OS:W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=38%UN=0%RIPL=G%RID=G%RI
# OS:PCK=G%RUCK=0%RUD=G)IE(R=Y%DFI=S%T=40%CD=S)
#     """

    osfp_dict = {'ExplicitCongestionNotificationProbe': {'ExplicitCongestionNotificationTest': 'Y', 'IPDontFragmentTest': 'Y', 'IPInitialTTLGuessTest': None, 'IPInitialTTLTest': 64, 'ResponsivenessTest': 'Y', 'TCPInitialWindowSizeTest': 64240, 'TCPMiscellaneousQuirksTest': '', 'TCPOptionsTest': 'M578NNSNW7'}, 'ICMPEchoProbe': {'ICMPDontFragmentTest': 'N', 'ICMPResponseCodeTest': 'S', 'IPInitialTTLGuessTest': None, 'IPInitialTTLTest': 64, 'ResponsivenessTest': 'Y'}, 'OPSProbe': {'O1Test': 'M578ST11NW7', 'O2Test': 'M578ST11NW7', 'O3Test': 'M578NNT11NW7', 'O4Test': 'M578ST11NW7', 'O5Test': 'M578ST11NW7', 'O6Test': 'M578ST11'}, 'SEQProbe': {'ICMPIIDII': None, 'TCPAndICMPIPIDSequenceBooleanTest': None, 'TCPIIDCI': None, 'TCPIIDTI': 'Z', 'TCPISNGCDTest': 1, 'TCPISNRateTest': 257, 'TCPISNSequencePredictabilityTest': 254, 'TCPTimestampOptionTest': 10}, 'T1Probe': {'IPDontFragmentTest': 'Y', 'IPInitialTTLGuessTest': None, 'IPInitialTTLTest': 64, 'ResponsivenessTest': 'Y', 'TCPAcknowledgmentNumberTest': 'S+', 'TCPFlagsTest': 'AS', 'TCPMiscellaneousQuirksTest': '', 'TCPRSTDataChecksumTest': 0, 'TCPSequenceNumberTest': 'O'}, 'T2Probe': {'IPDontFragmentTest': 'Y', 'IPInitialTTLGuessTest': None, 'IPInitialTTLTest': 64, 'ResponsivenessTest': 'Y', 'TCPAcknowledgmentNumberTest': 'S+', 'TCPFlagsTest': 'AS', 'TCPInitialWindowSizeTest': 65160, 'TCPMiscellaneousQuirksTest': '', 'TCPOptionsTest': 'M578ST11NW7', 'TCPRSTDataChecksumTest': 0, 'TCPSequenceNumberTest': 'O'}, 'T3Probe': {'IPDontFragmentTest': 'N', 'IPInitialTTLGuessTest': None, 'IPInitialTTLTest': None, 'ResponsivenessTest': 'N', 'TCPAcknowledgmentNumberTest': None, 'TCPFlagsTest': '', 'TCPInitialWindowSizeTest': None, 'TCPMiscellaneousQuirksTest': '', 'TCPOptionsTest': '', 'TCPRSTDataChecksumTest': 0, 'TCPSequenceNumberTest': None}, 'T4Probe': {'IPDontFragmentTest': 'N', 'IPInitialTTLGuessTest': None, 'IPInitialTTLTest': None, 'ResponsivenessTest': 'N', 'TCPAcknowledgmentNumberTest': None, 'TCPFlagsTest': '', 'TCPInitialWindowSizeTest': None, 'TCPMiscellaneousQuirksTest': '', 'TCPOptionsTest': '', 'TCPRSTDataChecksumTest': 0, 'TCPSequenceNumberTest': None}, 'T5Probe': {'IPDontFragmentTest': 'Y', 'IPInitialTTLGuessTest': None, 'IPInitialTTLTest': 64, 'ResponsivenessTest': 'Y', 'TCPAcknowledgmentNumberTest': 'S+', 'TCPFlagsTest': 'AR', 'TCPInitialWindowSizeTest': 0, 'TCPMiscellaneousQuirksTest': '', 'TCPOptionsTest': '', 'TCPRSTDataChecksumTest': 0, 'TCPSequenceNumberTest': 'Z'}, 'T6Probe': {'IPDontFragmentTest': 'N', 'IPInitialTTLGuessTest': None, 'IPInitialTTLTest': None, 'ResponsivenessTest': 'N', 'TCPAcknowledgmentNumberTest': None, 'TCPFlagsTest': '', 'TCPInitialWindowSizeTest': None, 'TCPMiscellaneousQuirksTest': '', 'TCPOptionsTest': '', 'TCPRSTDataChecksumTest': 0, 'TCPSequenceNumberTest': None}, 'T7Probe': {'IPDontFragmentTest': 'N', 'IPInitialTTLGuessTest': None, 'IPInitialTTLTest': None, 'ResponsivenessTest': 'N', 'TCPAcknowledgmentNumberTest': None, 'TCPFlagsTest': '', 'TCPInitialWindowSizeTest': None, 'TCPMiscellaneousQuirksTest': '', 'TCPOptionsTest': '', 'TCPRSTDataChecksumTest': 0, 'TCPSequenceNumberTest': None}, 'UDPProbe': {'IPDontFragmentTest': 'N', 'IPInitialTTLGuessTest': None, 'IPInitialTTLTest': 64, 'IPTotalLengthTest': 356, 'IntegrityReturnedIPChecksumTest': 'I', 'IntegrityReturnedUDPChecksumTest': 'G', 'IntegrityReturnedUDPDataTest': 'G', 'ResponsivenessTest': 'Y', 'ReturnedProbeIPIDValueTest': 'G', 'ReturnedProbeIPTotalLengthTest': 'G', 'UnusedPortUnreachableFieldTest': 0}, 'WINProbe': {'W1Test': 65160, 'W2Test': 65160, 'W3Test': 65160, 'W4Test': 65160, 'W5Test': 65160, 'W6Test': 65160}}
    diff = main(desired_fp, input_str, osfp_dict)