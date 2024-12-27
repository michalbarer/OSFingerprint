from response_tests import ExplicitCongestionNotificationTest
from response_tests import ICMPDontFragmentTest
from response_tests import ICMPResponseCodeTest
from response_tests import IPDontFragmentTest
from response_tests import IPInitialTTLGuessTest
from response_tests import IPInitialTTLTest
from response_tests import IPTotalLengthTest
from response_tests import IntegrityReturnedIPChecksumTest
from response_tests import IntegrityReturnedUDPChecksumTest
from response_tests import IntegrityReturnedUDPDataTest
from response_tests import ResponsivenessTest
from response_tests import ReturnedProbeIPIDValueTest
from response_tests import ReturnedProbeIPTotalLengthTest
from response_tests import TCPAcknowledgmentNumberTest
from response_tests import TCPFlagsTest
from response_tests import TCPIIDCI, ICMPIIDII, TCPAndICMPIPIDSequenceBooleanTest, TCPIIDTI
from response_tests import TCPISNGCDTest
from response_tests import TCPISNRateTest
from response_tests import TCPISNSequencePredictabilityTest
from response_tests import TCPInitialWindowSizeTest, W1Test, W2Test, W3Test, W4Test, W5Test, W6Test
from response_tests import TCPMiscellaneousQuirksTest
from response_tests import TCPOptionsTest, O1Test, O2Test, O3Test, O4Test, O5Test, O6Test
from response_tests import TCPRSTDataChecksumTest
from response_tests import TCPSequenceNumberTest
from response_tests import TCPTimestampOptionTest
from response_tests import UnusedPortUnreachableFieldTest

T_TESTS = [
    ResponsivenessTest,
    IPDontFragmentTest,
    IPInitialTTLTest,
    IPInitialTTLGuessTest,
    TCPSequenceNumberTest,
    TCPAcknowledgmentNumberTest,
    TCPFlagsTest,
    TCPRSTDataChecksumTest,
    TCPMiscellaneousQuirksTest
]

probe_to_test_mapping = {
    "ExplicitCongestionNotificationProbe": [
        ResponsivenessTest,
        IPDontFragmentTest,
        IPInitialTTLTest,
        IPInitialTTLGuessTest,
        TCPInitialWindowSizeTest,
        TCPOptionsTest,
        ExplicitCongestionNotificationTest,
        TCPMiscellaneousQuirksTest
    ],
    "ICMPEchoProbe": [
        ResponsivenessTest,
        ICMPDontFragmentTest,
        IPInitialTTLTest,
        IPInitialTTLGuessTest,
        ICMPResponseCodeTest,
    ],
    "T2Probe": T_TESTS + [TCPInitialWindowSizeTest, TCPOptionsTest],
    "T3Probe": T_TESTS + [TCPInitialWindowSizeTest, TCPOptionsTest],
    "T4Probe": T_TESTS + [TCPInitialWindowSizeTest, TCPOptionsTest],
    "T5Probe": T_TESTS + [TCPInitialWindowSizeTest, TCPOptionsTest],
    "T6Probe": T_TESTS + [TCPInitialWindowSizeTest, TCPOptionsTest],
    "T7Probe": T_TESTS + [TCPInitialWindowSizeTest, TCPOptionsTest],
    "SEQProbe": [
        TCPISNGCDTest,
        TCPISNSequencePredictabilityTest, # depends on GCD
        TCPISNRateTest,
        TCPIIDTI,
        TCPIIDCI, # depends on T5-T7
        ICMPIIDII, # depends on ICMP
        TCPAndICMPIPIDSequenceBooleanTest, # depends on ICMP, TCP SEQ, II, TI
        TCPTimestampOptionTest
    ],
    "OPSProbe": [O1Test, O2Test, O3Test, O4Test, O5Test, O6Test],
    "WINProbe": [W1Test, W2Test, W3Test, W4Test, W5Test, W6Test],
    "T1Probe": T_TESTS,
    "UDPProbe": [
        ResponsivenessTest,
        IPDontFragmentTest,
        IPInitialTTLTest,
        IPInitialTTLGuessTest,
        IPTotalLengthTest,
        UnusedPortUnreachableFieldTest,
        ReturnedProbeIPTotalLengthTest,
        ReturnedProbeIPIDValueTest,
        IntegrityReturnedIPChecksumTest,
        IntegrityReturnedUDPChecksumTest,
        IntegrityReturnedUDPDataTest
    ],
}
