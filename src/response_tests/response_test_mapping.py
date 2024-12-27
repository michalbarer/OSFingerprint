from src.response_tests import ICMPDontFragmentTest
from src.response_tests import ICMPResponseCodeTest
from src.response_tests import IPDontFragmentTest
from src.response_tests import IPInitialTTLTest
from src.response_tests import IPTotalLengthTest
from src.response_tests import IntegrityReturnedIPChecksumTest
from src.response_tests import IntegrityReturnedUDPDataTest
from src.response_tests import ResponsivenessTest
from src.response_tests import ReturnedProbeIPIDValueTest
from src.response_tests import ReturnedProbeIPTotalLengthTest
from src.response_tests import TCPAcknowledgmentNumberTest
from src.response_tests import TCPFlagsTest
from src.response_tests import TCPIIDCI, ICMPIIDII, TCPAndICMPIPIDSequenceBooleanTest, TCPIIDTI
from src.response_tests import TCPISNGCDTest
from src.response_tests import TCPISNRateTest
from src.response_tests import TCPISNSequencePredictabilityTest
from src.response_tests import TCPMiscellaneousQuirksTest
from src.response_tests import TCPRSTDataChecksumTest
from src.response_tests import TCPSequenceNumberTest
from src.response_tests import TCPTimestampOptionTest
from src.response_tests import UnusedPortUnreachableFieldTest
from src.response_tests.cc_test import ExplicitCongestionNotificationTest
from src.response_tests.o_tests import TCPOptionsTest, O1Test, O2Test, O3Test, O4Test, O5Test, O6Test
from src.response_tests.ruck_test import IntegrityReturnedUDPChecksumTest
from src.response_tests.tg_test import IPInitialTTLGuessTest
from src.response_tests.w_tests import TCPInitialWindowSizeTest, W1Test, W2Test, W3Test, W4Test, W5Test, W6Test

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
