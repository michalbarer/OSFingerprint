from probes import ExplicitCongestionNotificationProbe
from probes import ICMPEchoProbe
from probes import TCPProbe, T2Probe, T3Probe, T4Probe, T5Probe, T6Probe, T7Probe
from probes import T1Probe, TCPSequenceProbe, SEQProbe, WINProbe, OPSProbe
from probes import UDPProbe
from response_tests import TCPAcknowledgmentNumberTest
from response_tests import ExplicitCongestionNotificationTest
from response_tests import ICMPResponseCodeTest
from response_tests import IPDontFragmentTest
from response_tests import ICMPDontFragmentTest
from response_tests import TCPFlagsTest
from response_tests import TCPISNGCDTest
from response_tests import TCPIIDCI, ICMPIIDII, TCPAndICMPIPIDSequenceBooleanTest, TCPIIDTI
from response_tests import IPTotalLengthTest
from response_tests import TCPISNRateTest
from response_tests import TCPOptionsTest, O1Test, O2Test, O3Test, O4Test, O5Test, O6Test
from response_tests import TCPMiscellaneousQuirksTest
from response_tests import ResponsivenessTest
from response_tests import TCPRSTDataChecksumTest
from response_tests import ReturnedProbeIPIDValueTest
from response_tests import IntegrityReturnedIPChecksumTest
from response_tests import ReturnedProbeIPTotalLengthTest
from response_tests import IntegrityReturnedUDPChecksumTest
from response_tests import IntegrityReturnedUDPDataTest
from response_tests import TCPSequenceNumberTest
from response_tests import TCPISNSequencePredictabilityTest
from response_tests import IPInitialTTLTest
from response_tests import IPInitialTTLGuessTest
from response_tests import TCPTimestampOptionTest
from response_tests import UnusedPortUnreachableFieldTest
from response_tests import TCPInitialWindowSizeTest, W1Test, W2Test, W3Test, W4Test, W5Test, W6Test

T_TESTS = [ResponsivenessTest,
           IPDontFragmentTest,
           IPInitialTTLTest,
           IPInitialTTLGuessTest,
           TCPSequenceNumberTest,
           TCPAcknowledgmentNumberTest,
           TCPFlagsTest,
           TCPRSTDataChecksumTest,
           TCPMiscellaneousQuirksTest]

probe_to_test_mapping = {
    ExplicitCongestionNotificationProbe: [
        ResponsivenessTest,
        IPDontFragmentTest,
        IPInitialTTLTest,
        IPInitialTTLGuessTest,
        TCPInitialWindowSizeTest,
        TCPOptionsTest,
        ExplicitCongestionNotificationTest,
        TCPMiscellaneousQuirksTest
    ],
    ICMPEchoProbe: [
        ResponsivenessTest,
        ICMPDontFragmentTest,
        IPInitialTTLTest,
        IPInitialTTLGuessTest,
        ICMPResponseCodeTest
    ],
    TCPProbe:
        {
            T1Probe: T_TESTS + [TCPInitialWindowSizeTest, TCPOptionsTest],
            T2Probe: T_TESTS + [TCPInitialWindowSizeTest, TCPOptionsTest],
            T3Probe: T_TESTS + [TCPInitialWindowSizeTest, TCPOptionsTest],
            T4Probe: T_TESTS + [TCPInitialWindowSizeTest, TCPOptionsTest],
            T5Probe: T_TESTS + [TCPInitialWindowSizeTest, TCPOptionsTest],
            T6Probe: T_TESTS + [TCPInitialWindowSizeTest, TCPOptionsTest],
            T7Probe: T_TESTS + [TCPInitialWindowSizeTest, TCPOptionsTest]
        },
    TCPSequenceProbe: {
        SEQProbe: [
            TCPISNSequencePredictabilityTest,
            TCPISNGCDTest,
            TCPISNRateTest,
            TCPIIDTI,
            TCPIIDCI,
            ICMPIIDII,
            TCPAndICMPIPIDSequenceBooleanTest,
            TCPTimestampOptionTest
        ],
        OPSProbe: [O1Test, O2Test, O3Test, O4Test, O5Test, O6Test],
        WINProbe: [W1Test, W2Test, W3Test, W4Test, W5Test, W6Test],
        T1Probe: T_TESTS,
    },
    UDPProbe: [
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

# each line is called a test line
# OPS(O1=20%O2=20%O3=20%O4=20%O5=20%O6=20)
# WIN(W1=15%W2=15%W3=15%W4=15%W5=15%W6=15)
#
# ECN(R=100%DF=20%T=15%TG=15%W=15%O=15%CC=100%Q=20)
#
# T1(R=100%DF=20%T=15%TG=15%S=20%A=20%F=30%RD=20%Q=20) # missing W
#
# T2(R=80%DF=20%T=15%TG=15%W=25%S=20%A=20%F=30%O=10%RD=20%Q=20)
# T3(R=80%DF=20%T=15%TG=15%W=25%S=20%A=20%F=30%O=10%RD=20%Q=20)
# T4(R=100%DF=20%T=15%TG=15%W=25%S=20%A=20%F=30%O=10%RD=20%Q=20)
# T5(R=100%DF=20%T=15%TG=15%W=25%S=20%A=20%F=30%O=10%RD=20%Q=20)
# T6(R=100%DF=20%T=15%TG=15%W=25%S=20%A=20%F=30%O=10%RD=20%Q=20)
# T7(R=80%DF=20%T=15%TG=15%W=25%S=20%A=20%F=30%O=10%RD=20%Q=20)
#
# U1(R=50%DF=20%T=15%TG=15%IPL=100%UN=100%RIPL=100%RID=100%RIPCK=100%RUCK=50%RUD=100)
# IE(R=50%DFI=40%T=15%TG=15%CD=100) # icmp
