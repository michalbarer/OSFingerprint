from response_tests.a_test import TCPAcknowledgmentNumberTest
from response_tests.cc_test import ExplicitCongestionNotificationTest
from response_tests.cd_test import ICMPResponseCodeTest
from response_tests.df_test import IPDontFragmentTest
from response_tests.dfi_test import ICMPDontFragmentTest
from response_tests.f_test import TCPFlagsTest
from response_tests.gcd_test import TCPISNGCDTest
from response_tests.ip_id_test.ci_test import TCPIIDCI
from response_tests.ip_id_test.ii_test import ICMPIIDII
from response_tests.ip_id_test.ss_test import TCPAndICMPIPIDSequenceBooleanTest
from response_tests.ip_id_test.ti_test import TCPIIDTI
from response_tests.ipl_test import IPTotalLengthTest
from response_tests.isr_test import TCPISNRateTest
from response_tests.o_tests import TCPOptionsTest, O1Test, O2Test, O3Test, O4Test, O5Test, O6Test
from response_tests.q_test import TCPMiscellaneousQuirksTest
from response_tests.r_test import ResponsivenessTest
from response_tests.rd_test import TCPRSTDataChecksumTest
from response_tests.rid_test import ReturnedProbeIPIDValueTest
from response_tests.ripck_test import IntegrityReturnedIPChecksumTest
from response_tests.ripl_test import ReturnedProbeIPTotalLengthTest
from response_tests.ruck_test import IntegrityReturnedUDPChecksumTest
from response_tests.rud_test import IntegrityReturnedUDPDataTest
from response_tests.s_test import TCPSequenceNumberTest
from response_tests.sp_test import TCPISNSequencePredictabilityTest
from response_tests.t_test import IPInitialTTLTest
from response_tests.tg_test import IPInitialTTLGuessTest
from response_tests.ts_test import TCPTimestampOptionTest
from response_tests.un_test import UnusedPortUnreachableFieldTest
from response_tests.w_tests import TCPInitialWindowSizeTest, W1Test, W2Test, W3Test, W4Test, W5Test, W6Test

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
    "ExplicitCongestionNotificationProbe": [ResponsivenessTest,
                                            IPDontFragmentTest,
                                            IPInitialTTLTest,
                                            IPInitialTTLGuessTest,
                                            TCPInitialWindowSizeTest,
                                            TCPOptionsTest,
                                            ExplicitCongestionNotificationTest,
                                            TCPMiscellaneousQuirksTest],
    "ICMPEchoProbe": [ResponsivenessTest, ICMPDontFragmentTest],
    "TCPProbe": T_TESTS + [TCPInitialWindowSizeTest, TCPOptionsTest], # TODO: SPLIT TO T1-T7?
    "TCPSequenceProbe": {
        "SEQ": [
            TCPISNSequencePredictabilityTest,
            TCPISNGCDTest,
            TCPISNRateTest,
            TCPIIDTI,
            TCPIIDCI,
            ICMPIIDII,
            TCPAndICMPIPIDSequenceBooleanTest,
            TCPTimestampOptionTest
        ],
        "OPS": [O1Test, O2Test, O3Test, O4Test, O5Test, O6Test],
        "WIN": [W1Test, W2Test, W3Test, W4Test, W5Test, W6Test],
        "T1": T_TESTS,
    },
    "UDPProbe": [ResponsivenessTest,
                 IPDontFragmentTest,
                 IPInitialTTLTest,
                 IPInitialTTLGuessTest,
                 IPTotalLengthTest,
                 UnusedPortUnreachableFieldTest,
                 ReturnedProbeIPTotalLengthTest,
                 ReturnedProbeIPIDValueTest,
                 IntegrityReturnedIPChecksumTest,
                 IntegrityReturnedUDPChecksumTest,
                 IntegrityReturnedUDPDataTest],
    "IMCPEchoProbe": [ResponsivenessTest,
                      ICMPDontFragmentTest,
                      IPInitialTTLTest,
                      IPInitialTTLGuessTest,
                      ICMPResponseCodeTest],
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