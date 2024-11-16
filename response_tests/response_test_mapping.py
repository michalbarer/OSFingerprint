from response_tests.df_test import IPDontFragmentTest
from response_tests.dfi_test import ICMPDontFragmentTest
from response_tests.gcd_test import TCPISNGCDTest
from response_tests.ip_id_test.ci_test import TCPIIDCI
from response_tests.ip_id_test.ii_test import ICMPIIDII
from response_tests.ip_id_test.ss_test import TCPAndICMPIPIDSequenceBooleanTest
from response_tests.ip_id_test.ti_test import TCPIIDTI
from response_tests.isr_test import TCPISNRateTest
from response_tests.r_test import ResponsivenessTest
from response_tests.sp_test import TCPISNSequencePredictabilityTest
from response_tests.ts_test import TCPTimestampOptionTest

probe_to_test_mapping = {
    "ExplicitCongestionNotificationProbe": [ResponsivenessTest, IPDontFragmentTest],
    "ICMPEchoProbe": [ResponsivenessTest, ICMPDontFragmentTest],
    "TCPProbe": [ResponsivenessTest, IPDontFragmentTest],
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
        "OPS": [],
        "WIN": []
    },
    "UDPProbe": [ResponsivenessTest, IPDontFragmentTest],
}


# OPS(O1=20%O2=20%O3=20%O4=20%O5=20%O6=20)
# WIN(W1=15%W2=15%W3=15%W4=15%W5=15%W6=15)
#
# ECN(R=100%DF=20%T=15%TG=15%W=15%O=15%CC=100%Q=20)
#
# T1(R=100%DF=20%T=15%TG=15%S=20%A=20%F=30%RD=20%Q=20)
# T2(R=80%DF=20%T=15%TG=15%W=25%S=20%A=20%F=30%O=10%RD=20%Q=20)
# T3(R=80%DF=20%T=15%TG=15%W=25%S=20%A=20%F=30%O=10%RD=20%Q=20)
# T4(R=100%DF=20%T=15%TG=15%W=25%S=20%A=20%F=30%O=10%RD=20%Q=20)
# T5(R=100%DF=20%T=15%TG=15%W=25%S=20%A=20%F=30%O=10%RD=20%Q=20)
# T6(R=100%DF=20%T=15%TG=15%W=25%S=20%A=20%F=30%O=10%RD=20%Q=20)
# T7(R=80%DF=20%T=15%TG=15%W=25%S=20%A=20%F=30%O=10%RD=20%Q=20)
#
# U1(R=50%DF=20%T=15%TG=15%IPL=100%UN=100%RIPL=100%RID=100%RIPCK=100%RUCK=50%RUD=100)
# IE(R=50%DFI=40%T=15%TG=15%CD=100) # icmp