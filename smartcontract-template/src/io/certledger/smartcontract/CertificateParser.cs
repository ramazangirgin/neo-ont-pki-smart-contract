#if NEO
using CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract.platform.neo;

#endif

#if NET_CORE
using io.certledger.smartcontract.platform.netcore;
#endif

namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract
{
    public class CertificateParser
    {
        public static Certificate Parse(byte[] encodedCert)
        {
            //Certificate will be parsed using system call or native smart contract
            //and then certificate fields will be returned in Certificate structure.
            //now works with test native smart contract
            ////todo: add real implementation code
#if NET_CORE
                            return NetCoreCertificateParser.Parse(encodedCert);
#endif
#if NEO
            return NeoVMNativeSmartContractCertificateParser.parse(encodedCert);
#endif
        }

        public static byte[] StringToByteArrayToString(string text)
        {
#if NEO
            return NeoVMStringUtil.StringToByteArray(text);
#endif

#if NET_CORE
                            return NetCoreStringUtil.StringToByteArray(text);
#endif
        }
    }
}