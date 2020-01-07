using CertLedgerBusinessSCTemplate;
using io.certledger.smartcontract.business.util;

namespace io.certledger.smartcontract.business
{
    public class CertificateParser
    {
        public static Certificate Parse(byte[] encodedCert)
        {
            //Certificate will be parsed using system call or native smart contract
            //and then certificate fields will be returned in Certificate structure.
            //now returns mock certificate field data
            //todo: add real implementation code
            //return NeoVmCertificateParser.Parse(encodedCert);
            return NetCoreCertificateParser.Parse(encodedCert);
        }

        public static byte[] StringToByteArrayToString(string text)
        {
            //return NeoVMStringUtil.StringToByteArrayToString(text);
            return NetCoreStringUtil.StringToByteArray(text);
        }
    }
}