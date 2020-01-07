namespace io.certledger.smartcontract.business.util
{
    public class NeoVmCertificateParser
    {
        public static Certificate Parse(byte[] certBytes)
        {
            //Certificate will be parsed using system call or native smart contract
            //and then certificate fields will be returned in Certificate structure.
            //now returns mock certificate field data
            //todo: add real implementation code
            Certificate certificate = new Certificate();
            return certificate;
        }
    }
}