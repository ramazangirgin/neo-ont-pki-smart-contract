using Neo.SmartContract.Framework.Services.Neo;

namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract.platform.neo
{
    public class NeoVMSignatureValidator
    {
        public static bool Validate(SignedData signedData)
        {
            //todo: Signature will be validated using parameter fields
            //now always return signature is valid
            //todo: add real implementation code
            return true;
        }
        public static bool CheckCertificateSignature(byte[] rawCertificate, byte[] rawParentCertificate)
        {
            object[] parameters = new object[2];
            parameters[0] = rawCertificate;
            parameters[1] = rawParentCertificate;
            Runtime.Notify("Starting Check Certificate Signature With Native Smart Contract");
            byte[] result = Native.Invoke(0, NeoVMNativeSmartContractCertificateParser.parseContractAddr, "checkCertSignature", parameters);
            Runtime.Notify("Completed Check Certificate Signature With Native Smart Contract. Result: ");
            Runtime.Notify(result);
            if (result[0] == 0)
            {
                Runtime.Notify("Validation Failed");
                return false;
            }
            else
            {
                Runtime.Notify("Validation Succeed");
                return true;
            }
        }

        public static bool CheckSignature(int algorithmCode, byte[] signature, byte[] signed, byte[] publicKey)
        {
            object[] parameters = new object[4];
            parameters[0] = algorithmCode;
            parameters[1] = signature;
            parameters[2] = signed;
            parameters[3] = publicKey;
            Runtime.Notify("Starting Check Signed Data Signature With Native Smart Contract");
            byte[] result = Native.Invoke(0, NeoVMNativeSmartContractCertificateParser.parseContractAddr, "checkSignature", parameters);
            Runtime.Notify("Completed Check Signed Data Signature With Native Smart Contract. Result: ");
            Runtime.Notify(result);
            if (result[0] == 0)
            {
                Runtime.Notify("Validation Failed");
                return false;
            }
            else
            {
                Runtime.Notify("Validation Succeed");
                return true;
            }
        }
    }
}