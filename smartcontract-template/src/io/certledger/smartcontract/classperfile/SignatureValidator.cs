namespace io.certledger.smartcontract.business
{
    public struct SignedData
    {
        public byte[] signedData;
        public byte[] signatureAlgorithm;
        public byte[] subjectPublicKeyInfo;
        public byte[] signatureValue;
    }

    public class SignatureValidator
    {
        public static bool Validate(SignedData signedData)
        {
            return NetCoreSignatureValidator.Validate(signedData);
            //return NeoVMCoreSignatureValidator.Validate(signedData);
            //todo: Signature will be validated using parameter fields
            //now always return signature is valid
            //todo: add real implementation code
        }
    }
}