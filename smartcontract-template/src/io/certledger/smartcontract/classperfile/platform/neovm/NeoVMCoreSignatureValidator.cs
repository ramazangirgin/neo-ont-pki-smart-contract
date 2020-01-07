namespace io.certledger.smartcontract.business
{
    public class NeoVMCoreSignatureValidator
    {
        public static bool Validate(SignedData signedData)
        {
            //todo: Signature will be validated using parameter fields
            //now always return signature is valid
            //todo: add real implementation code
            return true;
        }
    }
}