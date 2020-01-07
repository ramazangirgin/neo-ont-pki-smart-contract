namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract
{
    public class RootCaCertificateHandler
    {
        public static bool AddTrustedRootCaCertificate(byte[] certificateHash, byte[] encodedCert, byte[] signature)
        {
            if (!ValidateRootCaCertificateAddRequestSignature(encodedCert, signature))
            {
                return false;
            }

            if (CertificateStorageManager.IsRootCaCertificateAddedBefore(certificateHash))
            {
                Logger.log("Trusted Root CA Added Before");
                return false;
            }

            Certificate rootCaCertificate = CertificateParser.Parse(encodedCert);

            if (!rootCaCertificate.IsLoaded)
            {
                return false;
            }

            if (!CertificateValidator.ValidateRootCaCertificate(rootCaCertificate))
            {
                return false;
            }

            CertificateStorageManager.AddRootCaCertificateToStorage(rootCaCertificate, certificateHash, encodedCert);
            return true;
        }

        public static bool UntrustRootCaCertificate(byte[] certificateHash, byte[] encodedCert, byte[] signature)
        {
            if (!ValidateUntrustRootCaCertificateRequestSignature(encodedCert, signature))
            {
                Logger.log("Error while validating Untrust Root Ca Certificate Request");
                return false;
            }

            if (!CertificateStorageManager.IsRootCaCertificateAddedBefore(certificateHash))
            {
                Logger.log("Untrust error. Root CA is not added before");
                return false;
            }

            Certificate rootCaCertificate = CertificateParser.Parse(encodedCert);
            if (!rootCaCertificate.IsLoaded)
            {
                Logger.log("Error while parsing encoded root CA content");
                return false;
            }

            CertificateStorageManager.MarkRootCaCertificateUntrustedInStorage(rootCaCertificate, certificateHash);
            return true;
        }


        private static bool ValidateRootCaCertificateAddRequestSignature(byte[] encodedCert, byte[] signature)
        {
            Logger.log("Starting Validate Add Trusted Root CA Certificate Request Signature");
            Logger.log("Request Signature");
            Logger.log(signature);
            bool result = SignatureValidator.CheckAddTrustedRootCARequestSignature(signature, encodedCert);
            Logger.log("Finished Validate  Add Trusted Root CA Certificate Request Signature. Result :", result);
            return result;
        }
        
        private static bool ValidateUntrustRootCaCertificateRequestSignature(byte[] encodedCert, byte[] signature)
        {
            Logger.log("Starting Validate Untrust Root CA Certificate Request Signature");
            Logger.log("Request Signature");
            Logger.log(signature);
            bool result = SignatureValidator.CheckUntrustRootCARequestSignature(signature, encodedCert);
            Logger.log("Finished Validate Untrust Root CA Certificate Request Signature. Result :", result);
            return result;
        }
    }
}