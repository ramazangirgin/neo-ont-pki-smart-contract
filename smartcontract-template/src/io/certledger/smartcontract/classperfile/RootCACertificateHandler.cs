namespace io.certledger.smartcontract.business
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
            if (!ValidateRootCaCertificateAddRequestSignature(encodedCert, signature))
            {
                return false;
            }

            if (!CertificateStorageManager.IsRootCaCertificateAddedBefore(certificateHash))
            {
                return false;
            }

            Certificate rootCaCertificate = CertificateParser.Parse(encodedCert);
            CertificateStorageManager.MarkRootCaCertificateUntrustedInStorage(rootCaCertificate, certificateHash);
            return true;
        }


        private static bool ValidateRootCaCertificateAddRequestSignature(byte[] encodedCert, byte[] signature)
        {
            //Validates encodedCert signature with signature
            //Signature Format will be discussed later
            //now always return valid signature
            //todo: add real implementation code
            return true;
        }
    }
}