namespace io.certledger.smartcontract.business
{
    public class SubCaCertificateHandler
    {
        public static bool AddSubCaCertificate(byte[] certificateHash, byte[] encodedCert, byte[] signature)
        {
            if (CertificateStorageManager.IsSubCaCertificateAddedBefore(certificateHash))
            {
                return false;
            }

            if (!ValidateSubCaCertificateAddRequestSignature(encodedCert, signature))
            {
                return false;
            }

            Certificate subCaCertificate = CertificateParser.Parse(encodedCert);
            if (!subCaCertificate.IsLoaded)
            {
                return false;
            }

            if (!CertificateValidator.ValidateSubCaCertificate(subCaCertificate))
            {
                return false;
            }

            CertificateStorageManager.AddSubCaCertificateToStorage(subCaCertificate, certificateHash, encodedCert);
            return true;
        }

        public static bool RevokeSubCaCertificate(byte[] certificateHash, byte[] encodedCert, byte[] signature)
        {
            if (!CertificateStorageManager.IsSubCaCertificateAddedBefore(certificateHash))
            {
                return false;
            }

            if (!ValidateRevokeSubCaCertificateRequestSignature(encodedCert, signature))
            {
                return false;
            }

            Certificate subCaCertificate = CertificateParser.Parse(encodedCert);

            if (!CertificateValidator.CheckValidityPeriod(subCaCertificate))
            {
                return false;
            }

            if (!CertificateStorageManager.MarkSubCaCertificateRevokedInStore(subCaCertificate, certificateHash))
            {
                return false;
            }

            return true;
        }

        private static bool ValidateSubCaCertificateAddRequestSignature(byte[] encodedCert, byte[] signature)
        {
            //Validates encodedCert signature with signature
            //Signature Format will be discussed later
            //now always return valid signature
            //todo: add real implementation code
            return true;
        }

        private static bool ValidateRevokeSubCaCertificateRequestSignature(byte[] encodedCert, byte[] signature)
        {
            //Validates encodedCert signature with signature
            //Signature Format will be discussed later
            //Will check sub ca remove request signed by any CA key in chain.
            //now always return valid signature
            //todo: add real implementation code
            return true;
        }
    }
}