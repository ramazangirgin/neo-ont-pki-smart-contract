namespace io.certledger.smartcontract.business
{
    public class SslCertificateHandler
    {
        public static bool AddSslCertificate(byte[] certificateHash, byte[] encodedCert)
        {
            if (CertificateStorageManager.IsSSLCertificateAddedBefore(certificateHash))
            {
                return false;
            }

            Certificate sslCertificate = CertificateParser.Parse(encodedCert);
            if (!sslCertificate.IsLoaded)
            {
                return false;
            }

            if (!CertificateValidator.CheckValidityPeriod(sslCertificate))
            {
                return false;
            }

            if (!CertificateValidator.ValidateSslCertificateFields(sslCertificate))
            {
                return false;
            }

            if (!CertificateChainValidator.ValidateCertificateSignatureWithChain(sslCertificate))
            {
                return false;
            }

            CertificateStorageManager.AddEndEntityCertificateToStorage(sslCertificate, certificateHash, encodedCert);
            return true;
        }
    }
}