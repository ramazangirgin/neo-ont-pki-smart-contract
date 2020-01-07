namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract
{
    public class SslCertificateHandler
    {
        public static bool AddSslCertificate(byte[] certificateHash, byte[] encodedCert)
        {
            Logger.log("Checking SSL Certificate is added before");
            if (CertificateStorageManager.IsSSLCertificateAddedBefore(certificateHash))
            {
                Logger.log("SSL Certificate is added before");
                return false;
            }

            Logger.log("Trying to parse SSL Certificate");
            Certificate sslCertificate = CertificateParser.Parse(encodedCert);
            if (!sslCertificate.IsLoaded)
            {
                Logger.log("Can not parse SSL Certificate");
                return false;
            }

            Logger.log("Checking SSL Certificate Validity Period");
            if (!CertificateValidator.CheckValidityPeriod(sslCertificate))
            {
                Logger.log("SSL Certificate validity period is invalid");
                return false;
            }

            Logger.log("Checking SSL Certificate Fields");
            if (!CertificateValidator.ValidateSslCertificateFields(sslCertificate))
            {
                Logger.log("SSL Certificate Fields are invalid");
                return false;
            }

            Logger.log("Validating SSL Certificate With Chain");
            if (!CertificateChainValidator.ValidateCertificateSignatureWithChain(sslCertificate))
            {
                Logger.log("Can not validate SSL Certificate Signature With Chain");
                return false;
            }

            Logger.log("Adding SSL Certificate To Storage");
            CertificateStorageManager.AddEndEntityCertificateToStorage(sslCertificate, certificateHash, encodedCert);
            return true;
        }

        public static bool RevokeSslCertificate(byte[] certificateHash, byte[] encodedCert, byte[] signature)
        {
            Logger.log("Checking SSL Certificate is added before");
            if (!CertificateStorageManager.IsSSLCertificateAddedBefore(certificateHash))
            {
                Logger.log("SSL Certificate is not added before");
                return false;
            }

            Certificate sslCertificate = CertificateParser.Parse(encodedCert);
            if (!sslCertificate.IsLoaded)
            {
                Logger.log("Can not parse SSL Certificate");
                return false;
            }

            if (!ValidateRevokeSslCertificateRequestSignature(sslCertificate, signature))
            {
                Logger.log("SSL Certificate revoke request signature is invalid");
                return false;
            }

            if (!CertificateStorageManager.MarkEndEntityCertificateRevokedInStorage(certificateHash))
            {
                Logger.log("Error while marking as remoked SSL Certificate in Storage");
                return false;
            }

            return true;
        }

        private static bool ValidateRevokeSslCertificateRequestSignature(Certificate sslCertificate, byte[] signature)
        {
            Logger.log("Starting Validate Revoke SSL Certificate Request Signature");
            Logger.log("Request Signature");
            Logger.log(signature);
            Logger.log("Checking Revoke SSL Certificate Request Signature with SSL Certificate Public Key");
            bool verified = SignatureValidator.CheckRevokeSSLCertificateRequestSignature(signature, sslCertificate, sslCertificate);
            if (verified)
            {
                Logger.log("Verified Revoke SSL Certificate Request Signature with SSL Certificate Public Key");
                return true;
            }

            Certificate issuerCACertificate = CertificateChainValidator.FindIssuerCaCertificate(sslCertificate);
            if (!issuerCACertificate.IsLoaded)
            {
                Logger.log("Can not find issuer certificate, so returning signature verification failed");
                return false;
            }

            verified = SignatureValidator.CheckRevokeSSLCertificateRequestSignature(signature, sslCertificate, issuerCACertificate);
            if (verified)
            {
                Logger.log("Verified Revoke SSL Certificate Request Signature with SSL Certificate Issuer Public Key");
                return true;
            }

            Logger.log("Finished Validate Revoke SSL Certificate Request Signature. Result :", verified);
            return verified;
        }
    }
}