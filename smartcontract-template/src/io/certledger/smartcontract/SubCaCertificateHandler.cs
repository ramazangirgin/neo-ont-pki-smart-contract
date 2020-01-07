namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract
{
    public class SubCaCertificateHandler
    {
        public static bool AddSubCaCertificate(byte[] certificateHash, byte[] encodedCert, byte[] signature)
        {
            if (CertificateStorageManager.IsSubCaCertificateAddedBefore(certificateHash))
            {
                Logger.log("Sub CA Certificate is added before");
                return false;
            }

            Certificate subCaCertificate = CertificateParser.Parse(encodedCert);
            if (!subCaCertificate.IsLoaded)
            {
                Logger.log("Can not parse Sub CA Certificate");
                return false;
            }

            if (!ValidateSubCaCertificateAddRequestSignature(subCaCertificate, signature))
            {
                Logger.log("Can not validate Add Sub CA Certificate request signature");
                return false;
            }

            if (!CertificateValidator.ValidateSubCaCertificate(subCaCertificate))
            {
                Logger.log("Can not validate Sub CA Certificate");
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

            Certificate subCaCertificate = CertificateParser.Parse(encodedCert);
            if (!subCaCertificate.IsLoaded)
            {
                Logger.log("Can not parse Sub CA Certificate");
                return false;
            }


            if (!ValidateRevokeSubCaCertificateRequestSignature(subCaCertificate, signature))
            {
                return false;
            }


            if (!CertificateValidator.CheckValidityPeriod(subCaCertificate))
            {
                return false;
            }

            if (!CertificateStorageManager.MarkSubCaCertificateRevokedInStorage(subCaCertificate, certificateHash))
            {
                return false;
            }

            return true;
        }

        private static bool ValidateSubCaCertificateAddRequestSignature(Certificate subCACertificate, byte[] signature)
        {
            Logger.log("Starting Validate Add Sub CACertificate Request Signature");
            Logger.log("Request Signature");
            Logger.log(signature);
            Logger.log(
                "Checking Starting Validate Add Sub CACertificate Request Signature with CA Certificate Public Key");

            Certificate issuerCACertificate = CertificateChainValidator.FindIssuerCaCertificate(subCACertificate);
            if (!issuerCACertificate.IsLoaded)
            {
                Logger.log("Can not find issuer certificate, so returning signature verification failed");
                return false;
            }

            bool verified = SignatureValidator.CheckAddSubCACertificateRequestSignature(signature, subCACertificate,
                issuerCACertificate);
            if (verified)
            {
                Logger.log(
                    "Verified Validate Add Sub CACertificate Request Signature with CA Certificate Issuer Public Key");
                return true;
            }

            Logger.log("Finished Validate Add Sub CACertificate Request Signature. Result :", verified);
            return verified;
        }

        private static bool ValidateRevokeSubCaCertificateRequestSignature(Certificate subCACertificate,
            byte[] signature)
        {
            Logger.log("Starting Validate Revoke SubCA Certificate Request Signature");
            Logger.log("Request Signature");
            Logger.log(signature);
            Logger.log("Checking Revoke SubCA Certificate Request Signature with SubCA Certificate Public Key");
            bool verified =
                SignatureValidator.CheckRevokeSubCACertificateRequestSignature(signature, subCACertificate,
                    subCACertificate);
            if (verified)
            {
                Logger.log("Verified Revoke SubCA Certificate Request Signature with SubCA Certificate Public Key");
                return true;
            }

            Certificate issuerCACertificate = CertificateChainValidator.FindIssuerCaCertificate(subCACertificate);
            if (!issuerCACertificate.IsLoaded)
            {
                Logger.log("Can not find issuer certificate, so returning signature verification failed");
                return false;
            }

            verified = SignatureValidator.CheckRevokeSubCACertificateRequestSignature(signature, subCACertificate,
                issuerCACertificate);
            if (verified)
            {
                Logger.log(
                    "Verified Revoke SubCA Certificate Request Signature with SubCA Certificate Issuer Public Key");
                return true;
            }

            Logger.log("Finished Validate Revoke SubCA Certificate Request Signature. Result :", verified);
            return verified;
        }
    }
}