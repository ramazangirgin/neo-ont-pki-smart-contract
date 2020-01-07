namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract
{
    class CertificateChainValidator
    {
        public static bool ValidateCertificateSignatureWithChain(Certificate certificate)
        {
            Certificate caCertificate = FindIssuerCaCertificate(certificate);
            if (!caCertificate.IsLoaded)
            {
                Logger.log("Can not find issuer certificate");
                return false;
            }

            if (!CertificateValidator.CheckCertificateWithWithCaCertificate(certificate, caCertificate))
            {
                Logger.log("Can not find validate validity with issuer certificate validity");
                return false;
            }

            return true;
        }

        public static Certificate FindIssuerCaCertificate(Certificate certificate)
        {
            Certificate nullCertificate = new Certificate();
            Logger.log("Certificate AuthorityKeyIdentifier.keyIdentifier : ");
            Logger.log(certificate.AuthorityKeyIdentifier.keyIdentifier);
            CaCertificateSubjectKeyIdEntry cACertificateSubjectKeyIdEntry =
                FindCaCertificateHashEntry(certificate.AuthorityKeyIdentifier.keyIdentifier);
            if (cACertificateSubjectKeyIdEntry.CertificateHash == null)
            {
                Logger.log("Can not find CA Certificate Hash Entry with AuthorityKeyIdentifier.keyIdentifier");
                return nullCertificate;
            }

            CaCertificateEntry cACertificateEntry =
                FindCaCertificatewithCertificateHash(cACertificateSubjectKeyIdEntry.CertificateHash);
            if (cACertificateEntry.CertificateValue == null)
            {
                Logger.log("Can not find CA Certificate Entry with CA Certificate Hash");
                return nullCertificate;
            }

            if (cACertificateSubjectKeyIdEntry.IsRootCa)
            {
                if (!cACertificateEntry.IsTrusted)
                {
                    Logger.log("CA Certificate is not trusted");
                    return nullCertificate;
                }
            }
            else
            {
                if (cACertificateEntry.IsRevoked)
                {
                    Logger.log("CA Certificate is revoked");
                    return nullCertificate;
                }
            }

            Certificate caCertificate = CertificateParser.Parse(cACertificateEntry.CertificateValue);
            if (!caCertificate.IsLoaded)
            {
                Logger.log("Can not parse CA Certificate value");
                return nullCertificate;
            }

            if (!CertificateValidator.CheckValidityPeriod(caCertificate))
            {
                Logger.log("Parse CA Certificate Validity is invalid");
                return nullCertificate;
            }

            return caCertificate;
        }

        private static CaCertificateSubjectKeyIdEntry FindCaCertificateHashEntry(byte[] subjectKeyIdentifier)
        {
            byte[] cACertificateSubjectKeyIdEntrySerialiazed = StorageUtil.readFromStorage(subjectKeyIdentifier);
            if (cACertificateSubjectKeyIdEntrySerialiazed != null)
            {
                return (CaCertificateSubjectKeyIdEntry) SerializationUtil.Deserialize(
                    cACertificateSubjectKeyIdEntrySerialiazed);
            }
            else
            {
                return new CaCertificateSubjectKeyIdEntry();
            }
        }

        private static CaCertificateEntry FindCaCertificatewithCertificateHash(byte[] certificateHash)
        {
            byte[] caCertificateEnrtySerialized = StorageUtil.readFromStorage(certificateHash);
            if (caCertificateEnrtySerialized != null)
            {
                return (CaCertificateEntry) SerializationUtil.Deserialize(caCertificateEnrtySerialized);
            }
            else
            {
                return new CaCertificateEntry();
            }
        }
    }
}