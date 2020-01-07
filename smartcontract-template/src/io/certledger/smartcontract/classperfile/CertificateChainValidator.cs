using io.certledger.smartcontract.business.util;

namespace io.certledger.smartcontract.business
{
    class CertificateChainValidator
    {
        public static bool ValidateCertificateSignatureWithChain(Certificate certificate)
        {
            Certificate caCertificate = FindIssuerCaCertificate(certificate);
            if (!caCertificate.IsLoaded)
            {
                return false;
            }

            if (!CertificateSignatureValidator.ValidateCertificateSignature(certificate, caCertificate))
            {
                return false;
            }

            if (!CertificateValidator.CheckValidityPeriodWithCaCertificate(certificate, caCertificate))
            {
                return false;
            }

            return true;
        }

        private static Certificate FindIssuerCaCertificate(Certificate certificate)
        {
            Certificate nullCertificate = new Certificate();
            CaCertificateSubjectKeyIdEntry cACertificateSubjectKeyIdEntry = FindCaCertificateHashEntry(certificate.AuthorityKeyIdentifier.keyIdentifier);
            if (cACertificateSubjectKeyIdEntry.CertificateHash == null)
            {
                return nullCertificate;
            }

            CaCertificateEntry cACertificateEntry = FindCaCertificatewithCertificateHash(cACertificateSubjectKeyIdEntry.CertificateHash);
            if (cACertificateEntry.CertificateValue == null)
            {
                return nullCertificate;
            }

            if (cACertificateSubjectKeyIdEntry.IsRootCa)
            {
                if (!cACertificateEntry.IsTrusted)
                {
                    return nullCertificate;
                }
            }
            else
            {
                if (cACertificateEntry.IsRevoked)
                {
                    return nullCertificate;
                }
            }

            Certificate caCertificate = CertificateParser.Parse(cACertificateEntry.CertificateValue);
            if (!caCertificate.IsLoaded)
            {
                return nullCertificate;
            }

            if (!CertificateValidator.CheckValidityPeriod(caCertificate))
            {
                return nullCertificate;
            }

            return caCertificate;
        }

        private static CaCertificateSubjectKeyIdEntry FindCaCertificateHashEntry(byte[] subjectKeyIdentifier)
        {
            byte[] cACertificateSubjectKeyIdEntrySerialiazed = StorageUtil.readFromStorage(subjectKeyIdentifier);
            if (cACertificateSubjectKeyIdEntrySerialiazed != null)
            {
                return (CaCertificateSubjectKeyIdEntry) SerializationUtil.Deserialize(cACertificateSubjectKeyIdEntrySerialiazed);
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